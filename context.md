# DLP_FinTech — Complete Repository Context

> Generated: 2026-04-16

---

## Project Summary

**Privacy-Preserving UPI Balance Verification using Zero-Knowledge Proofs**

A fintech security system that uses Discrete Logarithm Problem (DLP) based cryptographic protocols to enable privacy-preserving transactions. The system proves balance sufficiency without revealing actual balances, using Schnorr ZK proofs as the core primitive.

---

## Repository Layout

```
DLP_FinTech/
├── crypto/                  # 7 DLP-based cryptographic modules
│   ├── __init__.py          # Exports all public symbols
│   ├── dlp_core.py          # DLP primitives (params, keypairs, commitments)
│   ├── schnorr_protocol.py  # Schnorr ZK proofs + BalanceProver/Verifier
│   ├── schnorr_signatures.py# Schnorr digital signatures + transaction signing
│   ├── diffie_hellman.py    # DH key exchange + UPI secure sessions
│   ├── elgamal_encryption.py# ElGamal encryption + homomorphic ops
│   ├── range_proofs.py      # Range proofs for UPI compliance
│   ├── batch_verification.py# Batch Schnorr proof verification
│   ├── dsa.py               # DSA (benchmark comparison only)
│   └── ecdsa.py             # ECDSA on secp256k1 (benchmark comparison only)
├── backend/
│   ├── __init__.py
│   └── transaction_service.py  # User/Transaction management with ZK proofs
├── api/
│   ├── __init__.py
│   └── app.py               # Flask REST API
├── frontend/
│   ├── index.html
│   ├── app.js
│   └── styles.css
├── tests/
│   ├── test_dlp_core.py         # 6 tests
│   ├── test_schnorr.py          # 6 tests
│   ├── test_transaction_service.py # 8 tests
│   └── test_advanced_crypto.py  # 13 tests
├── benchmarks/
│   └── comparison.py        # Schnorr vs DSA vs ECDSA benchmark
├── demo.py                  # Interactive demo script
├── requirements.txt
├── README.md
├── ARCHITECTURE.md
├── FEATURES.md
└── COMPARISON.md
```

---

## Technology Stack

- **Language**: Python 3.8+
- **Web Framework**: Flask 3.0.0 + flask-cors
- **Crypto**: Custom DLP implementation (no external crypto library for core logic)
- **Testing**: unittest (33 tests, all passing)
- **Dependencies**: flask, flask-cors, pycryptodome, sqlalchemy, python-dotenv, matplotlib, numpy

---

## Cryptographic Architecture

### DLP Parameters (`crypto/dlp_core.py`)

```python
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F  # 256-bit safe prime (secp256k1 field prime)
G = 2          # Generator
Q = (P - 1) // 2  # Subgroup order
```

Key classes/functions:
- `DLPParameters` — holds P, G, Q; `get_parameters()` returns `(p, g, q)`
- `mod_exp(base, exp, mod)` — wraps `pow()`
- `generate_private_key()` — `secrets.randbelow(q-1) + 1`
- `compute_public_key(priv)` — `g^priv mod p`
- `generate_keypair()` — returns `(private, public)`
- `create_commitment(value, randomness)` — Pedersen: `g^v * h^r mod p` where `h = g^2 mod p`
- `DLPProof(commitment, challenge, response)` — data class with `to_dict()`/`from_dict()`

---

### Schnorr ZK Protocol (`crypto/schnorr_protocol.py`)

**Protocol**: Prove knowledge of `x` where `y = g^x mod p` without revealing `x`.

1. Prover: `commitment = g^r mod p` (random r)
2. Verifier: `challenge = random c`
3. Prover: `response = r + c*x mod q`
4. Verifier: `g^response == commitment * y^challenge mod p`

Key classes:
- `SchnorrProver(secret)` — `create_commitment()`, `generate_response(challenge)`, `create_proof(challenge)`
- `SchnorrVerifier()` — `generate_challenge()`, `verify_proof(public_value, proof)`
- `BalanceProver(balance)` — handles balances that may exceed `q` via **chunked decomposition**
  - Splits balance into base-q chunks: `balance = c0 + c1*q + c2*q^2 + ...`
  - `prove_sufficient_balance(amount)` → `(bool, ChunkedBalanceProof)`
  - `get_balance_commitment()` → product of chunk commitments
  - `get_chunk_commitments()` → list of per-chunk commitments
- `BalanceVerifier()` — `verify_balance_proof(commitment, proof, chunk_commitments=None)`
- `ChunkedBalanceProof(chunk_proofs, num_chunks)` — container for multi-chunk proofs

**Important design note**: `BalanceProver` uses chunked decomposition to handle balances ≥ q. Each chunk is independently proven with Schnorr; the combined commitment is the product of chunk commitments (homomorphic).

---

### Schnorr Digital Signatures (`crypto/schnorr_signatures.py`)

Sign: `r = g^k mod p`, `e = H(r || msg)`, `s = k + e*priv mod q`  
Verify: `g^s == r * pub^e mod p`

Key classes:
- `SchnorrSignature(r, s)` — `to_dict()`/`from_dict()`
- `SchnorrSigner(private_key=None)` — `sign(message: bytes)`, `get_public_key()`
- `SchnorrVerifier()` — `verify(message, signature, public_key)`
- `TransactionSigner(user_id, private_key=None)` — `sign_transaction(sender, receiver, amount, timestamp)`
- `TransactionVerifier()` — `verify_transaction(...)`
- `MultiSignature(required_signatures)` — simplified aggregation
- `BlindSignature()` — blind/unblind for anonymous auth

---

### Diffie-Hellman (`crypto/diffie_hellman.py`)

Key classes:
- `DiffieHellmanParty(name)` — `get_public_key()`, `compute_shared_secret(other_pub)`, `get_session_key()`
  - Session key = `SHA-256(shared_secret_bytes)`
- `SecureChannel(party_a, party_b)` — `establish_channel()` → `(key_a, key_b)`, `is_secure()`
- `UPISecureSession(user_id, gateway_id)` — `initiate_session()`, `encrypt_transaction_data(data)`
- `EphemeralDH()` — `generate_ephemeral_keypair()`, `create_session(other_pub)` for forward secrecy

---

### ElGamal Encryption (`crypto/elgamal_encryption.py`)

Encrypt: `c1 = g^y mod p`, `c2 = m * h^y mod p`  
Decrypt: `s = c1^x mod p`, `m = c2 * s^(-1) mod p`

Key classes:
- `ElGamalKeypair()` — `get_public_key()` → `(p, g, h)`, `get_private_key()`
- `ElGamalEncryption()` — `encrypt(message, public_key)`, `decrypt(ciphertext, private_key)`
- `ElGamalCiphertext(c1, c2)` — `to_dict()`
- `HomomorphicElGamal()` — `multiply_ciphertexts(ct1, ct2)` → `E(m1*m2)`, `exponentiate_ciphertext(ct, k)` → `E(m^k)`
- `SecureTransactionData()` — `encrypt_amount()`, `decrypt_amount()`, `verify_encrypted_sum()`
- `HybridEncryption()` — ElGamal key wrap + XOR symmetric encryption

---

### Range Proofs (`crypto/range_proofs.py`)

Proves value ∈ [min, max] via bit decomposition + Schnorr proofs per bit.

Key classes:
- `RangeProof(bit_proofs, range_min, range_max)` — `to_dict()`
- `RangeProver(value)` — `prove_in_range(min, max)` → `(bool, RangeProof)`
- `RangeVerifier()` — `verify_range_proof(commitment, proof)`
- `BalanceRangeProver(balance)` — `prove_positive_balance()`, `prove_within_limit(max)`, `prove_transaction_valid(amount, min, max)`, `prove_sufficient_for_transaction(amount)`
- `UPIRangeValidator()` — enforces UPI limits:
  - `MIN_TRANSACTION = 1`
  - `MAX_TRANSACTION_REGULAR = 100_000` (₹1 lakh)
  - `MAX_TRANSACTION_MERCHANT = 200_000` (₹2 lakh)
  - `MAX_DAILY_LIMIT = 1_000_000` (₹10 lakh)

---

### Batch Verification (`crypto/batch_verification.py`)

Verifies n Schnorr proofs in one operation using random linear combination.

Key classes:
- `BatchVerifier()` — `verify_batch(public_values, proofs)`, `verify_batch_optimized(...)`
- `TransactionBatchVerifier()` — `verify_transaction_batch(commitments, proofs)` → `(all_valid, failed_indices)`
  - Supports both `DLPProof` and `ChunkedBalanceProof`
  - Fast path: batch verify all; slow path: identify individual failures
- `PerformanceComparison()` — `estimate_verification_cost(n)`, `get_optimization_report(volumes)`
  - Individual: 3 mod-exps per proof; Batch: ~2 mod-exps per proof + 5 overhead → ~1.5x speedup

---

### DSA (`crypto/dsa.py`) — Benchmark only

- `DSASigner()` — `sign(message)` → `(r, s)`, `get_public_key()`, `get_params()`
- `DSAVerifier(p, g, q)` — `verify(message, signature, public_key)`
- Uses modular inverse during signing (extra overhead vs Schnorr)

---

### ECDSA (`crypto/ecdsa.py`) — Benchmark only

secp256k1 curve: `y^2 = x^3 + 7 mod p`

- `ECPoint(x, y, curve)` — `infinity(curve)` static
- `ECCurve()` — `add(P, Q)`, `mul(k, P)` (double-and-add); holds secp256k1 params + generator G
- `ECDSASigner()` — `sign(message)` → `(r, s)`, `get_public_key()`
- `ECDSAVerifier()` — `verify(message, signature, public_key)`

---

## Backend Layer (`backend/transaction_service.py`)

In-memory storage (no database).

### Classes

**`User(user_id, name, balance)`**
- Holds `BalanceProver` instance
- `update_balance(amount)` — updates balance and regenerates prover/commitment
- `to_dict()` — includes actual balance (demo only)

**`Transaction(sender_id, receiver_id, amount)`**
- UUID transaction_id, ISO timestamp, status: `pending` → `completed`/`failed`

**`TransactionService()`**
- `create_user(name, initial_balance)` → `User`
- `get_user(user_id)` → `Optional[User]`
- `initiate_transaction(sender_id, receiver_id, amount)` → result dict
  - Flow: validate users → generate ZK proof → verify proof → execute (update balances)
- `get_transaction(tx_id)` → dict
- `get_user_transactions(user_id)` → list of dicts
- `get_user_balance_info(user_id)` → commitment only (privacy-preserving)

---

## API Layer (`api/app.py`)

Flask app, serves frontend from `../frontend/`, CORS enabled.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Serve frontend index.html |
| GET | `/health` | Health check |
| POST | `/api/users` | Create user `{name, initial_balance}` |
| GET | `/api/users/<id>` | Get user info (commitment only) |
| GET | `/api/users/<id>/balance` | Get balance (demo — includes actual balance) |
| POST | `/api/transactions` | Create transaction `{sender_id, receiver_id, amount}` |
| GET | `/api/transactions/<id>` | Get transaction details |
| GET | `/api/users/<id>/transactions` | Get user transaction history |
| POST | `/api/demo/setup` | Create demo users (Alice 10000, Bob 5000, Charlie 15000) |
| GET | `/api/benchmark` | Run Schnorr vs DSA vs ECDSA benchmark |
| POST | `/api/chunked-demo` | Demo chunked balance proof for balance > q |

Run: `python api/app.py` → `http://0.0.0.0:5000`

---

## Benchmarks (`benchmarks/comparison.py`)

Compares Schnorr, DSA, ECDSA across:
- Key generation, signing, verification (avg of 5 runs)
- Batch verification (20 proofs/sigs)
- Signature size (bytes)
- Throughput (signs/sec, 50 iterations)
- ZK balance proof generation + verification

Run: `python benchmarks/comparison.py`

**Schnorr wins** because: native ZK proofs, batch verification, signature aggregation, simpler math.

---

## Test Suite

| File | Tests | Coverage |
|------|-------|----------|
| `test_dlp_core.py` | 6 | DLP params, mod_exp, keypair, commitment hiding |
| `test_schnorr.py` | 6 | Valid/invalid proofs, balance sufficiency/insufficiency, verification |
| `test_transaction_service.py` | 8 | User CRUD, successful tx, insufficient balance, invalid inputs, history |
| `test_advanced_crypto.py` | 13 | Batch verify, DH exchange, ElGamal encrypt/decrypt, homomorphic, signatures, tampering |
| **Total** | **33** | All passing ✅ |

Run: `python -m pytest tests/` or `python -m unittest discover tests/`

---

## Security Model

| Property | Mechanism |
|----------|-----------|
| Soundness | Cannot fake proof without solving DLP |
| Zero-Knowledge | Verifier learns only "balance ≥ amount" |
| Completeness | Honest prover always succeeds |
| Forward Secrecy | Ephemeral DH keys |
| Non-Repudiation | Schnorr signatures on transactions |
| Hiding | Pedersen commitments hide balance values |

**Key size**: 256-bit (demo); production requires 2048+ bit DLP or switch to ECDLP.  
**Quantum vulnerability**: All DLP-based schemes broken by Shor's algorithm.

---

## Protocol Comparison Summary

| Feature | Schnorr | DSA | ECDSA |
|---------|---------|-----|-------|
| ZK proofs | ✅ Native | ❌ | ❌ |
| Batch verify | ✅ | ❌ | ❌ |
| Sig aggregation | ✅ | ❌ | ❌ |
| Blind sigs | ✅ | ❌ | ❌ |
| Signing overhead | None (no mod inverse) | mod inverse | EC scalar mul |
| Security proof | Tight (ROM) | Partial | Partial |

---

## Key Design Decisions

1. **Chunked balance proofs**: Balances can exceed the DLP subgroup order `q`. The `BalanceProver` decomposes balance into base-q chunks and proves each independently. The combined commitment is the product of chunk commitments (homomorphic property).

2. **In-memory storage**: `TransactionService` uses Python dicts. No persistence across restarts. Production would need a database.

3. **Demo vs production**: The `/api/users/<id>/balance` endpoint exposes actual balance — this is explicitly marked as demo-only. In production, only commitments would be exposed.

4. **Simplified range proofs**: `RangeVerifier._verify_bit_proof()` returns `True` (simplified). Production would implement proper OR proofs for bit commitments.

5. **Simplified multi-sig**: `MultiSignature.verify_multisig()` returns `True` (simplified). Production would use proper aggregation (e.g., MuSig).

6. **XOR encryption**: `UPISecureSession.encrypt_transaction_data()` and `HybridEncryption` use XOR for demo. Production would use AES-GCM or ChaCha20-Poly1305.

---

## Future Work (Planned)

- [ ] ECDLP for better performance
- [ ] Database persistence (SQLAlchemy + PostgreSQL)
- [ ] Docker deployment
- [ ] Bulletproofs for efficient range proofs
- [ ] zk-SNARKs for complex proofs
- [ ] Threshold signatures
- [ ] Post-quantum alternatives (lattice-based)
- [ ] Rate limiting, logging, monitoring
