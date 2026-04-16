
# Schnorr vs DSA vs ECDSA — Protocol Comparison

This document compares the three digital signature protocols implemented in this project, all rooted in the hardness of the Discrete Logarithm Problem (DLP).

## Overview

| Property | Schnorr | DSA | ECDSA |
|---|---|---|---|
| Based on | DLP (mod p) | DLP (mod p) | ECDLP (secp256k1) |
| Key size | 256-bit | 256-bit | 256-bit |
| Signature size | 2 values (r, s) | 2 values (r, s) | 2 values (r, s) |
| Hash function | SHA-256 | SHA-256 | SHA-256 |
| Standardized | ISO/IEC 14888-3 | FIPS 186-4 | FIPS 186-4, SEC2 |

## How They Work

All three schemes follow a similar pattern: key generation, signing with a random nonce, and deterministic verification. The core difference is in the math.

- Schnorr: The simplest. Signing computes `s = k + e·x mod q` where `e = H(r ‖ m)`. Verification checks `g^s = r · y^e`. No modular inverse needed during signing.
- DSA: Signing requires a modular inverse of the nonce `k⁻¹`, adding computational overhead. Verification involves two modular exponentiations and an inverse.
- ECDSA: Same structure as DSA but operates over elliptic curve point arithmetic (secp256k1). Scalar multiplication replaces modular exponentiation, making it more complex per operation but offering stronger security per bit.

## Performance Comparison

Benchmarked using `benchmarks/comparison.py` (average of 5 runs per operation):

| Operation | Schnorr | DSA | ECDSA |
|---|---|---|---|
| Key Generation | Fastest | Comparable | Slowest (EC scalar mul) |
| Signing | Fastest (no inverse) | Slower (mod inverse) | Slowest (EC ops) |
| Verification | Fastest | Moderate | Slowest (EC point add + mul) |

Run `python benchmarks/comparison.py` to get exact timings on your machine.

## Feature Comparison

| Feature | Schnorr | DSA | ECDSA |
|---|---|---|---|
| Zero-knowledge proofs | ✅ Native | ❌ | ❌ |
| Signature aggregation | ✅ (MuSig) | ❌ | ❌ |
| Batch verification | ✅ Efficient | ❌ | ❌ |
| Blind signatures | ✅ | ❌ | ❌ |
| Multi-signatures | ✅ Simple | ❌ | ❌ |
| Provable security | Tight reduction | Partial | Partial |
| Implementation complexity | Simple | Moderate | Complex |

## Security

| Aspect | Schnorr | DSA | ECDSA |
|---|---|---|---|
| Hardness assumption | DLP | DLP | ECDLP |
| Security proof | Tight (ROM) | Loose | Loose |
| Nonce reuse impact | Key recovery | Key recovery | Key recovery |
| Bits of security (256-bit key) | ~128 | ~128 | ~128 |

All three are equally broken by nonce reuse — if the same `k` is used for two different messages, the private key can be recovered. Deterministic nonce generation (RFC 6979) mitigates this in production.

## Why Schnorr Wins for This Project

This project uses Schnorr as the primary protocol for UPI transaction privacy because:

1. It naturally extends into zero-knowledge proofs (prove balance ≥ amount without revealing it)
2. Signature aggregation reduces verification cost for bulk transactions
3. Simpler math means fewer implementation bugs and easier auditing
4. Blind signatures enable anonymous payment authentication

DSA and ECDSA are included as benchmarks to demonstrate Schnorr's advantages in a fintech context.

## Running the Benchmark

```bash
python benchmarks/comparison.py
```

This outputs key generation, signing, and verification times for all three protocols side by side.
