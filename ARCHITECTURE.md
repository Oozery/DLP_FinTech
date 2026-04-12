# System Architecture

## Overview
Privacy-Preserving UPI Payment System using Discrete Logarithm Problem (DLP) based Zero-Knowledge Proofs.

## Architecture Layers

### 1. Cryptographic Layer (`crypto/`)
**Purpose**: Core DLP and ZK proof implementations

#### DLP Core (`dlp_core.py`)
- **DLP Parameters**: Safe prime p, generator g, subgroup order q
- **Modular Exponentiation**: Efficient computation of g^x mod p
- **Key Generation**: Private/public keypair generation based on DLP
- **Commitments**: Pedersen commitments for hiding values
- **Security**: Based on 256-bit DLP (production would use 2048+ bits)

#### Schnorr Protocol (`schnorr_protocol.py`)
- **SchnorrProver**: Creates ZK proofs of knowledge
  - Commitment phase: g^r mod p
  - Response phase: r + c*secret mod q
- **SchnorrVerifier**: Verifies proofs without learning secrets
  - Challenge generation
  - Verification: g^response = commitment * public^challenge
- **BalanceProver**: Specialized for balance verification
- **BalanceVerifier**: Verifies balance proofs

**Key Property**: Soundness relies on DLP hardness - prover cannot fake proof without solving discrete logarithm

### 2. Business Logic Layer (`backend/`)
**Purpose**: Transaction management and user operations

#### Transaction Service (`transaction_service.py`)
- **User Management**: Create users with balance commitments
- **Transaction Processing**: 
  1. Generate ZK proof of sufficient balance
  2. Verify proof using DLP-based verification
  3. Execute transaction if proof valid
- **Privacy Preservation**: Balance commitments shared, actual balances private

**Flow**:
```
User A wants to pay User B amount X
1. A generates proof: "I have balance >= X" (without revealing actual balance)
2. System verifies proof using DLP properties
3. If valid, transaction executes
4. Balances updated, new commitments generated
```

### 3. API Layer (`api/`)
**Purpose**: RESTful interface for client applications

#### Endpoints
- `POST /api/users` - Create user with initial balance
- `GET /api/users/:id` - Get user info (commitment only)
- `POST /api/transactions` - Initiate transaction with ZK proof
- `GET /api/transactions/:id` - Get transaction details
- `GET /api/users/:id/transactions` - Get user transaction history

## Security Model

### Threat Model
**Adversary Goals**:
1. Learn user's actual balance from commitment
2. Create fake proof of sufficient balance
3. Double-spend or manipulate transactions

**Security Guarantees**:
1. **Computational Hiding**: Balance commitment computationally hides balance (DLP hardness)
2. **Soundness**: Cannot create valid proof without sufficient balance (DLP hardness)
3. **Zero-Knowledge**: Verifier learns only "balance >= amount", nothing more

### DLP Security
- **Problem**: Given g, p, and y = g^x mod p, find x
- **Hardness**: No known polynomial-time classical algorithm
- **Key Size**: 256-bit for demo, 2048+ bit for production
- **Quantum Resistance**: Vulnerable to Shor's algorithm (future work: lattice-based alternatives)

## Data Flow

### Transaction Flow
```
Client → API → TransactionService → BalanceProver → SchnorrProver
                                                          ↓
                                                    DLP Operations
                                                          ↓
Client ← API ← TransactionService ← BalanceVerifier ← SchnorrVerifier
```

### Proof Generation
```
1. Prover: commitment = g^r mod p (random r)
2. Verifier: challenge = random c
3. Prover: response = r + c*secret mod q
4. Verifier: check g^response = commitment * (g^secret)^c mod p
```

## Performance Considerations

### Computational Complexity
- **Key Generation**: O(log n) for modular exponentiation
- **Proof Generation**: 2 modular exponentiations
- **Proof Verification**: 3 modular exponentiations
- **Transaction**: ~5 modular exponentiations total

### Optimization Opportunities
1. Pre-compute common values
2. Use faster elliptic curve groups (ECDLP)
3. Batch verification for multiple proofs
4. Hardware acceleration for modular arithmetic

## Scalability

### Current Limitations
- In-memory storage (not persistent)
- Single-server architecture
- Synchronous proof generation

### Production Enhancements
1. Database for persistent storage
2. Distributed verification nodes
3. Asynchronous proof generation
4. Caching of commitments and public parameters

## Testing Strategy

### Unit Tests
- DLP primitives (modular exponentiation, key generation)
- Schnorr protocol (proof generation, verification)
- Transaction service (user management, transaction flow)

### Integration Tests
- End-to-end transaction flow
- API endpoint testing
- Error handling and edge cases

### Security Tests
- Invalid proof rejection
- Insufficient balance detection
- Commitment integrity

## Future Enhancements

1. **Range Proofs**: Prove balance in specific range without revealing exact value
2. **Multi-Party Computation**: Distributed transaction verification
3. **Elliptic Curves**: Faster operations with ECDLP
4. **Regulatory Compliance**: Selective disclosure for audits
5. **Post-Quantum**: Lattice-based alternatives to DLP
