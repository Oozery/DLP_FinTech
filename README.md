# Privacy-Preserving UPI Balance Verification using Zero-Knowledge Proofs

## Project Overview
A comprehensive fintech security system that uses Discrete Logarithm Problem (DLP) based cryptographic protocols to enable privacy-preserving transactions. The system implements multiple DLP-based schemes including Zero-Knowledge Proofs, key exchange, encryption, and digital signatures.

## Core Features

### Cryptographic Protocols (DLP-Based)
1. **Zero-Knowledge Proofs** - Schnorr protocol for balance verification
2. **Batch Verification** - Efficient verification of multiple proofs
3. **Diffie-Hellman Key Exchange** - Secure channel establishment
4. **ElGamal Encryption** - Public-key encryption with homomorphic properties
5. **Digital Signatures** - Schnorr signatures for transaction authentication
6. **Range Proofs** - Prove values within ranges for compliance
7. **Multi-Signatures** - Support for multi-party authorization

### Fintech Application
- **Privacy-Preserving Transactions**: Verify balance sufficiency without revealing amounts
- **Secure Communication**: Encrypted channels between users and gateways
- **Transaction Signing**: Non-repudiation and authentication
- **Batch Processing**: Efficient verification of multiple transactions
- **Regulatory Compliance**: Range proofs for UPI transaction limits

## Architecture
- **Crypto Layer**: 7 DLP-based cryptographic modules (~1900 lines)
- **Backend Layer**: Transaction service with ZK verification (~200 lines)
- **API Layer**: RESTful endpoints for all operations (~150 lines)
- **Testing**: 33 comprehensive unit tests (~450 lines)

## Security Guarantees
- **Soundness**: Prover cannot fake insufficient balance (relies on DLP hardness)
- **Zero-Knowledge**: Verifier learns nothing except balance sufficiency
- **Completeness**: Honest prover always convinces verifier
- **Forward Secrecy**: Ephemeral keys protect past sessions
- **Non-Repudiation**: Digital signatures prevent transaction denial

## Use Cases
1. **UPI Payment Verification**: Prove sufficient balance without revealing amount
2. **Secure Sessions**: Establish encrypted channels for sensitive data
3. **Transaction Authentication**: Sign transactions for proof of authorization
4. **Bulk Processing**: Verify multiple transactions efficiently
5. **Regulatory Compliance**: Prove transaction amounts within limits
