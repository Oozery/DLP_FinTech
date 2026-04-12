"""
Cryptographic module for DLP-based Zero-Knowledge Proofs
Comprehensive implementation of DLP-based cryptographic primitives
"""

from .dlp_core import (
    DLPParameters,
    mod_exp,
    generate_keypair,
    generate_private_key,
    compute_public_key,
    create_commitment,
    DLPProof
)

from .schnorr_protocol import (
    SchnorrProver,
    SchnorrVerifier,
    BalanceProver,
    BalanceVerifier
)

from .batch_verification import (
    BatchVerifier,
    TransactionBatchVerifier,
    PerformanceComparison
)

from .diffie_hellman import (
    DiffieHellmanParty,
    SecureChannel,
    UPISecureSession,
    EphemeralDH
)

from .elgamal_encryption import (
    ElGamalKeypair,
    ElGamalEncryption,
    ElGamalCiphertext,
    HomomorphicElGamal,
    SecureTransactionData
)

from .schnorr_signatures import (
    SchnorrSignature,
    SchnorrSigner,
    SchnorrVerifier as SignatureVerifier,
    TransactionSigner,
    TransactionVerifier,
    MultiSignature
)

from .range_proofs import (
    RangeProof,
    RangeProver,
    RangeVerifier,
    BalanceRangeProver,
    UPIRangeValidator
)

__all__ = [
    # Core DLP
    'DLPParameters',
    'mod_exp',
    'generate_keypair',
    'generate_private_key',
    'compute_public_key',
    'create_commitment',
    'DLPProof',
    
    # Zero-Knowledge Proofs
    'SchnorrProver',
    'SchnorrVerifier',
    'BalanceProver',
    'BalanceVerifier',
    
    # Batch Verification
    'BatchVerifier',
    'TransactionBatchVerifier',
    'PerformanceComparison',
    
    # Key Exchange
    'DiffieHellmanParty',
    'SecureChannel',
    'UPISecureSession',
    'EphemeralDH',
    
    # Encryption
    'ElGamalKeypair',
    'ElGamalEncryption',
    'ElGamalCiphertext',
    'HomomorphicElGamal',
    'SecureTransactionData',
    
    # Digital Signatures
    'SchnorrSignature',
    'SchnorrSigner',
    'SignatureVerifier',
    'TransactionSigner',
    'TransactionVerifier',
    'MultiSignature',
    
    # Range Proofs
    'RangeProof',
    'RangeProver',
    'RangeVerifier',
    'BalanceRangeProver',
    'UPIRangeValidator'
]
