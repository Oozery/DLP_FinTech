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
    BalanceVerifier,
    ChunkedBalanceProof
)

from .ecc_schnorr import (
    ECSchnorrProver,
    ECSchnorrVerifier,
    ECBalanceProver,
    ECBalanceVerifier,
    ECSchnorrProof,
    ECBalanceProof,
)

from .batch_verification import (
    BatchVerifier,
    TransactionBatchVerifier,
    PerformanceComparison,
    ECBatchVerifier,
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

from .dsa import (
    DSASigner,
    DSAVerifier
)

from .ecdsa import (
    ECDSASigner,
    ECDSAVerifier,
    ECCurve,
    ECPoint
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
    'ChunkedBalanceProof',
    
    # Batch Verification
    'BatchVerifier',
    'TransactionBatchVerifier',
    'PerformanceComparison',
    'ECBatchVerifier',

    # ECC Schnorr ZK Proofs
    'ECSchnorrProver',
    'ECSchnorrVerifier',
    'ECBalanceProver',
    'ECBalanceVerifier',
    'ECSchnorrProof',
    'ECBalanceProof',
    
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
    'UPIRangeValidator',
    
    # DSA
    'DSASigner',
    'DSAVerifier',
    
    # ECDSA
    'ECDSASigner',
    'ECDSAVerifier',
    'ECCurve',
    'ECPoint'
]
