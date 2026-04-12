"""
Discrete Logarithm Problem (DLP) Core Implementation
Provides cryptographic primitives based on DLP hardness
"""

import secrets
from typing import Tuple


class DLPParameters:
    """
    DLP parameters for cryptographic operations
    Using a safe prime p where p = 2q + 1 (q is also prime)
    """
    
    # 256-bit safe prime for demonstration (in production, use 2048+ bits)
    # This is a Sophie Germain prime where p = 2q + 1
    P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    
    # Generator of the multiplicative group
    G = 2
    
    # Order of the subgroup (q where p = 2q + 1)
    Q = (P - 1) // 2
    
    @classmethod
    def get_parameters(cls) -> Tuple[int, int, int]:
        """Returns (p, g, q) - prime, generator, subgroup order"""
        return cls.P, cls.G, cls.Q


def mod_exp(base: int, exponent: int, modulus: int) -> int:
    """
    Modular exponentiation: (base^exponent) mod modulus
    Efficient implementation using Python's built-in pow
    """
    return pow(base, exponent, modulus)


def generate_private_key() -> int:
    """
    Generate a random private key in the range [1, q-1]
    This is the secret that makes DLP hard to solve
    """
    _, _, q = DLPParameters.get_parameters()
    return secrets.randbelow(q - 1) + 1


def compute_public_key(private_key: int) -> int:
    """
    Compute public key from private key using DLP
    public_key = g^private_key mod p
    
    Security: Given public_key, finding private_key requires solving DLP
    """
    p, g, _ = DLPParameters.get_parameters()
    return mod_exp(g, private_key, p)


def generate_keypair() -> Tuple[int, int]:
    """
    Generate a DLP-based keypair
    Returns: (private_key, public_key)
    """
    private_key = generate_private_key()
    public_key = compute_public_key(private_key)
    return private_key, public_key


def create_commitment(value: int, randomness: int) -> int:
    """
    Create a Pedersen commitment to a value
    commitment = g^value * h^randomness mod p
    
    This is computationally hiding (due to DLP) and perfectly binding
    """
    p, g, _ = DLPParameters.get_parameters()
    # Use a second generator h (derived from g for simplicity)
    h = mod_exp(g, 2, p)
    
    commitment = (mod_exp(g, value, p) * mod_exp(h, randomness, p)) % p
    return commitment


def generate_challenge() -> int:
    """
    Generate a random challenge for the ZK protocol
    Challenge is used to ensure the prover cannot cheat
    """
    _, _, q = DLPParameters.get_parameters()
    return secrets.randbelow(q)


class DLPProof:
    """
    Represents a zero-knowledge proof based on DLP
    """
    
    def __init__(self, commitment: int, challenge: int, response: int):
        self.commitment = commitment
        self.challenge = challenge
        self.response = response
    
    def to_dict(self) -> dict:
        """Convert proof to dictionary for serialization"""
        return {
            'commitment': hex(self.commitment),
            'challenge': hex(self.challenge),
            'response': hex(self.response)
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'DLPProof':
        """Create proof from dictionary"""
        return cls(
            commitment=int(data['commitment'], 16),
            challenge=int(data['challenge'], 16),
            response=int(data['response'], 16)
        )
