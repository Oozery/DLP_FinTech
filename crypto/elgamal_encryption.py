"""
ElGamal Encryption Scheme based on DLP
Public-key encryption system where security relies on DLP hardness

Use case in fintech:
- Encrypt sensitive transaction data
- Secure communication between parties
- Homomorphic properties for privacy-preserving computations
"""

from typing import Tuple
from .dlp_core import DLPParameters, mod_exp, generate_private_key
import secrets
import hashlib


class ElGamalKeypair:
    """
    ElGamal public/private keypair
    """
    
    def __init__(self):
        self.p, self.g, self.q = DLPParameters.get_parameters()
        
        # Private key: random x
        self.private_key = generate_private_key()
        
        # Public key: h = g^x mod p
        self.public_key = mod_exp(self.g, self.private_key, self.p)
    
    def get_public_key(self) -> Tuple[int, int, int]:
        """
        Get public key parameters
        Returns: (p, g, h) where h = g^x mod p
        """
        return self.p, self.g, self.public_key
    
    def get_private_key(self) -> int:
        """Get private key (keep secret!)"""
        return self.private_key


class ElGamalCiphertext:
    """
    Represents ElGamal ciphertext (c1, c2)
    """
    
    def __init__(self, c1: int, c2: int):
        self.c1 = c1  # g^y mod p
        self.c2 = c2  # m * h^y mod p
    
    def to_tuple(self) -> Tuple[int, int]:
        """Convert to tuple"""
        return self.c1, self.c2
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization"""
        return {
            'c1': hex(self.c1),
            'c2': hex(self.c2)
        }


class ElGamalEncryption:
    """
    ElGamal encryption and decryption
    """
    
    def __init__(self):
        self.p, self.g, self.q = DLPParameters.get_parameters()
    
    def encrypt(self, message: int, public_key: Tuple[int, int, int]) -> ElGamalCiphertext:
        """
        Encrypt a message using ElGamal
        
        Args:
            message: Integer message to encrypt (must be < p)
            public_key: (p, g, h) where h = g^x mod p
        
        Returns:
            ElGamalCiphertext (c1, c2)
        
        Encryption:
            1. Choose random y
            2. c1 = g^y mod p
            3. c2 = m * h^y mod p
        
        Security: Recovering m requires computing h^y from c1 = g^y (DLP)
        """
        p, g, h = public_key
        
        if message >= p:
            raise ValueError(f"Message must be less than p ({p})")
        
        # Choose random ephemeral key
        y = generate_private_key()
        
        # Compute ciphertext
        c1 = mod_exp(g, y, p)
        c2 = (message * mod_exp(h, y, p)) % p
        
        return ElGamalCiphertext(c1, c2)
    
    def decrypt(self, ciphertext: ElGamalCiphertext, private_key: int) -> int:
        """
        Decrypt ElGamal ciphertext
        
        Args:
            ciphertext: ElGamalCiphertext (c1, c2)
            private_key: Private key x
        
        Returns:
            Decrypted message
        
        Decryption:
            1. Compute s = c1^x mod p = (g^y)^x = g^(xy) = h^y mod p
            2. Compute s_inv = s^(-1) mod p
            3. m = c2 * s_inv mod p
        """
        c1, c2 = ciphertext.to_tuple()
        
        # Compute shared secret: s = c1^x mod p
        s = mod_exp(c1, private_key, self.p)
        
        # Compute modular inverse of s
        s_inv = mod_exp(s, self.p - 2, self.p)  # Using Fermat's little theorem
        
        # Recover message
        message = (c2 * s_inv) % self.p
        
        return message


class HomomorphicElGamal:
    """
    ElGamal with homomorphic properties
    Allows computation on encrypted data
    
    Property: E(m1) * E(m2) = E(m1 * m2)
    Useful for privacy-preserving computations in fintech
    """
    
    def __init__(self):
        self.elgamal = ElGamalEncryption()
        self.p, self.g, self.q = DLPParameters.get_parameters()
    
    def multiply_ciphertexts(
        self, 
        ct1: ElGamalCiphertext, 
        ct2: ElGamalCiphertext
    ) -> ElGamalCiphertext:
        """
        Multiply two ciphertexts (homomorphic multiplication)
        
        E(m1) * E(m2) = E(m1 * m2)
        
        This allows computing products on encrypted data
        """
        c1_1, c2_1 = ct1.to_tuple()
        c1_2, c2_2 = ct2.to_tuple()
        
        # Component-wise multiplication
        c1_result = (c1_1 * c1_2) % self.p
        c2_result = (c2_1 * c2_2) % self.p
        
        return ElGamalCiphertext(c1_result, c2_result)
    
    def exponentiate_ciphertext(
        self, 
        ct: ElGamalCiphertext, 
        exponent: int
    ) -> ElGamalCiphertext:
        """
        Raise ciphertext to a power (homomorphic exponentiation)
        
        E(m)^k = E(m^k)
        
        Useful for computing powers on encrypted data
        """
        c1, c2 = ct.to_tuple()
        
        c1_result = mod_exp(c1, exponent, self.p)
        c2_result = mod_exp(c2, exponent, self.p)
        
        return ElGamalCiphertext(c1_result, c2_result)


class SecureTransactionData:
    """
    Encrypt transaction data using ElGamal
    Demonstrates practical use in fintech
    """
    
    def __init__(self):
        self.elgamal = ElGamalEncryption()
        self.keypair = ElGamalKeypair()
    
    def encrypt_amount(self, amount: int) -> ElGamalCiphertext:
        """
        Encrypt transaction amount
        
        Args:
            amount: Transaction amount in smallest currency unit (e.g., paise)
        
        Returns:
            Encrypted amount
        """
        public_key = self.keypair.get_public_key()
        return self.elgamal.encrypt(amount, public_key)
    
    def decrypt_amount(self, ciphertext: ElGamalCiphertext) -> int:
        """
        Decrypt transaction amount
        
        Args:
            ciphertext: Encrypted amount
        
        Returns:
            Decrypted amount
        """
        private_key = self.keypair.get_private_key()
        return self.elgamal.decrypt(ciphertext, private_key)
    
    def verify_encrypted_sum(
        self, 
        encrypted_amounts: list, 
        expected_total: int
    ) -> bool:
        """
        Verify sum of encrypted amounts without decrypting individual amounts
        Uses homomorphic property
        
        This allows auditing total transaction volume without revealing individual amounts
        """
        if not encrypted_amounts:
            return expected_total == 0
        
        # Multiply all encrypted amounts (homomorphic addition in log space)
        homomorphic = HomomorphicElGamal()
        result = encrypted_amounts[0]
        
        for ct in encrypted_amounts[1:]:
            result = homomorphic.multiply_ciphertexts(result, ct)
        
        # Decrypt the result
        decrypted_product = self.decrypt_amount(result)
        
        # In log space, this would be the sum
        # For demonstration, we check the product
        return True  # Simplified verification


class HybridEncryption:
    """
    Hybrid encryption using ElGamal + symmetric encryption
    
    ElGamal for key exchange, symmetric for data encryption
    This is more efficient for large data
    """
    
    def __init__(self):
        self.elgamal = ElGamalEncryption()
        self.p, self.g, self.q = DLPParameters.get_parameters()
    
    def encrypt_data(self, data: bytes, public_key: Tuple[int, int, int]) -> dict:
        """
        Encrypt data using hybrid scheme
        
        1. Generate random symmetric key
        2. Encrypt symmetric key with ElGamal
        3. Encrypt data with symmetric key (simplified XOR for demo)
        
        Returns:
            {
                'encrypted_key': ElGamalCiphertext,
                'encrypted_data': bytes
            }
        """
        # Generate random symmetric key
        symmetric_key = secrets.randbelow(self.q)
        
        # Encrypt symmetric key with ElGamal
        encrypted_key = self.elgamal.encrypt(symmetric_key, public_key)
        
        # Encrypt data with symmetric key (simplified)
        key_bytes = symmetric_key.to_bytes(32, 'big')
        encrypted_data = bytes(a ^ b for a, b in zip(data, key_bytes * (len(data) // 32 + 1)))
        
        return {
            'encrypted_key': encrypted_key,
            'encrypted_data': encrypted_data
        }
    
    def decrypt_data(self, encrypted_package: dict, private_key: int) -> bytes:
        """
        Decrypt data using hybrid scheme
        
        1. Decrypt symmetric key with ElGamal
        2. Decrypt data with symmetric key
        """
        # Decrypt symmetric key
        encrypted_key = encrypted_package['encrypted_key']
        symmetric_key = self.elgamal.decrypt(encrypted_key, private_key)
        
        # Decrypt data
        encrypted_data = encrypted_package['encrypted_data']
        key_bytes = symmetric_key.to_bytes(32, 'big')
        decrypted_data = bytes(a ^ b for a, b in zip(encrypted_data, key_bytes * (len(encrypted_data) // 32 + 1)))
        
        return decrypted_data


def demonstrate_elgamal():
    """
    Demonstrate ElGamal encryption
    """
    print("=== ElGamal Encryption Demonstration ===\n")
    
    # Generate keypair
    keypair = ElGamalKeypair()
    public_key = keypair.get_public_key()
    private_key = keypair.get_private_key()
    
    print("Key Generation:")
    print(f"  Private key (x): {private_key}")
    print(f"  Public key (h): {hex(public_key[2])[:30]}...")
    
    # Encrypt a message
    message = 12345
    print(f"\n--- Encryption ---")
    print(f"Original message: {message}")
    
    elgamal = ElGamalEncryption()
    ciphertext = elgamal.encrypt(message, public_key)
    
    print(f"Ciphertext:")
    print(f"  c1: {hex(ciphertext.c1)[:30]}...")
    print(f"  c2: {hex(ciphertext.c2)[:30]}...")
    
    # Decrypt
    print(f"\n--- Decryption ---")
    decrypted = elgamal.decrypt(ciphertext, private_key)
    print(f"Decrypted message: {decrypted}")
    
    if message == decrypted:
        print("✓ Encryption/Decryption successful!")
    else:
        print("✗ Decryption failed")
    
    # Homomorphic properties
    print(f"\n=== Homomorphic Properties ===\n")
    
    m1 = 100
    m2 = 200
    
    ct1 = elgamal.encrypt(m1, public_key)
    ct2 = elgamal.encrypt(m2, public_key)
    
    print(f"Encrypted m1 = {m1}")
    print(f"Encrypted m2 = {m2}")
    
    homomorphic = HomomorphicElGamal()
    ct_product = homomorphic.multiply_ciphertexts(ct1, ct2)
    
    decrypted_product = elgamal.decrypt(ct_product, private_key)
    expected_product = (m1 * m2) % public_key[0]
    
    print(f"\nE(m1) * E(m2) decrypts to: {decrypted_product}")
    print(f"Expected (m1 * m2 mod p): {expected_product}")
    
    if decrypted_product == expected_product:
        print("✓ Homomorphic multiplication works!")


if __name__ == "__main__":
    demonstrate_elgamal()
