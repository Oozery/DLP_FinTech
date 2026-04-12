"""
Diffie-Hellman Key Exchange using DLP
Enables two parties to establish a shared secret over an insecure channel

Security: Based on Computational Diffie-Hellman (CDH) problem
Given g^a and g^b, computing g^(ab) is hard (related to DLP)

Use case in fintech: Secure channel establishment between UPI app and payment gateway
"""

from typing import Tuple
from .dlp_core import DLPParameters, mod_exp, generate_private_key
import secrets
import hashlib


class DiffieHellmanParty:
    """
    Represents one party in Diffie-Hellman key exchange
    """
    
    def __init__(self, party_name: str):
        self.party_name = party_name
        self.p, self.g, self.q = DLPParameters.get_parameters()
        
        # Generate private key
        self.private_key = generate_private_key()
        
        # Compute public key: g^private_key mod p
        self.public_key = mod_exp(self.g, self.private_key, self.p)
        
        self.shared_secret = None
        self.session_key = None
    
    def get_public_key(self) -> int:
        """Get public key to send to other party"""
        return self.public_key
    
    def compute_shared_secret(self, other_public_key: int) -> int:
        """
        Compute shared secret from other party's public key
        shared_secret = other_public_key^private_key mod p
        
        Security: Both parties compute the same value:
        Alice: (g^b)^a = g^(ab) mod p
        Bob: (g^a)^b = g^(ab) mod p
        
        Attacker sees g^a and g^b but cannot compute g^(ab) (CDH problem)
        """
        self.shared_secret = mod_exp(other_public_key, self.private_key, self.p)
        
        # Derive session key from shared secret using hash function
        self.session_key = self._derive_session_key(self.shared_secret)
        
        return self.shared_secret
    
    def _derive_session_key(self, shared_secret: int) -> bytes:
        """
        Derive a session key from shared secret using KDF
        Uses SHA-256 as key derivation function
        """
        secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')
        return hashlib.sha256(secret_bytes).digest()
    
    def get_session_key(self) -> bytes:
        """Get derived session key for encryption"""
        if self.session_key is None:
            raise ValueError("Shared secret not computed yet")
        return self.session_key


class SecureChannel:
    """
    Establishes a secure communication channel using Diffie-Hellman
    Simulates secure channel between UPI app and payment gateway
    """
    
    def __init__(self, party_a_name: str, party_b_name: str):
        self.party_a = DiffieHellmanParty(party_a_name)
        self.party_b = DiffieHellmanParty(party_b_name)
        self.channel_established = False
    
    def establish_channel(self) -> Tuple[bytes, bytes]:
        """
        Perform key exchange and establish secure channel
        
        Returns: (party_a_session_key, party_b_session_key)
        Both should be identical
        """
        # Exchange public keys
        pub_a = self.party_a.get_public_key()
        pub_b = self.party_b.get_public_key()
        
        # Each party computes shared secret
        secret_a = self.party_a.compute_shared_secret(pub_b)
        secret_b = self.party_b.compute_shared_secret(pub_a)
        
        # Verify both computed the same shared secret
        if secret_a != secret_b:
            raise ValueError("Key exchange failed: shared secrets don't match")
        
        self.channel_established = True
        
        return self.party_a.get_session_key(), self.party_b.get_session_key()
    
    def is_secure(self) -> bool:
        """Check if channel is established and secure"""
        if not self.channel_established:
            return False
        
        # Verify both parties have the same session key
        return self.party_a.get_session_key() == self.party_b.get_session_key()


class UPISecureSession:
    """
    Simulates secure session establishment for UPI transactions
    Uses DH key exchange to create encrypted channel
    """
    
    def __init__(self, user_id: str, gateway_id: str):
        self.user_id = user_id
        self.gateway_id = gateway_id
        self.channel = SecureChannel(f"User-{user_id}", f"Gateway-{gateway_id}")
        self.session_active = False
    
    def initiate_session(self) -> dict:
        """
        Initiate secure session between user and payment gateway
        
        Returns session information
        """
        # Establish DH channel
        user_key, gateway_key = self.channel.establish_channel()
        
        # Verify keys match
        if user_key != gateway_key:
            return {
                'success': False,
                'error': 'Key exchange failed'
            }
        
        self.session_active = True
        
        return {
            'success': True,
            'user_id': self.user_id,
            'gateway_id': self.gateway_id,
            'session_key': user_key.hex()[:32] + '...',  # Show partial key
            'channel_secure': self.channel.is_secure(),
            'message': 'Secure session established'
        }
    
    def encrypt_transaction_data(self, transaction_data: str) -> bytes:
        """
        Encrypt transaction data using session key
        Simplified encryption for demonstration
        """
        if not self.session_active:
            raise ValueError("Session not active")
        
        session_key = self.channel.party_a.get_session_key()
        
        # Simple XOR encryption for demonstration
        # Production would use AES or ChaCha20
        data_bytes = transaction_data.encode()
        encrypted = bytes(a ^ b for a, b in zip(data_bytes, session_key * (len(data_bytes) // len(session_key) + 1)))
        
        return encrypted
    
    def get_session_info(self) -> dict:
        """Get current session information"""
        return {
            'user_id': self.user_id,
            'gateway_id': self.gateway_id,
            'session_active': self.session_active,
            'channel_secure': self.channel.is_secure() if self.session_active else False
        }


class EphemeralDH:
    """
    Ephemeral Diffie-Hellman for forward secrecy
    Generates new keys for each session
    
    Forward Secrecy: Even if long-term keys are compromised,
    past session keys remain secure
    """
    
    def __init__(self):
        self.p, self.g, self.q = DLPParameters.get_parameters()
    
    def generate_ephemeral_keypair(self) -> Tuple[int, int]:
        """
        Generate ephemeral (temporary) keypair for one session
        
        Returns: (private_key, public_key)
        """
        private_key = generate_private_key()
        public_key = mod_exp(self.g, private_key, self.p)
        return private_key, public_key
    
    def compute_session_key(self, ephemeral_private: int, other_ephemeral_public: int) -> bytes:
        """
        Compute session key from ephemeral keys
        """
        shared_secret = mod_exp(other_ephemeral_public, ephemeral_private, self.p)
        secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')
        return hashlib.sha256(secret_bytes).digest()
    
    def create_session(self, other_public_key: int) -> Tuple[int, bytes]:
        """
        Create a new ephemeral session
        
        Returns: (my_public_key, session_key)
        """
        my_private, my_public = self.generate_ephemeral_keypair()
        session_key = self.compute_session_key(my_private, other_public_key)
        
        # Immediately discard private key (forward secrecy)
        # In production, would securely wipe from memory
        
        return my_public, session_key


def demonstrate_diffie_hellman():
    """
    Demonstrate Diffie-Hellman key exchange
    """
    print("=== Diffie-Hellman Key Exchange Demonstration ===\n")
    
    # Create two parties
    alice = DiffieHellmanParty("Alice")
    bob = DiffieHellmanParty("Bob")
    
    print("Parties:")
    print(f"  Alice: Private key = {alice.private_key}")
    print(f"         Public key = {hex(alice.public_key)[:30]}...")
    print(f"  Bob:   Private key = {bob.private_key}")
    print(f"         Public key = {hex(bob.public_key)[:30]}...")
    
    # Exchange public keys and compute shared secret
    print("\n--- Key Exchange ---")
    print("Alice sends public key to Bob")
    print("Bob sends public key to Alice")
    
    alice_secret = alice.compute_shared_secret(bob.get_public_key())
    bob_secret = bob.compute_shared_secret(alice.get_public_key())
    
    print(f"\nAlice computes: {hex(alice_secret)[:30]}...")
    print(f"Bob computes:   {hex(bob_secret)[:30]}...")
    
    if alice_secret == bob_secret:
        print("\n✓ Shared secrets match!")
        print(f"  Session key (Alice): {alice.get_session_key().hex()[:32]}...")
        print(f"  Session key (Bob):   {bob.get_session_key().hex()[:32]}...")
    else:
        print("\n✗ Key exchange failed")
    
    # UPI session example
    print("\n=== UPI Secure Session Example ===\n")
    session = UPISecureSession("user123", "gateway456")
    result = session.initiate_session()
    
    if result['success']:
        print("✓ Secure session established")
        print(f"  User: {result['user_id']}")
        print(f"  Gateway: {result['gateway_id']}")
        print(f"  Session key: {result['session_key']}")
        print(f"  Channel secure: {result['channel_secure']}")


if __name__ == "__main__":
    demonstrate_diffie_hellman()
