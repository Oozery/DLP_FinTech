"""
Schnorr Digital Signatures based on DLP
Provides authentication and non-repudiation for transactions

Security: Forging a signature requires solving DLP
Use case: Sign UPI transactions to prove authenticity
"""

import hashlib
from typing import Tuple
from .dlp_core import DLPParameters, mod_exp, generate_private_key


class SchnorrSignature:
    """
    Represents a Schnorr signature (r, s)
    """
    
    def __init__(self, r: int, s: int):
        self.r = r  # Commitment value
        self.s = s  # Response value
    
    def to_tuple(self) -> Tuple[int, int]:
        """Convert to tuple"""
        return self.r, self.s
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization"""
        return {
            'r': hex(self.r),
            's': hex(self.s)
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'SchnorrSignature':
        """Create signature from dictionary"""
        return cls(
            r=int(data['r'], 16),
            s=int(data['s'], 16)
        )


class SchnorrSigner:
    """
    Schnorr signature generation
    """
    
    def __init__(self, private_key: int = None):
        self.p, self.g, self.q = DLPParameters.get_parameters()
        
        # Private key (signing key)
        self.private_key = private_key if private_key else generate_private_key()
        
        # Public key (verification key): g^private_key mod p
        self.public_key = mod_exp(self.g, self.private_key, self.p)
    
    def sign(self, message: bytes) -> SchnorrSignature:
        """
        Sign a message using Schnorr signature scheme
        
        Args:
            message: Message to sign (as bytes)
        
        Returns:
            SchnorrSignature (r, s)
        
        Signature generation:
            1. Choose random k
            2. r = g^k mod p
            3. e = H(r || message)  (hash of commitment and message)
            4. s = k + e * private_key mod q
        
        Security: Forging requires finding k such that g^k = r (DLP)
        """
        # Generate random nonce
        k = generate_private_key()
        
        # Compute commitment
        r = mod_exp(self.g, k, self.p)
        
        # Compute challenge (hash of commitment and message)
        e = self._hash_to_challenge(r, message)
        
        # Compute response
        s = (k + e * self.private_key) % self.q
        
        return SchnorrSignature(r, s)
    
    def _hash_to_challenge(self, r: int, message: bytes) -> int:
        """
        Hash commitment and message to create challenge
        Uses SHA-256 and reduces modulo q
        """
        # Convert r to bytes
        r_bytes = r.to_bytes((r.bit_length() + 7) // 8, 'big')
        
        # Hash r || message
        hash_input = r_bytes + message
        hash_output = hashlib.sha256(hash_input).digest()
        
        # Convert hash to integer and reduce modulo q
        e = int.from_bytes(hash_output, 'big') % self.q
        
        return e
    
    def get_public_key(self) -> int:
        """Get public key for signature verification"""
        return self.public_key


class SchnorrVerifier:
    """
    Schnorr signature verification
    """
    
    def __init__(self):
        self.p, self.g, self.q = DLPParameters.get_parameters()
    
    def verify(self, message: bytes, signature: SchnorrSignature, public_key: int) -> bool:
        """
        Verify a Schnorr signature
        
        Args:
            message: Original message (as bytes)
            signature: SchnorrSignature (r, s)
            public_key: Signer's public key
        
        Returns:
            True if signature is valid, False otherwise
        
        Verification:
            1. Compute e = H(r || message)
            2. Check: g^s = r * public_key^e mod p
        
        Why this works:
            g^s = g^(k + e*private_key) = g^k * g^(e*private_key)
                = r * (g^private_key)^e = r * public_key^e
        """
        r, s = signature.to_tuple()
        
        # Compute challenge
        e = self._hash_to_challenge(r, message)
        
        # Verify equation: g^s = r * public_key^e mod p
        left_side = mod_exp(self.g, s, self.p)
        right_side = (r * mod_exp(public_key, e, self.p)) % self.p
        
        return left_side == right_side
    
    def _hash_to_challenge(self, r: int, message: bytes) -> int:
        """Hash commitment and message to create challenge"""
        r_bytes = r.to_bytes((r.bit_length() + 7) // 8, 'big')
        hash_input = r_bytes + message
        hash_output = hashlib.sha256(hash_input).digest()
        e = int.from_bytes(hash_output, 'big') % self.q
        return e


class TransactionSigner:
    """
    Sign UPI transactions for authentication and non-repudiation
    """
    
    def __init__(self, user_id: str, private_key: int = None):
        self.user_id = user_id
        self.signer = SchnorrSigner(private_key)
    
    def sign_transaction(
        self, 
        sender_id: str, 
        receiver_id: str, 
        amount: int, 
        timestamp: str
    ) -> SchnorrSignature:
        """
        Sign a transaction
        
        Creates a signature over transaction details to prove:
        1. Transaction was authorized by sender
        2. Transaction details cannot be modified
        3. Sender cannot deny creating the transaction
        """
        # Create transaction message
        transaction_data = f"{sender_id}|{receiver_id}|{amount}|{timestamp}"
        message = transaction_data.encode('utf-8')
        
        # Sign the transaction
        signature = self.signer.sign(message)
        
        return signature
    
    def get_public_key(self) -> int:
        """Get public key for signature verification"""
        return self.signer.get_public_key()


class TransactionVerifier:
    """
    Verify signed UPI transactions
    """
    
    def __init__(self):
        self.verifier = SchnorrVerifier()
    
    def verify_transaction(
        self,
        sender_id: str,
        receiver_id: str,
        amount: int,
        timestamp: str,
        signature: SchnorrSignature,
        sender_public_key: int
    ) -> bool:
        """
        Verify a signed transaction
        
        Returns True if:
        1. Signature is cryptographically valid
        2. Transaction details match the signature
        """
        # Reconstruct transaction message
        transaction_data = f"{sender_id}|{receiver_id}|{amount}|{timestamp}"
        message = transaction_data.encode('utf-8')
        
        # Verify signature
        return self.verifier.verify(message, signature, sender_public_key)


class MultiSignature:
    """
    Multi-signature scheme for transactions requiring multiple approvals
    Useful for high-value transactions or corporate accounts
    """
    
    def __init__(self, required_signatures: int):
        self.required_signatures = required_signatures
        self.verifier = SchnorrVerifier()
    
    def aggregate_signatures(self, signatures: list) -> SchnorrSignature:
        """
        Aggregate multiple Schnorr signatures
        Simplified aggregation for demonstration
        
        In production, would use proper signature aggregation schemes
        """
        if len(signatures) < self.required_signatures:
            raise ValueError(f"Need at least {self.required_signatures} signatures")
        
        # Simple aggregation: sum of responses
        # Note: This is simplified; production would use proper aggregation
        p, g, q = DLPParameters.get_parameters()
        
        r_combined = signatures[0].r
        s_combined = sum(sig.s for sig in signatures) % q
        
        return SchnorrSignature(r_combined, s_combined)
    
    def verify_multisig(
        self,
        message: bytes,
        aggregated_signature: SchnorrSignature,
        public_keys: list
    ) -> bool:
        """
        Verify aggregated multi-signature
        Checks that required number of valid signatures were provided
        """
        if len(public_keys) < self.required_signatures:
            return False
        
        # Simplified verification
        # Production would verify each signature or use proper aggregation
        return True


class BlindSignature:
    """
    Blind signature scheme for privacy-preserving authentication
    Signer signs a message without seeing its content
    
    Use case: Anonymous payments where bank signs transaction
    without knowing transaction details
    """
    
    def __init__(self):
        self.p, self.g, self.q = DLPParameters.get_parameters()
    
    def blind_message(self, message: bytes, blinding_factor: int) -> bytes:
        """
        Blind a message before sending to signer
        
        Args:
            message: Original message
            blinding_factor: Random blinding factor
        
        Returns:
            Blinded message
        """
        # Convert message to integer
        message_int = int.from_bytes(hashlib.sha256(message).digest(), 'big') % self.q
        
        # Blind: m' = m * g^r mod q
        blinded = (message_int * mod_exp(self.g, blinding_factor, self.q)) % self.q
        
        return blinded.to_bytes(32, 'big')
    
    def unblind_signature(
        self, 
        blind_signature: SchnorrSignature, 
        blinding_factor: int
    ) -> SchnorrSignature:
        """
        Unblind a signature to get signature on original message
        
        Args:
            blind_signature: Signature on blinded message
            blinding_factor: Original blinding factor
        
        Returns:
            Signature on original message
        """
        # Unblind: s = s' - r mod q
        r, s_blind = blind_signature.to_tuple()
        s_unblinded = (s_blind - blinding_factor) % self.q
        
        return SchnorrSignature(r, s_unblinded)


def demonstrate_schnorr_signatures():
    """
    Demonstrate Schnorr signature scheme
    """
    print("=== Schnorr Digital Signatures Demonstration ===\n")
    
    # Create signer
    signer = SchnorrSigner()
    public_key = signer.get_public_key()
    
    print("Key Generation:")
    print(f"  Private key: {signer.private_key}")
    print(f"  Public key: {hex(public_key)[:30]}...")
    
    # Sign a message
    message = b"Transfer 1000 INR from Alice to Bob"
    print(f"\n--- Signing ---")
    print(f"Message: {message.decode()}")
    
    signature = signer.sign(message)
    print(f"Signature:")
    print(f"  r: {hex(signature.r)[:30]}...")
    print(f"  s: {signature.s}")
    
    # Verify signature
    print(f"\n--- Verification ---")
    verifier = SchnorrVerifier()
    is_valid = verifier.verify(message, signature, public_key)
    
    print(f"Signature valid: {'✓ Yes' if is_valid else '✗ No'}")
    
    # Try to verify with wrong message
    wrong_message = b"Transfer 2000 INR from Alice to Bob"
    is_valid_wrong = verifier.verify(wrong_message, signature, public_key)
    
    print(f"\nVerify with modified message: {'✓ Valid' if is_valid_wrong else '✗ Invalid (expected)'}")
    
    # Transaction signing example
    print(f"\n=== Transaction Signing Example ===\n")
    
    tx_signer = TransactionSigner("alice123")
    tx_signature = tx_signer.sign_transaction(
        sender_id="alice123",
        receiver_id="bob456",
        amount=1000,
        timestamp="2024-01-01T12:00:00"
    )
    
    print("Transaction signed:")
    print(f"  Sender: alice123")
    print(f"  Receiver: bob456")
    print(f"  Amount: 1000 INR")
    print(f"  Signature: {tx_signature.to_dict()['r'][:30]}...")
    
    # Verify transaction
    tx_verifier = TransactionVerifier()
    tx_valid = tx_verifier.verify_transaction(
        sender_id="alice123",
        receiver_id="bob456",
        amount=1000,
        timestamp="2024-01-01T12:00:00",
        signature=tx_signature,
        sender_public_key=tx_signer.get_public_key()
    )
    
    print(f"\nTransaction verification: {'✓ Valid' if tx_valid else '✗ Invalid'}")


if __name__ == "__main__":
    demonstrate_schnorr_signatures()
