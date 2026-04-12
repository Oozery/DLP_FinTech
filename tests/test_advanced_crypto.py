"""
Unit tests for advanced cryptographic features
Tests batch verification, DH key exchange, ElGamal, and signatures
"""

import unittest
from crypto.batch_verification import BatchVerifier, TransactionBatchVerifier
from crypto.diffie_hellman import DiffieHellmanParty, SecureChannel, UPISecureSession
from crypto.elgamal_encryption import ElGamalKeypair, ElGamalEncryption, HomomorphicElGamal
from crypto.schnorr_signatures import SchnorrSigner, SchnorrVerifier, TransactionSigner, TransactionVerifier
from crypto.schnorr_protocol import SchnorrProver
from crypto.dlp_core import generate_private_key


class TestBatchVerification(unittest.TestCase):
    """Test batch verification of multiple proofs"""
    
    def test_batch_verify_valid_proofs(self):
        """Test batch verification with all valid proofs"""
        # Create multiple valid proofs
        num_proofs = 5
        public_values = []
        proofs = []
        
        for _ in range(num_proofs):
            secret = generate_private_key()
            prover = SchnorrProver(secret)
            commitment = prover.create_commitment()
            
            from crypto.schnorr_protocol import SchnorrVerifier
            verifier = SchnorrVerifier()
            challenge = verifier.generate_challenge()
            proof = prover.create_proof(challenge)
            
            public_values.append(prover.public_value)
            proofs.append(proof)
        
        # Batch verify
        batch_verifier = BatchVerifier()
        is_valid = batch_verifier.verify_batch(public_values, proofs)
        
        self.assertTrue(is_valid)
    
    def test_transaction_batch_verifier(self):
        """Test transaction-specific batch verification"""
        # Create transaction proofs
        from crypto.schnorr_protocol import BalanceProver
        
        balances = [10000, 5000, 15000]
        commitments = []
        proofs = []
        
        for balance in balances:
            prover = BalanceProver(balance)
            can_prove, proof = prover.prove_sufficient_balance(1000)
            
            self.assertTrue(can_prove)
            commitments.append(prover.get_balance_commitment())
            proofs.append(proof)
        
        # Batch verify transactions
        tx_verifier = TransactionBatchVerifier()
        all_valid, failed = tx_verifier.verify_transaction_batch(commitments, proofs)
        
        self.assertTrue(all_valid)
        self.assertEqual(len(failed), 0)


class TestDiffieHellman(unittest.TestCase):
    """Test Diffie-Hellman key exchange"""
    
    def test_key_exchange(self):
        """Test basic DH key exchange"""
        alice = DiffieHellmanParty("Alice")
        bob = DiffieHellmanParty("Bob")
        
        # Exchange public keys
        alice_secret = alice.compute_shared_secret(bob.get_public_key())
        bob_secret = bob.compute_shared_secret(alice.get_public_key())
        
        # Verify both computed same shared secret
        self.assertEqual(alice_secret, bob_secret)
    
    def test_session_keys_match(self):
        """Test that derived session keys match"""
        alice = DiffieHellmanParty("Alice")
        bob = DiffieHellmanParty("Bob")
        
        alice.compute_shared_secret(bob.get_public_key())
        bob.compute_shared_secret(alice.get_public_key())
        
        alice_key = alice.get_session_key()
        bob_key = bob.get_session_key()
        
        self.assertEqual(alice_key, bob_key)
    
    def test_secure_channel(self):
        """Test secure channel establishment"""
        channel = SecureChannel("User", "Gateway")
        user_key, gateway_key = channel.establish_channel()
        
        self.assertEqual(user_key, gateway_key)
        self.assertTrue(channel.is_secure())
    
    def test_upi_session(self):
        """Test UPI secure session"""
        session = UPISecureSession("user123", "gateway456")
        result = session.initiate_session()
        
        self.assertTrue(result['success'])
        self.assertTrue(result['channel_secure'])


class TestElGamalEncryption(unittest.TestCase):
    """Test ElGamal encryption scheme"""
    
    def test_encryption_decryption(self):
        """Test basic encryption and decryption"""
        keypair = ElGamalKeypair()
        elgamal = ElGamalEncryption()
        
        message = 12345
        public_key = keypair.get_public_key()
        private_key = keypair.get_private_key()
        
        # Encrypt
        ciphertext = elgamal.encrypt(message, public_key)
        
        # Decrypt
        decrypted = elgamal.decrypt(ciphertext, private_key)
        
        self.assertEqual(message, decrypted)
    
    def test_homomorphic_multiplication(self):
        """Test homomorphic property of ElGamal"""
        keypair = ElGamalKeypair()
        elgamal = ElGamalEncryption()
        public_key = keypair.get_public_key()
        private_key = keypair.get_private_key()
        
        m1 = 100
        m2 = 200
        
        ct1 = elgamal.encrypt(m1, public_key)
        ct2 = elgamal.encrypt(m2, public_key)
        
        # Multiply ciphertexts
        homomorphic = HomomorphicElGamal()
        ct_product = homomorphic.multiply_ciphertexts(ct1, ct2)
        
        # Decrypt product
        decrypted_product = elgamal.decrypt(ct_product, private_key)
        expected_product = (m1 * m2) % public_key[0]
        
        self.assertEqual(decrypted_product, expected_product)
    
    def test_different_messages_different_ciphertexts(self):
        """Test that different messages produce different ciphertexts"""
        keypair = ElGamalKeypair()
        elgamal = ElGamalEncryption()
        public_key = keypair.get_public_key()
        
        m1 = 100
        m2 = 200
        
        ct1 = elgamal.encrypt(m1, public_key)
        ct2 = elgamal.encrypt(m2, public_key)
        
        self.assertNotEqual(ct1.c1, ct2.c1)
        self.assertNotEqual(ct1.c2, ct2.c2)


class TestSchnorrSignatures(unittest.TestCase):
    """Test Schnorr digital signatures"""
    
    def test_sign_and_verify(self):
        """Test basic signature generation and verification"""
        signer = SchnorrSigner()
        verifier = SchnorrVerifier()
        
        message = b"Test message"
        signature = signer.sign(message)
        
        is_valid = verifier.verify(message, signature, signer.get_public_key())
        
        self.assertTrue(is_valid)
    
    def test_invalid_signature_rejected(self):
        """Test that invalid signatures are rejected"""
        signer = SchnorrSigner()
        verifier = SchnorrVerifier()
        
        message = b"Test message"
        wrong_message = b"Wrong message"
        
        signature = signer.sign(message)
        
        # Verify with wrong message should fail
        is_valid = verifier.verify(wrong_message, signature, signer.get_public_key())
        
        self.assertFalse(is_valid)
    
    def test_transaction_signing(self):
        """Test transaction signing and verification"""
        tx_signer = TransactionSigner("alice123")
        tx_verifier = TransactionVerifier()
        
        # Sign transaction
        signature = tx_signer.sign_transaction(
            sender_id="alice123",
            receiver_id="bob456",
            amount=1000,
            timestamp="2024-01-01T12:00:00"
        )
        
        # Verify transaction
        is_valid = tx_verifier.verify_transaction(
            sender_id="alice123",
            receiver_id="bob456",
            amount=1000,
            timestamp="2024-01-01T12:00:00",
            signature=signature,
            sender_public_key=tx_signer.get_public_key()
        )
        
        self.assertTrue(is_valid)
    
    def test_transaction_tampering_detected(self):
        """Test that transaction tampering is detected"""
        tx_signer = TransactionSigner("alice123")
        tx_verifier = TransactionVerifier()
        
        # Sign transaction
        signature = tx_signer.sign_transaction(
            sender_id="alice123",
            receiver_id="bob456",
            amount=1000,
            timestamp="2024-01-01T12:00:00"
        )
        
        # Try to verify with modified amount
        is_valid = tx_verifier.verify_transaction(
            sender_id="alice123",
            receiver_id="bob456",
            amount=2000,  # Modified!
            timestamp="2024-01-01T12:00:00",
            signature=signature,
            sender_public_key=tx_signer.get_public_key()
        )
        
        self.assertFalse(is_valid)


if __name__ == '__main__':
    unittest.main()
