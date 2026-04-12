"""
Unit tests for Schnorr protocol implementation
"""

import unittest
from crypto.schnorr_protocol import (
    SchnorrProver,
    SchnorrVerifier,
    BalanceProver,
    BalanceVerifier
)
from crypto.dlp_core import generate_private_key


class TestSchnorrProtocol(unittest.TestCase):
    """Test Schnorr ZK proof protocol"""
    
    def test_schnorr_proof_valid(self):
        """Test that valid Schnorr proof verifies correctly"""
        # Setup
        secret = generate_private_key()
        prover = SchnorrProver(secret)
        verifier = SchnorrVerifier()
        
        # Protocol execution
        commitment = prover.create_commitment()
        challenge = verifier.generate_challenge()
        proof = prover.create_proof(challenge)
        
        # Verification
        is_valid = verifier.verify_proof(prover.public_value, proof)
        self.assertTrue(is_valid)
    
    def test_schnorr_proof_invalid_secret(self):
        """Test that proof with wrong secret fails"""
        # Setup with correct secret
        correct_secret = generate_private_key()
        prover = SchnorrProver(correct_secret)
        verifier = SchnorrVerifier()
        
        # Create proof
        commitment = prover.create_commitment()
        challenge = verifier.generate_challenge()
        proof = prover.create_proof(challenge)
        
        # Try to verify with different public value (wrong secret)
        wrong_secret = generate_private_key()
        wrong_prover = SchnorrProver(wrong_secret)
        
        is_valid = verifier.verify_proof(wrong_prover.public_value, proof)
        self.assertFalse(is_valid)
    
    def test_balance_proof_sufficient(self):
        """Test balance proof with sufficient balance"""
        balance = 10000
        required = 5000
        
        prover = BalanceProver(balance)
        can_prove, proof = prover.prove_sufficient_balance(required)
        
        self.assertTrue(can_prove)
        self.assertIsNotNone(proof)
    
    def test_balance_proof_insufficient(self):
        """Test balance proof with insufficient balance"""
        balance = 3000
        required = 5000
        
        prover = BalanceProver(balance)
        can_prove, proof = prover.prove_sufficient_balance(required)
        
        self.assertFalse(can_prove)
        self.assertIsNone(proof)
    
    def test_balance_verification(self):
        """Test balance proof verification"""
        balance = 10000
        required = 5000
        
        prover = BalanceProver(balance)
        verifier = BalanceVerifier()
        
        can_prove, proof = prover.prove_sufficient_balance(required)
        self.assertTrue(can_prove)
        
        # Verify the proof
        is_valid = verifier.verify_balance_proof(
            prover.get_balance_commitment(),
            proof
        )
        self.assertTrue(is_valid)
    
    def test_multiple_proofs(self):
        """Test that multiple proofs from same prover all verify"""
        secret = generate_private_key()
        prover = SchnorrProver(secret)
        verifier = SchnorrVerifier()
        
        # Create and verify multiple proofs
        for _ in range(5):
            commitment = prover.create_commitment()
            challenge = verifier.generate_challenge()
            proof = prover.create_proof(challenge)
            
            is_valid = verifier.verify_proof(prover.public_value, proof)
            self.assertTrue(is_valid)


if __name__ == '__main__':
    unittest.main()
