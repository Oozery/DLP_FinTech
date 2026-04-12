"""
Unit tests for DLP core functionality
"""

import unittest
from crypto.dlp_core import (
    DLPParameters,
    mod_exp,
    generate_keypair,
    generate_private_key,
    compute_public_key,
    create_commitment
)


class TestDLPCore(unittest.TestCase):
    """Test DLP cryptographic primitives"""
    
    def test_parameters(self):
        """Test DLP parameters are valid"""
        p, g, q = DLPParameters.get_parameters()
        
        # Check p is odd (prime)
        self.assertEqual(p % 2, 1)
        
        # Check q = (p-1)/2
        self.assertEqual(q, (p - 1) // 2)
        
        # Check generator is valid
        self.assertGreater(g, 1)
        self.assertLess(g, p)
    
    def test_modular_exponentiation(self):
        """Test modular exponentiation"""
        result = mod_exp(2, 10, 1000)
        self.assertEqual(result, 24)  # 2^10 mod 1000 = 1024 mod 1000 = 24
    
    def test_keypair_generation(self):
        """Test keypair generation"""
        private_key, public_key = generate_keypair()
        p, g, _ = DLPParameters.get_parameters()
        
        # Verify public key is computed correctly
        expected_public = mod_exp(g, private_key, p)
        self.assertEqual(public_key, expected_public)
    
    def test_private_key_range(self):
        """Test private key is in valid range"""
        _, _, q = DLPParameters.get_parameters()
        
        for _ in range(10):
            private_key = generate_private_key()
            self.assertGreater(private_key, 0)
            self.assertLess(private_key, q)
    
    def test_commitment_creation(self):
        """Test commitment creation"""
        p, _, _ = DLPParameters.get_parameters()
        
        value = 1000
        randomness = 12345
        
        commitment = create_commitment(value, randomness)
        
        # Commitment should be in valid range
        self.assertGreater(commitment, 0)
        self.assertLess(commitment, p)
    
    def test_commitment_hiding(self):
        """Test that same value with different randomness gives different commitments"""
        value = 1000
        randomness1 = 12345
        randomness2 = 67890
        
        commitment1 = create_commitment(value, randomness1)
        commitment2 = create_commitment(value, randomness2)
        
        # Different randomness should give different commitments
        self.assertNotEqual(commitment1, commitment2)


if __name__ == '__main__':
    unittest.main()
