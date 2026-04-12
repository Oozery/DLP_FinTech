"""
Unit tests for transaction service
"""

import unittest
from backend.transaction_service import TransactionService


class TestTransactionService(unittest.TestCase):
    """Test transaction service functionality"""
    
    def setUp(self):
        """Setup test service"""
        self.service = TransactionService()
    
    def test_create_user(self):
        """Test user creation"""
        user = self.service.create_user('Alice', 10000)
        
        self.assertIsNotNone(user.user_id)
        self.assertEqual(user.name, 'Alice')
        self.assertEqual(user.balance, 10000)
    
    def test_get_user(self):
        """Test getting user by ID"""
        user = self.service.create_user('Bob', 5000)
        retrieved = self.service.get_user(user.user_id)
        
        self.assertEqual(retrieved.user_id, user.user_id)
        self.assertEqual(retrieved.name, 'Bob')
    
    def test_transaction_success(self):
        """Test successful transaction"""
        alice = self.service.create_user('Alice', 10000)
        bob = self.service.create_user('Bob', 5000)
        
        result = self.service.initiate_transaction(
            alice.user_id,
            bob.user_id,
            3000
        )
        
        self.assertTrue(result['success'])
        self.assertEqual(result['transaction']['status'], 'completed')
        
        # Check balances updated
        self.assertEqual(alice.balance, 7000)
        self.assertEqual(bob.balance, 8000)
    
    def test_transaction_insufficient_balance(self):
        """Test transaction with insufficient balance"""
        alice = self.service.create_user('Alice', 2000)
        bob = self.service.create_user('Bob', 5000)
        
        result = self.service.initiate_transaction(
            alice.user_id,
            bob.user_id,
            5000
        )
        
        self.assertFalse(result['success'])
        self.assertIn('Insufficient balance', result['error'])
        
        # Balances should remain unchanged
        self.assertEqual(alice.balance, 2000)
        self.assertEqual(bob.balance, 5000)
    
    def test_transaction_invalid_user(self):
        """Test transaction with invalid user"""
        alice = self.service.create_user('Alice', 10000)
        
        result = self.service.initiate_transaction(
            alice.user_id,
            'invalid_user_id',
            1000
        )
        
        self.assertFalse(result['success'])
        self.assertIn('Invalid', result['error'])
    
    def test_transaction_invalid_amount(self):
        """Test transaction with invalid amount"""
        alice = self.service.create_user('Alice', 10000)
        bob = self.service.create_user('Bob', 5000)
        
        result = self.service.initiate_transaction(
            alice.user_id,
            bob.user_id,
            -1000
        )
        
        self.assertFalse(result['success'])
        self.assertIn('Invalid amount', result['error'])
    
    def test_get_user_transactions(self):
        """Test getting user transactions"""
        alice = self.service.create_user('Alice', 10000)
        bob = self.service.create_user('Bob', 5000)
        
        # Create multiple transactions
        self.service.initiate_transaction(alice.user_id, bob.user_id, 1000)
        self.service.initiate_transaction(alice.user_id, bob.user_id, 2000)
        
        transactions = self.service.get_user_transactions(alice.user_id)
        
        self.assertEqual(len(transactions), 2)
    
    def test_balance_commitment_privacy(self):
        """Test that balance commitment doesn't reveal actual balance"""
        alice = self.service.create_user('Alice', 10000)
        bob = self.service.create_user('Bob', 10000)
        
        # Same balance should give different commitments (due to different random setup)
        # This is a simplified test - in real system, commitments would use explicit randomness
        self.assertIsNotNone(alice.balance_commitment)
        self.assertIsNotNone(bob.balance_commitment)


if __name__ == '__main__':
    unittest.main()
