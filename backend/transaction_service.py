"""
Transaction Service for Privacy-Preserving UPI Payments
Handles transaction verification using Zero-Knowledge Proofs
"""

import uuid
from datetime import datetime
from typing import Dict, List, Optional
from crypto import BalanceProver, BalanceVerifier, ChunkedBalanceProof


class User:
    """Represents a user in the payment system"""
    
    def __init__(self, user_id: str, name: str, balance: int):
        if balance < 0:
            raise ValueError(f"Initial balance cannot be negative: {balance}")
        self.user_id = user_id
        self.name = name
        self.balance = balance
        self.prover = BalanceProver(balance)
        self.balance_commitment = self.prover.get_balance_commitment()
    
    def update_balance(self, amount: int):
        """Update user balance (for completed transactions)"""
        new_balance = self.balance + amount
        if new_balance < 0:
            raise ValueError(f"Balance cannot go negative: {new_balance}")
        self.balance = new_balance
        self.prover = BalanceProver(self.balance)
        self.balance_commitment = self.prover.get_balance_commitment()
    
    def to_dict(self) -> dict:
        """Convert to dictionary (includes balance for demo)"""
        return {
            'user_id': self.user_id,
            'name': self.name,
            'balance': self.balance,
            'balance_commitment': hex(self.balance_commitment)
        }


class Transaction:
    """Represents a payment transaction"""
    
    def __init__(self, sender_id: str, receiver_id: str, amount: int):
        self.transaction_id = str(uuid.uuid4())
        self.sender_id = sender_id
        self.receiver_id = receiver_id
        self.amount = amount
        self.status = 'pending'
        self.timestamp = datetime.now().isoformat()
        self.proof = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            'transaction_id': self.transaction_id,
            'sender_id': self.sender_id,
            'receiver_id': self.receiver_id,
            'amount': self.amount,
            'status': self.status,
            'timestamp': self.timestamp,
            'proof_included': self.proof is not None
        }


class TransactionService:
    """
    Core service for handling privacy-preserving transactions
    Uses ZK proofs to verify balance without revealing amounts
    """
    
    def __init__(self):
        self.users: Dict[str, User] = {}
        self.transactions: Dict[str, Transaction] = {}
        self.verifier = BalanceVerifier()
    
    def create_user(self, name: str, initial_balance: int) -> User:
        """Create a new user with initial balance"""
        user_id = str(uuid.uuid4())
        user = User(user_id, name, initial_balance)
        self.users[user_id] = user
        return user
    
    def get_user(self, user_id: str) -> Optional[User]:
        """Get user by ID"""
        return self.users.get(user_id)
    
    def initiate_transaction(self, sender_id: str, receiver_id: str, amount: int) -> Dict:
        """
        Initiate a transaction with ZK proof verification
        
        Returns transaction details with verification status
        """
        # Validate users exist
        sender = self.users.get(sender_id)
        receiver = self.users.get(receiver_id)
        
        if not sender or not receiver:
            return {
                'success': False,
                'error': 'Invalid sender or receiver'
            }
        
        if amount <= 0:
            return {
                'success': False,
                'error': 'Invalid amount'
            }
        
        # Create transaction
        transaction = Transaction(sender_id, receiver_id, amount)
        
        # Generate ZK proof of sufficient balance
        can_prove, proof = sender.prover.prove_sufficient_balance(amount)
        
        if not can_prove:
            transaction.status = 'failed'
            self.transactions[transaction.transaction_id] = transaction
            return {
                'success': False,
                'error': 'Insufficient balance',
                'transaction': transaction.to_dict()
            }
        
        # Verify the proof
        proof_valid = self.verifier.verify_balance_proof(
            sender.balance_commitment,
            proof,
            chunk_commitments=sender.prover.get_chunk_commitments()
        )
        
        if not proof_valid:
            transaction.status = 'failed'
            self.transactions[transaction.transaction_id] = transaction
            return {
                'success': False,
                'error': 'Invalid proof',
                'transaction': transaction.to_dict()
            }
        
        # Execute transaction
        sender.update_balance(-amount)
        receiver.update_balance(amount)
        
        transaction.status = 'completed'
        transaction.proof = proof
        self.transactions[transaction.transaction_id] = transaction
        
        return {
            'success': True,
            'message': 'Transaction completed successfully',
            'transaction': transaction.to_dict(),
            'proof': proof.to_dict()
        }
    
    def get_transaction(self, transaction_id: str) -> Optional[Dict]:
        """Get transaction details"""
        transaction = self.transactions.get(transaction_id)
        if transaction:
            return transaction.to_dict()
        return None
    
    def get_user_transactions(self, user_id: str) -> List[Dict]:
        """Get all transactions for a user"""
        user_transactions = []
        for transaction in self.transactions.values():
            if transaction.sender_id == user_id or transaction.receiver_id == user_id:
                user_transactions.append(transaction.to_dict())
        return user_transactions
    
    def get_user_balance_info(self, user_id: str) -> Optional[Dict]:
        """
        Get user balance information
        Returns commitment (public) but not actual balance (private)
        """
        user = self.users.get(user_id)
        if not user:
            return None
        
        return {
            'user_id': user.user_id,
            'name': user.name,
            'balance_commitment': hex(user.balance_commitment),
            'note': 'Actual balance is private. Commitment can be used for ZK proofs.'
        }
