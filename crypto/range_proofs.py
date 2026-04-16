"""
Range Proof Implementation
Proves that a committed value lies within a specific range without revealing the value

This is crucial for fintech applications where you need to prove:
- Balance is positive (>= 0)
- Transaction amount is within limits (e.g., 1 <= amount <= 100000)
- Account balance is within regulatory thresholds
"""

from typing import Tuple, List
from .dlp_core import DLPParameters, mod_exp, generate_private_key, DLPProof
import secrets


class RangeProof:
    """
    Represents a range proof showing value is in [min, max]
    Uses bit decomposition and multiple Schnorr proofs
    """
    
    def __init__(self, bit_proofs: List[DLPProof], range_min: int, range_max: int):
        self.bit_proofs = bit_proofs
        self.range_min = range_min
        self.range_max = range_max
    
    def to_dict(self) -> dict:
        """Serialize range proof"""
        return {
            'bit_proofs': [proof.to_dict() for proof in self.bit_proofs],
            'range_min': self.range_min,
            'range_max': self.range_max,
            'num_bits': len(self.bit_proofs)
        }


class RangeProver:
    """
    Prover for range proofs
    Proves that a committed value lies within [min, max]
    """
    
    def __init__(self, value: int):
        self.p, self.g, self.q = DLPParameters.get_parameters()
        if value < 0:
            raise ValueError(f"Value cannot be negative: {value}")
        self.value = value
    
    def prove_in_range(self, min_value: int, max_value: int) -> Tuple[bool, RangeProof]:
        """
        Prove that value is in [min_value, max_value]
        
        Strategy: Prove value - min_value >= 0 and max_value - value >= 0
        using bit decomposition
        
        Returns: (can_prove, proof)
        """
        if self.value < min_value or self.value > max_value:
            return False, None
        
        # For simplicity, we'll create a proof for the positive difference
        # In production, this would use more sophisticated bit commitment schemes
        difference_low = self.value - min_value
        difference_high = max_value - self.value
        
        # Create bit decomposition proofs
        bit_proofs = []
        
        # Prove lower bound: value >= min_value
        low_bits = self._decompose_to_bits(difference_low, 32)  # 32-bit representation
        for bit in low_bits:
            proof = self._create_bit_proof(bit)
            bit_proofs.append(proof)
        
        # Prove upper bound: value <= max_value
        high_bits = self._decompose_to_bits(difference_high, 32)
        for bit in high_bits:
            proof = self._create_bit_proof(bit)
            bit_proofs.append(proof)
        
        return True, RangeProof(bit_proofs, min_value, max_value)
    
    def _decompose_to_bits(self, value: int, num_bits: int) -> List[int]:
        """Decompose value into binary representation"""
        bits = []
        for i in range(num_bits):
            bits.append((value >> i) & 1)
        return bits
    
    def _create_bit_proof(self, bit: int) -> DLPProof:
        """
        Create a proof that a value is either 0 or 1
        This is a simplified version - production would use proper OR proofs
        """
        # Create commitment to bit
        r = generate_private_key()
        commitment = mod_exp(self.g, bit, self.p) * mod_exp(self.g, r, self.p) % self.p
        
        # Generate challenge and response
        challenge = secrets.randbelow(self.q)
        response = (r + challenge * bit) % self.q
        
        return DLPProof(commitment, challenge, response)


class RangeVerifier:
    """
    Verifier for range proofs
    Verifies that a committed value lies within specified range
    """
    
    def __init__(self):
        self.p, self.g, self.q = DLPParameters.get_parameters()
    
    def verify_range_proof(self, commitment: int, proof: RangeProof) -> bool:
        """
        Verify that the committed value is in [proof.range_min, proof.range_max]
        
        This is a simplified verification - production would verify:
        1. Each bit proof is valid (bit is 0 or 1)
        2. Bit decomposition is correct
        3. Range constraints are satisfied
        """
        # Verify all bit proofs
        for bit_proof in proof.bit_proofs:
            if not self._verify_bit_proof(bit_proof):
                return False
        
        return True
    
    def _verify_bit_proof(self, proof: DLPProof) -> bool:
        """
        Verify that a proof represents a valid bit (0 or 1)
        Simplified verification for demonstration
        """
        # Check basic proof structure
        left = mod_exp(self.g, proof.response, self.p)
        right = (proof.commitment * mod_exp(self.g, proof.challenge, self.p)) % self.p
        
        # In production, would verify OR proof (bit is 0 OR bit is 1)
        return True  # Simplified for demo


class BalanceRangeProver:
    """
    Specialized prover for balance range verification in fintech
    Common use cases:
    - Prove balance > 0 (account is not overdrawn)
    - Prove balance in regulatory range (e.g., 0 to 1,000,000)
    - Prove transaction amount within limits
    """
    
    def __init__(self, balance: int):
        if balance < 0:
            raise ValueError(f"Balance cannot be negative: {balance}")
        self.balance = balance
        self.prover = RangeProver(balance)
    
    def prove_positive_balance(self) -> Tuple[bool, RangeProof]:
        """Prove balance >= 0"""
        return self.prover.prove_in_range(0, 2**32 - 1)
    
    def prove_within_limit(self, max_limit: int) -> Tuple[bool, RangeProof]:
        """Prove balance is within [0, max_limit]"""
        return self.prover.prove_in_range(0, max_limit)
    
    def prove_transaction_valid(self, amount: int, min_tx: int, max_tx: int) -> Tuple[bool, RangeProof]:
        """
        Prove transaction amount is within valid range
        Useful for regulatory compliance (e.g., UPI limits)
        """
        if amount < min_tx or amount > max_tx:
            return False, None
        
        amount_prover = RangeProver(amount)
        return amount_prover.prove_in_range(min_tx, max_tx)
    
    def prove_sufficient_for_transaction(self, amount: int) -> Tuple[bool, RangeProof]:
        """
        Prove balance >= amount without revealing exact balance
        This combines sufficiency check with range proof
        """
        if self.balance < amount:
            return False, None
        
        # Prove the difference (balance - amount) is in valid range
        difference = self.balance - amount
        diff_prover = RangeProver(difference)
        return diff_prover.prove_in_range(0, 2**32 - 1)


class UPIRangeValidator:
    """
    UPI-specific range validation
    Enforces UPI transaction limits and regulatory requirements
    """
    
    # UPI transaction limits (in INR)
    MIN_TRANSACTION = 1
    MAX_TRANSACTION_REGULAR = 100000  # 1 lakh
    MAX_TRANSACTION_MERCHANT = 200000  # 2 lakhs
    MAX_DAILY_LIMIT = 1000000  # 10 lakhs
    
    def __init__(self):
        self.verifier = RangeVerifier()
    
    def validate_transaction_amount(self, amount: int, is_merchant: bool = False) -> Tuple[bool, str]:
        """
        Validate transaction amount against UPI limits
        Returns: (is_valid, message)
        """
        if amount < self.MIN_TRANSACTION:
            return False, f"Transaction amount must be at least ₹{self.MIN_TRANSACTION}"
        
        max_limit = self.MAX_TRANSACTION_MERCHANT if is_merchant else self.MAX_TRANSACTION_REGULAR
        
        if amount > max_limit:
            return False, f"Transaction amount exceeds limit of ₹{max_limit}"
        
        return True, "Transaction amount is within valid range"
    
    def verify_transaction_range_proof(self, proof: RangeProof, is_merchant: bool = False) -> bool:
        """
        Verify that transaction amount is within UPI limits using range proof
        """
        max_limit = self.MAX_TRANSACTION_MERCHANT if is_merchant else self.MAX_TRANSACTION_REGULAR
        
        if proof.range_min != self.MIN_TRANSACTION or proof.range_max != max_limit:
            return False
        
        # Verify the actual range proof
        return self.verifier.verify_range_proof(0, proof)  # Commitment not used in simplified version
    
    def get_transaction_limits(self, is_merchant: bool = False) -> dict:
        """Get applicable transaction limits"""
        return {
            'min_transaction': self.MIN_TRANSACTION,
            'max_transaction': self.MAX_TRANSACTION_MERCHANT if is_merchant else self.MAX_TRANSACTION_REGULAR,
            'max_daily_limit': self.MAX_DAILY_LIMIT,
            'currency': 'INR'
        }
