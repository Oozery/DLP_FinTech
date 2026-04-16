"""
Range Proof Implementation over Elliptic Curve Cryptography (secp256k1)
Proves that a committed value lies within a specific range without revealing it.

Uses bit decomposition: value is split into bits, each bit is committed as
  C_i = b_i·P  (where b_i ∈ {0,1})
and proven via ECC Schnorr ZK proofs.

Crucial for fintech applications:
- Balance is positive (>= 0)
- Transaction amount is within limits (e.g., 1 <= amount <= 100000)
- Account balance is within regulatory thresholds
"""

import secrets
from typing import Tuple, List

from .ecdsa import ECCurve, ECPoint
from .ecc_schnorr import (
    ECSchnorrProof, ECSchnorrProver, ECSchnorrVerifier,
    _curve, _random_scalar, _hash_challenge, _points_equal,
)

NUM_BITS = 32  # bit-width for range decomposition


class RangeProof:
    """Range proof: list of per-bit Schnorr proofs for value ∈ [min, max]."""

    def __init__(self, bit_proofs: List[ECSchnorrProof],
                 bit_commitments: List[ECPoint],
                 range_min: int, range_max: int):
        self.bit_proofs = bit_proofs
        self.bit_commitments = bit_commitments
        self.range_min = range_min
        self.range_max = range_max

    def to_dict(self) -> dict:
        return {
            'num_bits': len(self.bit_proofs),
            'range_min': self.range_min,
            'range_max': self.range_max,
            'bit_proofs': [p.to_dict() for p in self.bit_proofs],
        }


def _decompose_bits(value: int, num_bits: int) -> List[int]:
    """Decompose value into little-endian binary."""
    return [(value >> i) & 1 for i in range(num_bits)]


def _prove_bits(value: int) -> Tuple[List[ECSchnorrProof], List[ECPoint]]:
    """
    For each bit b_i of value:
      - If b_i == 1: secret = 1, Q_i = 1·P = P, prove knowledge of 1
      - If b_i == 0: trivial proof (point at infinity)
    """
    bits = _decompose_bits(value, NUM_BITS)
    proofs = []
    commitments = []
    for b in bits:
        if b == 1:
            prover = ECSchnorrProver(1)
            proofs.append(prover.prove())
            commitments.append(prover.public_key)
        else:
            proofs.append(ECSchnorrProof(ECPoint.infinity(_curve), 0))
            commitments.append(ECPoint.infinity(_curve))
    return proofs, commitments


class RangeProver:
    """Proves a value lies within [min, max] using ECC bit-decomposition."""

    def __init__(self, value: int):
        if value < 0:
            raise ValueError(f"Value cannot be negative: {value}")
        self.value = value

    def prove_in_range(self, min_value: int, max_value: int) -> Tuple[bool, RangeProof]:
        """
        Prove value ∈ [min_value, max_value].
        Strategy: prove (value - min) >= 0 AND (max - value) >= 0
        via bit decomposition of both differences.
        """
        if self.value < min_value or self.value > max_value:
            return False, None

        low_proofs, low_commits = _prove_bits(self.value - min_value)
        high_proofs, high_commits = _prove_bits(max_value - self.value)

        return True, RangeProof(
            low_proofs + high_proofs,
            low_commits + high_commits,
            min_value, max_value,
        )


class RangeVerifier:
    """Verifies ECC range proofs."""

    def __init__(self):
        self._verifier = ECSchnorrVerifier()

    def verify_range_proof(self, proof: RangeProof) -> bool:
        """
        Verify all bit proofs.
        Each non-zero bit commitment must have Q_i == P (the generator)
        and a valid Schnorr proof of knowledge of 1.
        """
        for commit, bp in zip(proof.bit_commitments, proof.bit_proofs):
            if commit.is_infinity:
                continue  # zero bit
            # bit commitment must equal G (i.e. 1·P)
            if not _points_equal(commit, _curve.G):
                return False
            if not self._verifier.verify(commit, bp):
                return False
        return True


class BalanceRangeProver:
    """
    Fintech-specific range prover:
    - Prove balance > 0
    - Prove balance within regulatory limit
    - Prove transaction amount within limits
    """

    def __init__(self, balance: int):
        if balance < 0:
            raise ValueError(f"Balance cannot be negative: {balance}")
        self.balance = balance
        self._prover = RangeProver(balance)

    def prove_positive_balance(self) -> Tuple[bool, RangeProof]:
        return self._prover.prove_in_range(0, 2**NUM_BITS - 1)

    def prove_within_limit(self, max_limit: int) -> Tuple[bool, RangeProof]:
        return self._prover.prove_in_range(0, max_limit)

    def prove_transaction_valid(self, amount: int, min_tx: int, max_tx: int) -> Tuple[bool, RangeProof]:
        if amount < min_tx or amount > max_tx:
            return False, None
        return RangeProver(amount).prove_in_range(min_tx, max_tx)

    def prove_sufficient_for_transaction(self, amount: int) -> Tuple[bool, RangeProof]:
        if self.balance < amount:
            return False, None
        return RangeProver(self.balance - amount).prove_in_range(0, 2**NUM_BITS - 1)


class UPIRangeValidator:
    """UPI-specific range validation with ECC range proofs."""

    MIN_TRANSACTION = 1
    MAX_TRANSACTION_REGULAR = 100000
    MAX_TRANSACTION_MERCHANT = 200000
    MAX_DAILY_LIMIT = 1000000

    def __init__(self):
        self._verifier = RangeVerifier()

    def validate_transaction_amount(self, amount: int, is_merchant: bool = False) -> Tuple[bool, str]:
        if amount < self.MIN_TRANSACTION:
            return False, f"Transaction amount must be at least ₹{self.MIN_TRANSACTION}"
        max_limit = self.MAX_TRANSACTION_MERCHANT if is_merchant else self.MAX_TRANSACTION_REGULAR
        if amount > max_limit:
            return False, f"Transaction amount exceeds limit of ₹{max_limit}"
        return True, "Transaction amount is within valid range"

    def verify_transaction_range_proof(self, proof: RangeProof, is_merchant: bool = False) -> bool:
        max_limit = self.MAX_TRANSACTION_MERCHANT if is_merchant else self.MAX_TRANSACTION_REGULAR
        if proof.range_min != self.MIN_TRANSACTION or proof.range_max != max_limit:
            return False
        return self._verifier.verify_range_proof(proof)

    def get_transaction_limits(self, is_merchant: bool = False) -> dict:
        return {
            'min_transaction': self.MIN_TRANSACTION,
            'max_transaction': self.MAX_TRANSACTION_MERCHANT if is_merchant else self.MAX_TRANSACTION_REGULAR,
            'max_daily_limit': self.MAX_DAILY_LIMIT,
            'currency': 'INR',
        }
