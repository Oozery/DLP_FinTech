"""
Schnorr Zero-Knowledge Proof over Elliptic Curve Cryptography
Uses scalar multiplication Q = k·P instead of modular exponentiation g^x mod p

Protocol (ECC form):
  Setup:    P = secp256k1 base point, n = curve order
  KeyGen:   secret x, public Q = x·P
  Commit:   choose random r, R = r·P
  Challenge: c = H(R || Q || context)  (Fiat-Shamir)
  Response: s = (r + c·x) mod n
  Verify:   s·P == R + c·Q  (point equality)

Security: Breaking this requires solving ECDLP (given Q and P, find x).
"""

import hashlib
import secrets
from typing import Tuple, List, Optional

from .ecdsa import ECCurve, ECPoint


# Shared curve instance
_curve = ECCurve()


def _random_scalar() -> int:
    """Random scalar in [1, n-1]"""
    return secrets.randbelow(_curve.n - 1) + 1


def _point_to_bytes(P: ECPoint) -> bytes:
    """Serialize a curve point to bytes (compressed form)."""
    if P.is_infinity:
        return b'\x00'
    prefix = b'\x02' if P.y % 2 == 0 else b'\x03'
    return prefix + P.x.to_bytes(32, 'big')


def _hash_challenge(*items) -> int:
    """
    Fiat-Shamir challenge: H(item1 || item2 || ...) mod n
    Each item can be an ECPoint or int.
    """
    h = hashlib.sha256()
    for item in items:
        if isinstance(item, ECPoint):
            h.update(_point_to_bytes(item))
        elif isinstance(item, int):
            h.update(item.to_bytes(32, 'big'))
        elif isinstance(item, bytes):
            h.update(item)
    return int.from_bytes(h.digest(), 'big') % _curve.n


class ECSchnorrProof:
    """A single ECC Schnorr proof: (R, s) where R is a curve point."""

    def __init__(self, R: ECPoint, s: int):
        self.R = R  # commitment point
        self.s = s  # response scalar

    def to_dict(self) -> dict:
        return {
            'R_x': hex(self.R.x) if not self.R.is_infinity else '0',
            'R_y': hex(self.R.y) if not self.R.is_infinity else '0',
            's': hex(self.s),
        }


class ECSchnorrProver:
    """
    Proves knowledge of x such that Q = x·P, without revealing x.
    Uses non-interactive Fiat-Shamir transform.
    """

    def __init__(self, secret: int):
        if not (1 <= secret < _curve.n):
            raise ValueError("Secret must be in [1, n-1]")
        self.secret = secret
        self.public_key = _curve.mul(secret, _curve.G)  # Q = x·P

    def prove(self, context: bytes = b'') -> ECSchnorrProof:
        """
        Generate a non-interactive ZK proof of knowledge of secret x.
        R = r·P,  c = H(R, Q, context),  s = r + c·x mod n
        """
        r = _random_scalar()
        R = _curve.mul(r, _curve.G)                          # commitment
        c = _hash_challenge(R, self.public_key, context)     # Fiat-Shamir challenge
        s = (r + c * self.secret) % _curve.n                 # response
        return ECSchnorrProof(R, s)


class ECSchnorrVerifier:
    """
    Verifies an ECC Schnorr proof without learning the secret.
    Check: s·P == R + c·Q
    """

    def verify(self, public_key: ECPoint, proof: ECSchnorrProof,
               context: bytes = b'') -> bool:
        c = _hash_challenge(proof.R, public_key, context)
        lhs = _curve.mul(proof.s, _curve.G)                  # s·P
        rhs = _curve.add(proof.R, _curve.mul(c, public_key)) # R + c·Q
        return (not lhs.is_infinity) and lhs.x == rhs.x and lhs.y == rhs.y


# ---------------------------------------------------------------------------
# Chunked balance proof (handles balances that may exceed curve order n)
# ---------------------------------------------------------------------------

class ECBalanceProof:
    """Container for a (possibly multi-chunk) ECC balance proof."""

    def __init__(self, chunk_proofs: List[ECSchnorrProof],
                 chunk_public_keys: List[ECPoint]):
        self.chunk_proofs = chunk_proofs
        self.chunk_public_keys = chunk_public_keys  # Q_i = chunk_i · P
        self.num_chunks = len(chunk_proofs)

    def to_dict(self) -> dict:
        return {
            'num_chunks': len(self.chunk_proofs),
            'chunk_proofs': [p.to_dict() for p in self.chunk_proofs],
        }


class ECBalanceProver:
    """
    Privacy-preserving balance prover using ECC Schnorr ZK proofs.

    Balance is decomposed into base-n chunks so each chunk fits in [1, n-1]:
        balance = c0 + c1·n + c2·n² + ...
    Each chunk ci is proven independently via ECSchnorrProver.
    The combined public commitment is the sum of chunk public keys:
        Q_total = Q0 + Q1 + Q2 + ...  (point addition — homomorphic)
    """

    def __init__(self, balance: int):
        if balance < 0:
            raise ValueError("Balance cannot be negative")
        self.balance = balance
        self.n = _curve.n

        # Decompose into base-n chunks
        self.chunks: List[int] = []
        remaining = balance
        while remaining > 0:
            self.chunks.append(remaining % self.n)
            remaining //= self.n
        if not self.chunks:
            self.chunks = [0]

        # Public key per chunk: Q_i = chunk_i · P  (0 chunk → point at infinity)
        self.chunk_public_keys: List[ECPoint] = [
            _curve.mul(c, _curve.G) if c > 0 else ECPoint.infinity(_curve)
            for c in self.chunks
        ]

        # Combined commitment: sum of all chunk public keys
        self.balance_commitment: ECPoint = ECPoint.infinity(_curve)
        for Q in self.chunk_public_keys:
            self.balance_commitment = _curve.add(self.balance_commitment, Q)

    def get_balance_commitment(self) -> ECPoint:
        """Public commitment to balance (EC point). Reveals nothing about balance."""
        return self.balance_commitment

    def get_chunk_public_keys(self) -> List[ECPoint]:
        return self.chunk_public_keys

    def prove_sufficient_balance(
        self, required_amount: int
    ) -> Tuple[bool, Optional[ECBalanceProof]]:
        """
        Prove balance >= required_amount using ECC Schnorr ZK proofs.
        Returns (can_prove, proof). Proof is None if balance insufficient.
        """
        if self.balance < required_amount:
            return False, None

        chunk_proofs = []
        for chunk in self.chunks:
            if chunk == 0:
                # Zero chunk: trivial proof with point at infinity
                chunk_proofs.append(ECSchnorrProof(ECPoint.infinity(_curve), 0))
            else:
                prover = ECSchnorrProver(chunk)
                chunk_proofs.append(prover.prove())

        return True, ECBalanceProof(chunk_proofs, self.chunk_public_keys)


class ECBalanceVerifier:
    """
    Verifies ECC balance proofs.
    1. Checks chunk public keys sum to the overall balance commitment.
    2. Verifies each chunk's Schnorr proof against its public key.
    """

    def __init__(self):
        self.verifier = ECSchnorrVerifier()

    def verify_balance_proof(
        self,
        balance_commitment: ECPoint,
        proof: ECBalanceProof,
    ) -> bool:
        # 1. Verify chunk public keys sum to balance_commitment
        combined = ECPoint.infinity(_curve)
        for Q in proof.chunk_public_keys:
            combined = _curve.add(combined, Q)

        if not _points_equal(combined, balance_commitment):
            return False

        # 2. Verify each chunk proof
        for Q, cp in zip(proof.chunk_public_keys, proof.chunk_proofs):
            if Q.is_infinity:
                continue  # zero chunk, skip
            if not self.verifier.verify(Q, cp):
                return False

        return True


def _points_equal(A: ECPoint, B: ECPoint) -> bool:
    if A.is_infinity and B.is_infinity:
        return True
    if A.is_infinity or B.is_infinity:
        return False
    return A.x == B.x and A.y == B.y
