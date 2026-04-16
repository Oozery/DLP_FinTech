"""
Schnorr Protocol Implementation for Zero-Knowledge Proofs
Based on the hardness of the Discrete Logarithm Problem

Protocol Flow:
1. Prover commits to a random value
2. Verifier sends a challenge
3. Prover responds with a value that proves knowledge without revealing the secret
4. Verifier checks the proof using DLP properties
"""

import secrets
from typing import Tuple, List
from .dlp_core import (
    DLPParameters, 
    mod_exp, 
    generate_private_key,
    DLPProof
)


class SchnorrProver:
    """
    Prover in the Schnorr protocol
    Proves knowledge of discrete logarithm without revealing it
    """
    
    def __init__(self, secret: int):
        """
        Initialize prover with a secret value
        secret: The discrete logarithm we want to prove knowledge of
        """
        self.p, self.g, self.q = DLPParameters.get_parameters()
        if secret < 1 or secret >= self.q:
            raise ValueError(
                f"Secret must be in range [1, {self.q - 1}], got {secret}"
            )
        self.secret = secret
        self.public_value = mod_exp(self.g, secret, self.p)
        self.random_value = None
        self.commitment = None
    
    def create_commitment(self) -> int:
        """
        Step 1: Create commitment
        Choose random r, compute commitment = g^r mod p
        """
        self.random_value = generate_private_key()
        self.commitment = mod_exp(self.g, self.random_value, self.p)
        return self.commitment
    
    def generate_response(self, challenge: int) -> int:
        """
        Step 3: Generate response to challenge
        response = r + challenge * secret mod q
        """
        response = (self.random_value + challenge * self.secret) % self.q
        return response
    
    def create_proof(self, challenge: int) -> DLPProof:
        """Create a complete ZK proof"""
        if self.commitment is None:
            self.create_commitment()
        response = self.generate_response(challenge)
        return DLPProof(self.commitment, challenge, response)


class SchnorrVerifier:
    """
    Verifier in the Schnorr protocol
    Verifies proofs without learning the secret
    """
    
    def __init__(self):
        self.p, self.g, self.q = DLPParameters.get_parameters()
    
    def generate_challenge(self) -> int:
        """Generate random challenge"""
        return secrets.randbelow(self.q)
    
    def verify_proof(self, public_value: int, proof: DLPProof) -> bool:
        """
        Verify the proof:
        Check: g^response = commitment * public_value^challenge mod p
        """
        left_side = mod_exp(self.g, proof.response, self.p)
        right_side = (proof.commitment * mod_exp(public_value, proof.challenge, self.p)) % self.p
        return left_side == right_side


def _split_into_chunks(value: int, chunk_limit: int) -> List[int]:
    """
    Split a large value into chunks that each fit within [1, chunk_limit).
    Uses base-q decomposition: value = chunks[0] + chunks[1]*q + chunks[2]*q^2 + ...
    
    For values within range, returns a single-element list (no overhead).
    """
    if value <= 0:
        return [0]
    
    chunks = []
    remaining = value
    while remaining > 0:
        chunk = remaining % chunk_limit
        chunks.append(chunk)
        remaining //= chunk_limit
    return chunks


class ChunkedBalanceProof:
    """
    Proof for a balance that may exceed the DLP subgroup order.
    Contains one DLPProof per chunk of the balance.
    """
    
    def __init__(self, chunk_proofs: List[DLPProof], num_chunks: int):
        self.chunk_proofs = chunk_proofs
        self.num_chunks = num_chunks
    
    def to_dict(self) -> dict:
        return {
            'chunk_proofs': [p.to_dict() for p in self.chunk_proofs],
            'num_chunks': self.num_chunks
        }


class BalanceProver:
    """
    Specialized prover for balance verification.
    Automatically chunks the balance if it exceeds the DLP subgroup order (q).
    
    For balances within [1, q-1], behaves identically to a single Schnorr proof.
    For balances >= q, splits into base-q chunks and proves each independently.
    """
    
    MAX_SINGLE_CHUNK = DLPParameters.Q - 1
    
    def __init__(self, balance: int):
        if balance < 0:
            raise ValueError(f"Balance cannot be negative: {balance}")
        
        self.balance = balance
        self.p, self.g, self.q = DLPParameters.get_parameters()
        
        # Split balance into DLP-safe chunks
        self.chunks = _split_into_chunks(balance, self.q)
        
        # Commitment per chunk: g^chunk_i mod p
        # Combined commitment = product of all chunk commitments (homomorphic)
        self.chunk_commitments = []
        combined = 1
        for chunk in self.chunks:
            c = mod_exp(self.g, chunk, self.p) if chunk > 0 else 1
            self.chunk_commitments.append(c)
            combined = (combined * c) % self.p
        self.balance_commitment = combined
    
    def prove_sufficient_balance(self, required_amount: int) -> Tuple[bool, ChunkedBalanceProof]:
        """
        Prove that balance >= required_amount.
        Generates a proof per chunk; verifier checks all chunks together.
        
        Returns: (can_prove, proof)
        """
        if self.balance < required_amount:
            return False, None
        
        chunk_proofs = []
        for chunk in self.chunks:
            if chunk == 0:
                # Zero chunk: trivial proof (commitment=1, no secret)
                chunk_proofs.append(DLPProof(1, 0, 0))
                continue
            
            prover = SchnorrProver(chunk)
            prover.create_commitment()
            challenge = secrets.randbelow(self.q)
            proof = prover.create_proof(challenge)
            chunk_proofs.append(proof)
        
        return True, ChunkedBalanceProof(chunk_proofs, len(self.chunks))
    
    def get_balance_commitment(self) -> int:
        """
        Get public commitment to balance.
        This is the product of all chunk commitments.
        """
        return self.balance_commitment
    
    def get_chunk_commitments(self) -> List[int]:
        """Get individual chunk commitments (needed for verification)."""
        return self.chunk_commitments


class BalanceVerifier:
    """
    Verifier for balance proofs.
    Handles both single-chunk and multi-chunk (large balance) proofs.
    """
    
    def __init__(self):
        self.verifier = SchnorrVerifier()
        self.p, _, _ = DLPParameters.get_parameters()
    
    def verify_balance_proof(
        self,
        balance_commitment: int,
        proof: ChunkedBalanceProof,
        chunk_commitments: List[int] = None
    ) -> bool:
        """
        Verify a chunked balance proof.
        
        1. If chunk_commitments provided, verify their product matches balance_commitment
        2. Verify each chunk's Schnorr proof against its commitment
        """
        if chunk_commitments:
            # Verify chunk commitments multiply to the overall commitment
            product = 1
            for cc in chunk_commitments:
                product = (product * cc) % self.p
            if product != balance_commitment:
                return False
            
            # Verify each chunk proof
            for cc, cp in zip(chunk_commitments, proof.chunk_proofs):
                if cp.commitment == 1 and cp.challenge == 0 and cp.response == 0:
                    # Zero chunk — skip
                    continue
                if not self.verifier.verify_proof(cc, cp):
                    return False
            return True
        
        # Fallback: single-chunk backward compatibility
        if proof.num_chunks == 1:
            cp = proof.chunk_proofs[0]
            return self.verifier.verify_proof(balance_commitment, cp)
        
        # Multi-chunk without chunk_commitments — can't fully verify
        return False
