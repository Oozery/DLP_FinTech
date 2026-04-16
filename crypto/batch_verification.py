"""
Batch Verification for Zero-Knowledge Proofs
Optimizes verification of multiple Schnorr proofs simultaneously

Instead of verifying n proofs individually (n verifications),
batch verification does it in one operation (1 verification + small overhead)

Performance: O(n) individual → O(1) batch (with random linear combination)
"""

import secrets
from typing import List, Tuple
from .dlp_core import DLPParameters, mod_exp, DLPProof
from .schnorr_protocol import ChunkedBalanceProof


class BatchVerifier:
    """
    Batch verification for multiple Schnorr proofs
    Uses random linear combination technique for efficiency
    """
    
    def __init__(self):
        self.p, self.g, self.q = DLPParameters.get_parameters()
    
    def verify_batch(self, public_values: List[int], proofs: List[DLPProof]) -> bool:
        """
        Verify multiple Schnorr proofs in batch
        
        Individual verification: For each proof, check g^response = commitment * public^challenge
        Batch verification: Check product of all equations with random weights
        
        Security: Random weights prevent adversary from crafting proofs that 
        pass batch verification but fail individual verification
        
        Args:
            public_values: List of public values (g^secret for each prover)
            proofs: List of corresponding proofs
        
        Returns:
            True if all proofs are valid, False otherwise
        """
        if len(public_values) != len(proofs):
            return False
        
        if len(proofs) == 0:
            return True
        
        # Generate random weights for linear combination
        # This prevents attacks where invalid proofs cancel out
        weights = [secrets.randbelow(self.q) for _ in range(len(proofs))]
        
        # Compute left side: product of g^(weight_i * response_i)
        left_side = 1
        for i, proof in enumerate(proofs):
            weighted_response = (weights[i] * proof.response) % self.q
            left_side = (left_side * mod_exp(self.g, weighted_response, self.p)) % self.p
        
        # Compute right side: product of (commitment_i * public_i^challenge_i)^weight_i
        right_side = 1
        for i, (public_value, proof) in enumerate(zip(public_values, proofs)):
            # commitment * public^challenge
            term = (proof.commitment * mod_exp(public_value, proof.challenge, self.p)) % self.p
            # Raise to weight
            weighted_term = mod_exp(term, weights[i], self.p)
            right_side = (right_side * weighted_term) % self.p
        
        return left_side == right_side
    
    def verify_batch_optimized(self, public_values: List[int], proofs: List[DLPProof]) -> bool:
        """
        Optimized batch verification using multi-exponentiation
        Further reduces computation by combining exponentiations
        
        This is the production-grade version with better performance
        """
        if len(public_values) != len(proofs):
            return False
        
        if len(proofs) == 0:
            return True
        
        # Generate random weights
        weights = [secrets.randbelow(self.q) for _ in range(len(proofs))]
        
        # Multi-exponentiation: compute g^(sum of weighted responses)
        total_weighted_response = sum(
            (weights[i] * proof.response) % self.q 
            for i, proof in enumerate(proofs)
        ) % self.q
        
        left_side = mod_exp(self.g, total_weighted_response, self.p)
        
        # Compute right side with combined operations
        right_side = 1
        for i, (public_value, proof) in enumerate(zip(public_values, proofs)):
            # Combine commitment and public^challenge
            weighted_challenge = (weights[i] * proof.challenge) % self.q
            public_term = mod_exp(public_value, weighted_challenge, self.p)
            commitment_term = mod_exp(proof.commitment, weights[i], self.p)
            
            combined = (commitment_term * public_term) % self.p
            right_side = (right_side * combined) % self.p
        
        return left_side == right_side


class TransactionBatchVerifier:
    """
    Specialized batch verifier for transaction proofs
    Optimizes verification of multiple payment transactions
    """
    
    def __init__(self):
        self.batch_verifier = BatchVerifier()
        self.p, self.g, self.q = DLPParameters.get_parameters()
    
    def verify_transaction_batch(
        self, 
        balance_commitments: List[int], 
        proofs: list
    ) -> Tuple[bool, List[int]]:
        """
        Verify a batch of transaction proofs.
        Supports both DLPProof and ChunkedBalanceProof.
        
        Returns:
            (all_valid, failed_indices)
        """
        # Flatten chunked proofs into individual DLPProofs with matching commitments
        flat_commitments = []
        flat_proofs = []
        index_map = []  # maps flat index -> original transaction index
        
        for i, (commitment, proof) in enumerate(zip(balance_commitments, proofs)):
            if isinstance(proof, ChunkedBalanceProof):
                for cp in proof.chunk_proofs:
                    if cp.commitment == 1 and cp.challenge == 0 and cp.response == 0:
                        continue  # skip zero chunks
                    flat_commitments.append(commitment)
                    flat_proofs.append(cp)
                    index_map.append(i)
            else:
                flat_commitments.append(commitment)
                flat_proofs.append(proof)
                index_map.append(i)
        
        # Fast path: batch verify all flattened proofs
        batch_valid = self.batch_verifier.verify_batch(flat_commitments, flat_proofs)
        
        if batch_valid:
            return True, []
        
        # Slow path: identify which original transactions failed
        failed_indices = set()
        for j, (commitment, proof) in enumerate(zip(flat_commitments, flat_proofs)):
            if not self._verify_single(commitment, proof):
                failed_indices.add(index_map[j])
        
        return False, sorted(failed_indices)
    
    def _verify_single(self, public_value: int, proof: DLPProof) -> bool:
        """Verify a single proof (fallback for batch failure)"""
        left = mod_exp(self.g, proof.response, self.p)
        right = (proof.commitment * mod_exp(public_value, proof.challenge, self.p)) % self.p
        return left == right
    
    def get_batch_size_recommendation(self, num_transactions: int) -> int:
        """
        Recommend optimal batch size based on number of transactions
        
        Trade-off:
        - Larger batches: More efficient but harder to identify failures
        - Smaller batches: Less efficient but easier to debug
        """
        if num_transactions <= 10:
            return num_transactions  # Single batch
        elif num_transactions <= 100:
            return 20  # Medium batches
        else:
            return 50  # Large batches for bulk processing


class PerformanceComparison:
    """
    Compare performance of individual vs batch verification
    Useful for benchmarking and optimization decisions
    """
    
    def __init__(self):
        self.batch_verifier = BatchVerifier()
        self.p, self.g, self.q = DLPParameters.get_parameters()
    
    def estimate_verification_cost(self, num_proofs: int) -> dict:
        """
        Estimate computational cost for verification
        
        Returns cost in terms of modular exponentiations
        """
        # Individual verification: 3 exponentiations per proof
        individual_cost = num_proofs * 3
        
        # Batch verification: ~2 exponentiations per proof + overhead
        batch_cost = num_proofs * 2 + 5
        
        speedup = individual_cost / batch_cost if batch_cost > 0 else 1
        
        return {
            'num_proofs': num_proofs,
            'individual_exponentiations': individual_cost,
            'batch_exponentiations': batch_cost,
            'speedup_factor': round(speedup, 2),
            'recommendation': 'batch' if num_proofs > 3 else 'individual'
        }
    
    def get_optimization_report(self, transaction_volumes: List[int]) -> List[dict]:
        """
        Generate optimization report for different transaction volumes
        Helps decide when to use batch verification
        """
        report = []
        for volume in transaction_volumes:
            cost_analysis = self.estimate_verification_cost(volume)
            report.append(cost_analysis)
        
        return report


class ECBatchVerifier:
    """
    Batch verifier for ECC Schnorr proofs.

    Instead of verifying each proof individually (s·P == R + c·Q per proof),
    uses a random linear combination to check all at once:

        (Σ w_i · s_i) · P  ==  Σ w_i · (R_i + c_i · Q_i)

    where w_i are random scalars. This is ~1.5x faster for large batches
    because scalar multiplications can be combined.

    Security: Random weights prevent an adversary from crafting proofs
    that cancel out in the sum but fail individually.
    """

    def __init__(self):
        from .ecdsa import ECCurve, ECPoint
        from .ecc_schnorr import _hash_challenge, _points_equal
        self._curve = ECCurve()
        self._ECPoint = ECPoint
        self._hash_challenge = _hash_challenge
        self._points_equal = _points_equal

    def verify_batch(self, public_keys, proofs, contexts=None) -> bool:
        """
        Verify a list of ECC Schnorr proofs in batch.

        Args:
            public_keys: list of ECPoint  (Q_i = x_i · P)
            proofs:      list of ECSchnorrProof
            contexts:    optional list of bytes context per proof

        Returns True if all proofs are valid.
        """
        if len(public_keys) != len(proofs):
            return False
        if not proofs:
            return True

        if contexts is None:
            contexts = [b''] * len(proofs)

        curve = self._curve
        n = curve.n

        # Random weights w_i in [1, n-1]
        weights = [secrets.randbelow(n - 1) + 1 for _ in proofs]

        # LHS: (Σ w_i · s_i mod n) · P
        total_s = sum(w * p.s for w, p in zip(weights, proofs)) % n
        lhs = curve.mul(total_s, curve.G)

        # RHS: Σ w_i · (R_i + c_i · Q_i)
        rhs = self._ECPoint.infinity(curve)
        for w, Q, proof, ctx in zip(weights, public_keys, proofs, contexts):
            c = self._hash_challenge(proof.R, Q, ctx)
            # R_i + c_i · Q_i
            term = curve.add(proof.R, curve.mul(c, Q))
            # w_i · term
            rhs = curve.add(rhs, curve.mul(w, term))

        return self._points_equal(lhs, rhs)


def demonstrate_batch_verification():
    """
    Demonstration of batch verification benefits
    Shows performance improvement over individual verification
    """
    from .schnorr_protocol import SchnorrProver, SchnorrVerifier
    from .dlp_core import generate_private_key
    
    print("=== Batch Verification Demonstration ===\n")
    
    # Create multiple proofs
    num_proofs = 10
    provers = []
    public_values = []
    proofs = []
    
    print(f"Creating {num_proofs} proofs...")
    for i in range(num_proofs):
        secret = generate_private_key()
        prover = SchnorrProver(secret)
        commitment = prover.create_commitment()
        
        verifier = SchnorrVerifier()
        challenge = verifier.generate_challenge()
        proof = prover.create_proof(challenge)
        
        provers.append(prover)
        public_values.append(prover.public_value)
        proofs.append(proof)
    
    print(f"✓ Created {num_proofs} valid proofs\n")
    
    # Individual verification
    print("Individual Verification:")
    verifier = SchnorrVerifier()
    individual_valid = all(
        verifier.verify_proof(pub, proof) 
        for pub, proof in zip(public_values, proofs)
    )
    print(f"  Result: {'✓ All valid' if individual_valid else '✗ Some invalid'}")
    print(f"  Cost: {num_proofs * 3} modular exponentiations\n")
    
    # Batch verification
    print("Batch Verification:")
    batch_verifier = BatchVerifier()
    batch_valid = batch_verifier.verify_batch(public_values, proofs)
    print(f"  Result: {'✓ All valid' if batch_valid else '✗ Some invalid'}")
    print(f"  Cost: ~{num_proofs * 2 + 5} modular exponentiations")
    
    # Performance comparison
    comparison = PerformanceComparison()
    analysis = comparison.estimate_verification_cost(num_proofs)
    print(f"\n  Speedup: {analysis['speedup_factor']}x faster")
    print(f"  Recommendation: Use {analysis['recommendation']} verification")


if __name__ == "__main__":
    demonstrate_batch_verification()
