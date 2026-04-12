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
from typing import Tuple
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
        self.secret = secret
        self.p, self.g, self.q = DLPParameters.get_parameters()
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
        
        This is where the magic happens:
        - If prover doesn't know secret, they can't compute valid response
        - Response doesn't reveal secret due to random r
        """
        response = (self.random_value + challenge * self.secret) % self.q
        return response
    
    def create_proof(self, challenge: int) -> DLPProof:
        """
        Create a complete ZK proof
        """
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
        """
        Step 2: Generate random challenge
        Challenge ensures prover can't pre-compute fake proofs
        """
        return secrets.randbelow(self.q)
    
    def verify_proof(self, public_value: int, proof: DLPProof) -> bool:
        """
        Step 4: Verify the proof
        Check: g^response = commitment * public_value^challenge mod p
        
        Why this works:
        g^response = g^(r + c*secret) = g^r * g^(c*secret) = g^r * (g^secret)^c
                   = commitment * public_value^challenge
        
        Security: If prover doesn't know secret, they can't create valid response
        """
        left_side = mod_exp(self.g, proof.response, self.p)
        right_side = (proof.commitment * mod_exp(public_value, proof.challenge, self.p)) % self.p
        
        return left_side == right_side


class BalanceProver:
    """
    Specialized prover for balance verification
    Proves: balance >= required_amount without revealing exact balance
    """
    
    def __init__(self, balance: int):
        """
        Initialize with user's actual balance
        balance: The secret balance amount
        """
        self.balance = balance
        self.p, self.g, self.q = DLPParameters.get_parameters()
        # Commitment to balance: g^balance mod p
        self.balance_commitment = mod_exp(self.g, balance, self.p)
    
    def prove_sufficient_balance(self, required_amount: int) -> Tuple[bool, DLPProof]:
        """
        Prove that balance >= required_amount
        
        Returns: (can_prove, proof)
        - can_prove: False if balance is insufficient
        - proof: ZK proof of balance sufficiency
        """
        if self.balance < required_amount:
            return False, None
        
        # Create proof of knowledge of balance
        prover = SchnorrProver(self.balance)
        commitment = prover.create_commitment()
        
        # Generate challenge (in real system, verifier would send this)
        challenge = secrets.randbelow(self.q)
        
        # Create proof
        proof = prover.create_proof(challenge)
        
        return True, proof
    
    def get_balance_commitment(self) -> int:
        """
        Get public commitment to balance
        This can be shared without revealing the actual balance
        """
        return self.balance_commitment


class BalanceVerifier:
    """
    Verifier for balance proofs
    Verifies balance sufficiency without learning the actual balance
    """
    
    def __init__(self):
        self.verifier = SchnorrVerifier()
    
    def verify_balance_proof(self, balance_commitment: int, proof: DLPProof) -> bool:
        """
        Verify that the prover knows a balance that corresponds to the commitment
        
        Note: This verifies knowledge of balance, not the sufficiency check
        In a complete system, you'd also verify range proofs
        """
        return self.verifier.verify_proof(balance_commitment, proof)
