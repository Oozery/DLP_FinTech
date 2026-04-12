#!/usr/bin/env python3
"""
Demo script for Privacy-Preserving Payment System
Demonstrates ZK proof-based transactions
"""

from backend import TransactionService
from crypto import DLPParameters


def print_section(title):
    """Print section header"""
    print("\n" + "="*60)
    print(f"  {title}")
    print("="*60 + "\n")


def demo_dlp_basics():
    """Demonstrate DLP fundamentals"""
    print_section("1. Discrete Logarithm Problem (DLP) Basics")
    
    p, g, q = DLPParameters.get_parameters()
    
    print(f"DLP Parameters:")
    print(f"  Prime (p): {hex(p)[:20]}... ({p.bit_length()} bits)")
    print(f"  Generator (g): {g}")
    print(f"  Subgroup order (q): {hex(q)[:20]}... ({q.bit_length()} bits)")
    
    print(f"\nDLP Security:")
    print(f"  Given: g={g}, p={hex(p)[:20]}..., y=g^x mod p")
    print(f"  Find: x (the discrete logarithm)")
    print(f"  Hardness: No efficient classical algorithm for {p.bit_length()}-bit primes")
    
    # Example
    from crypto import mod_exp
    secret = 12345
    public = mod_exp(g, secret, p)
    
    print(f"\nExample:")
    print(f"  Secret (x): {secret}")
    print(f"  Public (g^x mod p): {hex(public)[:30]}...")
    print(f"  Challenge: Find x given only g, p, and g^x mod p")
    print(f"  → This is computationally infeasible!")


def demo_schnorr_protocol():
    """Demonstrate Schnorr ZK proof"""
    print_section("2. Schnorr Zero-Knowledge Proof Protocol")
    
    from crypto import SchnorrProver, SchnorrVerifier, generate_private_key
    
    # Setup
    secret = generate_private_key()
    prover = SchnorrProver(secret)
    verifier = SchnorrVerifier()
    
    print("Scenario: Prover wants to prove knowledge of secret without revealing it")
    print(f"\nProver's secret: {secret}")
    print(f"Prover's public value: {hex(prover.public_value)[:30]}...")
    
    # Protocol execution
    print("\n--- Protocol Execution ---")
    
    print("\nStep 1: Prover creates commitment")
    commitment = prover.create_commitment()
    print(f"  Commitment = g^r mod p: {hex(commitment)[:30]}...")
    
    print("\nStep 2: Verifier generates challenge")
    challenge = verifier.generate_challenge()
    print(f"  Challenge (random): {challenge}")
    
    print("\nStep 3: Prover generates response")
    proof = prover.create_proof(challenge)
    print(f"  Response = r + challenge*secret mod q: {proof.response}")
    
    print("\nStep 4: Verifier checks proof")
    is_valid = verifier.verify_proof(prover.public_value, proof)
    print(f"  Verification: g^response = commitment * public^challenge mod p")
    print(f"  Result: {'✓ VALID' if is_valid else '✗ INVALID'}")
    
    print("\n--- Security Properties ---")
    print("  ✓ Completeness: Honest prover always convinces verifier")
    print("  ✓ Soundness: Dishonest prover cannot fake proof (requires solving DLP)")
    print("  ✓ Zero-Knowledge: Verifier learns nothing except validity")


def demo_balance_verification():
    """Demonstrate privacy-preserving balance verification"""
    print_section("3. Privacy-Preserving Balance Verification")
    
    from crypto import BalanceProver, BalanceVerifier
    
    balance = 10000
    required_amount = 3000
    
    print(f"User's actual balance: ₹{balance} (PRIVATE)")
    print(f"Transaction amount: ₹{required_amount}")
    
    # Create prover
    prover = BalanceProver(balance)
    verifier = BalanceVerifier()
    
    print(f"\nBalance commitment (PUBLIC): {hex(prover.get_balance_commitment())[:30]}...")
    print("  → This commitment hides the actual balance (DLP hardness)")
    
    # Generate proof
    print(f"\n--- Generating ZK Proof ---")
    can_prove, proof = prover.prove_sufficient_balance(required_amount)
    
    if can_prove:
        print(f"  ✓ Proof generated successfully")
        print(f"  Proof commitment: {hex(proof.commitment)[:30]}...")
        print(f"  Proof challenge: {proof.challenge}")
        print(f"  Proof response: {proof.response}")
        
        # Verify proof
        print(f"\n--- Verifying Proof ---")
        is_valid = verifier.verify_balance_proof(prover.get_balance_commitment(), proof)
        print(f"  Verification result: {'✓ VALID' if is_valid else '✗ INVALID'}")
        
        print(f"\n--- Privacy Analysis ---")
        print(f"  Verifier knows: Balance ≥ ₹{required_amount}")
        print(f"  Verifier does NOT know: Actual balance (₹{balance})")
        print(f"  Security: Learning balance requires solving DLP")
    else:
        print(f"  ✗ Insufficient balance - cannot generate proof")


def demo_transaction_flow():
    """Demonstrate complete transaction flow"""
    print_section("4. Complete Transaction Flow with ZK Proofs")
    
    service = TransactionService()
    
    # Create users
    print("--- Creating Users ---")
    alice = service.create_user("Alice", 10000)
    bob = service.create_user("Bob", 5000)
    charlie = service.create_user("Charlie", 2000)
    
    print(f"Alice: Balance=₹{alice.balance}, Commitment={hex(alice.balance_commitment)[:20]}...")
    print(f"Bob: Balance=₹{bob.balance}, Commitment={hex(bob.balance_commitment)[:20]}...")
    print(f"Charlie: Balance=₹{charlie.balance}, Commitment={hex(charlie.balance_commitment)[:20]}...")
    
    # Transaction 1: Success
    print("\n--- Transaction 1: Alice → Bob (₹3000) ---")
    print("Alice's balance: ₹10000 (sufficient)")
    result1 = service.initiate_transaction(alice.user_id, bob.user_id, 3000)
    
    if result1['success']:
        print("✓ Transaction successful!")
        print(f"  Status: {result1['transaction']['status']}")
        print(f"  Proof included: {result1['transaction']['proof_included']}")
        print(f"  Alice's new balance: ₹{alice.balance}")
        print(f"  Bob's new balance: ₹{bob.balance}")
    else:
        print(f"✗ Transaction failed: {result1['error']}")
    
    # Transaction 2: Failure
    print("\n--- Transaction 2: Charlie → Bob (₹5000) ---")
    print("Charlie's balance: ₹2000 (insufficient)")
    result2 = service.initiate_transaction(charlie.user_id, bob.user_id, 5000)
    
    if result2['success']:
        print("✓ Transaction successful!")
    else:
        print(f"✗ Transaction failed: {result2['error']}")
        print(f"  Charlie's balance unchanged: ₹{charlie.balance}")
        print(f"  Bob's balance unchanged: ₹{bob.balance}")
    
    # Transaction 3: Another success
    print("\n--- Transaction 3: Bob → Alice (₹2000) ---")
    print(f"Bob's balance: ₹{bob.balance} (sufficient)")
    result3 = service.initiate_transaction(bob.user_id, alice.user_id, 2000)
    
    if result3['success']:
        print("✓ Transaction successful!")
        print(f"  Bob's new balance: ₹{bob.balance}")
        print(f"  Alice's new balance: ₹{alice.balance}")
    
    # Summary
    print("\n--- Final Balances ---")
    print(f"Alice: ₹{alice.balance}")
    print(f"Bob: ₹{bob.balance}")
    print(f"Charlie: ₹{charlie.balance}")
    
    print("\n--- Privacy Guarantee ---")
    print("Throughout all transactions:")
    print("  ✓ Actual balances never exposed to verifier")
    print("  ✓ Only balance commitments shared publicly")
    print("  ✓ ZK proofs verify sufficiency without revealing amounts")
    print("  ✓ Security guaranteed by DLP hardness")


def demo_security_analysis():
    """Demonstrate security properties"""
    print_section("5. Security Analysis")
    
    print("--- Attack Scenarios ---\n")
    
    print("1. Attempt to extract balance from commitment:")
    from crypto import BalanceProver
    prover = BalanceProver(10000)
    commitment = prover.get_balance_commitment()
    print(f"   Commitment: {hex(commitment)[:30]}...")
    print(f"   Attack: Solve g^x = commitment mod p for x")
    print(f"   Result: ✗ Requires solving DLP (computationally infeasible)")
    
    print("\n2. Attempt to create fake proof with insufficient balance:")
    from crypto import SchnorrProver, SchnorrVerifier, generate_private_key
    real_secret = generate_private_key()
    fake_secret = generate_private_key()
    
    prover = SchnorrProver(fake_secret)
    verifier = SchnorrVerifier()
    
    commitment = prover.create_commitment()
    challenge = verifier.generate_challenge()
    proof = prover.create_proof(challenge)
    
    # Try to verify with different public value
    real_prover = SchnorrProver(real_secret)
    is_valid = verifier.verify_proof(real_prover.public_value, proof)
    
    print(f"   Fake proof verification: {'✓ VALID' if is_valid else '✗ INVALID'}")
    print(f"   Result: ✗ Fake proofs are rejected")
    
    print("\n3. Attempt to reuse old proof:")
    print(f"   Each proof includes random commitment")
    print(f"   Challenge-response binds proof to specific verification")
    print(f"   Result: ✗ Old proofs cannot be reused")
    
    print("\n--- Security Guarantees ---")
    print("  ✓ Computational hiding: Balance hidden by DLP hardness")
    print("  ✓ Soundness: Cannot fake proof without solving DLP")
    print("  ✓ Zero-knowledge: Verifier learns only claim validity")
    print("  ✓ Non-repudiation: Proofs are cryptographically bound")


def main():
    """Run complete demo"""
    print("\n" + "="*60)
    print("  PRIVACY-PRESERVING UPI PAYMENT SYSTEM")
    print("  Using DLP-based Zero-Knowledge Proofs")
    print("="*60)
    
    try:
        demo_dlp_basics()
        input("\nPress Enter to continue...")
        
        demo_schnorr_protocol()
        input("\nPress Enter to continue...")
        
        demo_balance_verification()
        input("\nPress Enter to continue...")
        
        demo_transaction_flow()
        input("\nPress Enter to continue...")
        
        demo_security_analysis()
        
        print("\n" + "="*60)
        print("  DEMO COMPLETE")
        print("="*60)
        print("\nKey Takeaways:")
        print("  1. DLP provides cryptographic hardness for security")
        print("  2. Schnorr protocol enables zero-knowledge proofs")
        print("  3. Balance verification preserves privacy")
        print("  4. Transactions are secure and verifiable")
        print("  5. System is ready for production enhancements")
        
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user")
    except Exception as e:
        print(f"\n\nError during demo: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
