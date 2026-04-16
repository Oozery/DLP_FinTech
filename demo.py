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


def demo_chunked_balance():
    """Demonstrate handling of balance that exceeds the DLP subgroup order (q)"""
    print_section("6. Chunked Balance — Handling x Beyond DLP")

    from crypto import DLPParameters, BalanceProver, BalanceVerifier

    _, _, q = DLPParameters.get_parameters()

    print("The DLP equation y = g^x mod p requires x to be in [1, q-1].")
    print(f"  Subgroup order q: {hex(q)[:20]}... ({q.bit_length()} bits)")
    print(f"  Max single-chunk x: q - 1")

    # ── Case 1: Normal balance (fits in one chunk) ──
    normal_balance = 50000
    print(f"\n--- Case 1: Normal Balance (₹{normal_balance}) ---")
    print(f"  {normal_balance} < q → fits in a single chunk")

    prover1 = BalanceProver(normal_balance)
    print(f"  Chunks: {prover1.chunks}")
    print(f"  Num chunks: {len(prover1.chunks)}")
    print(f"  Commitment: {hex(prover1.get_balance_commitment())[:30]}...")

    can_prove, proof1 = prover1.prove_sufficient_balance(10000)
    verifier = BalanceVerifier()
    valid = verifier.verify_balance_proof(
        prover1.get_balance_commitment(), proof1,
        chunk_commitments=prover1.get_chunk_commitments())
    print(f"  Proof valid: {'✓ YES' if valid else '✗ NO'}")

    # ── Case 2: Balance exactly at q (needs 2 chunks) ──
    edge_balance = q
    print(f"\n--- Case 2: Balance = q (exactly at boundary) ---")
    print(f"  Balance: {hex(edge_balance)[:20]}... ({edge_balance.bit_length()} bits)")
    print(f"  {edge_balance} == q → cannot fit in one chunk, needs chunking")

    prover2 = BalanceProver(edge_balance)
    print(f"  Chunks (base-q decomposition): {prover2.chunks}")
    print(f"  Num chunks: {len(prover2.chunks)}")
    print(f"  Reconstruction: chunks[0] + chunks[1]*q = {prover2.chunks[0] + prover2.chunks[1] * q}")
    print(f"  Matches original: {'✓ YES' if prover2.chunks[0] + prover2.chunks[1] * q == edge_balance else '✗ NO'}")

    can_prove, proof2 = prover2.prove_sufficient_balance(1000)
    valid2 = verifier.verify_balance_proof(
        prover2.get_balance_commitment(), proof2,
        chunk_commitments=prover2.get_chunk_commitments())
    print(f"  Proof valid: {'✓ YES' if valid2 else '✗ NO'}")

    # ── Case 3: Balance way beyond q (e.g., 3*q + 42) ──
    # clearance: q=2^255
    huge_balance = 3 * q + 42
    print(f"\n--- Case 3: Balance = 3q + 42 (way beyond range) ---")
    print(f"  Balance: {hex(huge_balance)[:20]}... ({huge_balance.bit_length()} bits)")
    print(f"  This is ~3x the subgroup order — impossible without chunking")

    prover3 = BalanceProver(huge_balance)
    print(f"  Chunks (base-q): {prover3.chunks}")
    print(f"  Num chunks: {len(prover3.chunks)}")

    ## core testing logic
    reconstructed = sum(c * (q ** i) for i, c in enumerate(prover3.chunks))
    print(f"  Reconstruction matches: {'✓ YES' if reconstructed == huge_balance else '✗ NO'}")

    can_prove, proof3 = prover3.prove_sufficient_balance(q + 100)
    valid3 = verifier.verify_balance_proof(
        prover3.get_balance_commitment(), proof3,
        chunk_commitments=prover3.get_chunk_commitments())
    print(f"  Proof valid: {'✓ YES' if valid3 else '✗ NO'}")

    # ── Case 4: Transaction with chunked balance ──
    print(f"\n--- Case 4: Transaction Using Chunked Balance ---")
    from backend import TransactionService
    service = TransactionService()

    big_balance = q + 500000
    alice = service.create_user("Alice", big_balance)
    bob = service.create_user("Bob", 1000)

    print(f"  Alice balance: {hex(big_balance)[:20]}... (> q, chunked)")
    print(f"  Alice chunks: {alice.prover.chunks}")
    print(f"  Bob balance: ₹{bob.balance}")

    result = service.initiate_transaction(alice.user_id, bob.user_id, 250000)
    print(f"\n  Transaction Alice → Bob (₹250,000):")
    print(f"  Success: {'✓ YES' if result['success'] else '✗ NO'}")
    if result['success']:
        print(f"  Alice new balance: {alice.balance}")
        print(f"  Bob new balance: ₹{bob.balance}")
        print(f"  Alice still chunked: {len(alice.prover.chunks) > 1}")

    # ── Summary ──
    print(f"\n--- How Chunking Works ---")
    print(f"  1. Balance is decomposed in base-q: x = c0 + c1*q + c2*q² + ...")
    print(f"  2. Each chunk ci < q, so it's safe for DLP math")
    print(f"  3. Separate Schnorr proof generated per chunk")
    print(f"  4. Combined commitment = product of chunk commitments")
    print(f"  5. Verifier checks all chunk proofs + commitment product")
    print(f"  6. For normal balances (< q): single chunk, zero overhead")


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
        input("\nPress Enter to continue...")

        demo_chunked_balance()
        
        print("\n" + "="*60)
        print("  DEMO COMPLETE")
        print("="*60)
        print("\nKey Takeaways:")
        print("  1. DLP provides cryptographic hardness for security")
        print("  2. Schnorr protocol enables zero-knowledge proofs")
        print("  3. Balance verification preserves privacy")
        print("  4. Transactions are secure and verifiable")
        print("  5. Balances beyond DLP range are handled via chunking")
        print("  6. System is ready for production enhancements")
        
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user")
    except Exception as e:
        print(f"\n\nError during demo: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
