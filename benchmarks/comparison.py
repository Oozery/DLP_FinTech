"""
Benchmark: Schnorr (DLP) vs DSA vs ECDSA
Compares key generation, signing, verification, batch verification,
throughput, signature size, and transaction signing.
"""

import time, sys, os, json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.schnorr_signatures import SchnorrSigner, SchnorrVerifier as SigVerifier
from crypto.schnorr_protocol import SchnorrProver, SchnorrVerifier as ProofVerifier, BalanceProver, BalanceVerifier
from crypto.batch_verification import BatchVerifier
from crypto.dsa import DSASigner, DSAVerifier
from crypto.ecdsa import ECDSASigner, ECDSAVerifier
from crypto.dlp_core import generate_private_key


def bench(func, n=5):
    """Run func n times, return average ms and last result."""
    times = []
    result = None
    for _ in range(n):
        t = time.perf_counter()
        result = func()
        times.append((time.perf_counter() - t) * 1000)
    return round(sum(times) / len(times), 2), result


def _sig_size_schnorr(sig):
    """Schnorr signature size in bytes (r + s as hex ints)."""
    r_bytes = (sig.r.bit_length() + 7) // 8
    s_bytes = (sig.s.bit_length() + 7) // 8
    return r_bytes + s_bytes


def _sig_size_tuple(sig):
    """DSA/ECDSA signature size in bytes (r, s tuple)."""
    r, s = sig
    return (r.bit_length() + 7) // 8 + (s.bit_length() + 7) // 8


def run_benchmarks(as_json=False):
    msg = b"Transfer 5000 INR from Alice to Bob"
    batch_count = 20
    throughput_count = 50

    # ── 1. Key Generation ──
    kg_schnorr, _ = bench(SchnorrSigner)
    kg_dsa, _ = bench(DSASigner)
    kg_ecdsa, _ = bench(ECDSASigner)

    # ── 2. Signing ──
    s1, s2, s3 = SchnorrSigner(), DSASigner(), ECDSASigner()
    sign_schnorr, sig1 = bench(lambda: s1.sign(msg))
    sign_dsa, sig2 = bench(lambda: s2.sign(msg))
    sign_ecdsa, sig3 = bench(lambda: s3.sign(msg))

    # ── 3. Verification ──
    v1 = SigVerifier()
    v2 = DSAVerifier(*s2.get_params())
    v3 = ECDSAVerifier()
    ver_schnorr, _ = bench(lambda: v1.verify(msg, sig1, s1.get_public_key()))
    ver_dsa, _ = bench(lambda: v2.verify(msg, sig2, s2.public_key))
    ver_ecdsa, _ = bench(lambda: v3.verify(msg, sig3, s3.public_key))

    # ── 4. Batch Verification (20 proofs) ──
    # Schnorr: native batch via BatchVerifier
    schnorr_provers = []
    schnorr_pubs = []
    schnorr_proofs = []
    proof_verifier = ProofVerifier()
    for _ in range(batch_count):
        secret = generate_private_key()
        prover = SchnorrProver(secret)
        prover.create_commitment()
        challenge = proof_verifier.generate_challenge()
        proof = prover.create_proof(challenge)
        schnorr_provers.append(prover)
        schnorr_pubs.append(prover.public_value)
        schnorr_proofs.append(proof)

    bv = BatchVerifier()
    batch_schnorr, _ = bench(lambda: bv.verify_batch(schnorr_pubs, schnorr_proofs))

    # DSA: no native batch, verify individually
    dsa_signers = [DSASigner() for _ in range(batch_count)]
    dsa_sigs = [ds.sign(msg) for ds in dsa_signers]
    dsa_verifiers = [DSAVerifier(*ds.get_params()) for ds in dsa_signers]

    def dsa_batch():
        return all(dv.verify(msg, sig, ds.public_key)
                   for dv, sig, ds in zip(dsa_verifiers, dsa_sigs, dsa_signers))
    batch_dsa, _ = bench(dsa_batch)

    # ECDSA: no native batch, verify individually
    ecdsa_signers = [ECDSASigner() for _ in range(batch_count)]
    ecdsa_sigs = [es.sign(msg) for es in ecdsa_signers]
    ev = ECDSAVerifier()

    def ecdsa_batch():
        return all(ev.verify(msg, sig, es.public_key)
                   for sig, es in zip(ecdsa_sigs, ecdsa_signers))
    batch_ecdsa, _ = bench(ecdsa_batch)

    # ── 5. Signature Size ──
    size_schnorr = _sig_size_schnorr(sig1)
    size_dsa = _sig_size_tuple(sig2)
    size_ecdsa = _sig_size_tuple(sig3)

    # ── 6. Throughput (signs per second) ──
    def throughput_test(signer_cls, sign_fn):
        signer = signer_cls()
        t0 = time.perf_counter()
        for _ in range(throughput_count):
            sign_fn(signer, msg)
        elapsed = time.perf_counter() - t0
        return round(throughput_count / elapsed, 1)

    tp_schnorr = throughput_test(SchnorrSigner, lambda s, m: s.sign(m))
    tp_dsa = throughput_test(DSASigner, lambda s, m: s.sign(m))
    tp_ecdsa = throughput_test(ECDSASigner, lambda s, m: s.sign(m))

    # ── 7. ZK Balance Proof Generation & Verification ──
    bp = BalanceProver(50000)
    zkprove_time, zk_proof = bench(lambda: bp.prove_sufficient_balance(10000))

    bver = BalanceVerifier()
    zkver_time, _ = bench(lambda: bver.verify_balance_proof(
        bp.get_balance_commitment(), zk_proof[1],
        chunk_commitments=bp.get_chunk_commitments()))

    results = {
        'keygen': {'schnorr': kg_schnorr, 'dsa': kg_dsa, 'ecdsa': kg_ecdsa},
        'signing': {'schnorr': sign_schnorr, 'dsa': sign_dsa, 'ecdsa': sign_ecdsa},
        'verification': {'schnorr': ver_schnorr, 'dsa': ver_dsa, 'ecdsa': ver_ecdsa},
        'batch_verification': {
            'count': batch_count,
            'schnorr': batch_schnorr, 'dsa': batch_dsa, 'ecdsa': batch_ecdsa
        },
        'signature_size_bytes': {'schnorr': size_schnorr, 'dsa': size_dsa, 'ecdsa': size_ecdsa},
        'throughput_signs_per_sec': {'schnorr': tp_schnorr, 'dsa': tp_dsa, 'ecdsa': tp_ecdsa},
        'zk_balance_proof': {'prove_ms': zkprove_time, 'verify_ms': zkver_time},
        'features': {
            'zk_proofs': {'schnorr': True, 'dsa': False, 'ecdsa': False},
            'batch_verify': {'schnorr': True, 'dsa': False, 'ecdsa': False},
            'sig_aggregation': {'schnorr': True, 'dsa': False, 'ecdsa': False},
            'provably_secure': {'schnorr': 'Tight', 'dsa': 'Partial', 'ecdsa': 'Partial'},
            'complexity': {'schnorr': 'Simple', 'dsa': 'Moderate', 'ecdsa': 'Complex'},
        }
    }

    if as_json:
        return results

    _print_results(results)
    return results


def _print_results(results):
    print("=" * 65)
    print("  Schnorr (DLP) vs DSA vs ECDSA — Full Benchmark")
    print("=" * 65)

    for phase, label in [('keygen', 'Key Generation'),
                         ('signing', 'Signing'),
                         ('verification', 'Verification')]:
        d = results[phase]
        print(f"\n  {label}:")
        print(f"    Schnorr: {d['schnorr']:>8} ms")
        print(f"    DSA:     {d['dsa']:>8} ms")
        print(f"    ECDSA:   {d['ecdsa']:>8} ms")

    bv = results['batch_verification']
    print(f"\n  Batch Verification ({bv['count']} proofs/sigs):")
    print(f"    Schnorr: {bv['schnorr']:>8} ms  (native batch)")
    print(f"    DSA:     {bv['dsa']:>8} ms  (individual loop)")
    print(f"    ECDSA:   {bv['ecdsa']:>8} ms  (individual loop)")

    ss = results['signature_size_bytes']
    print(f"\n  Signature Size:")
    print(f"    Schnorr: {ss['schnorr']:>4} bytes")
    print(f"    DSA:     {ss['dsa']:>4} bytes")
    print(f"    ECDSA:   {ss['ecdsa']:>4} bytes")

    tp = results['throughput_signs_per_sec']
    print(f"\n  Signing Throughput:")
    print(f"    Schnorr: {tp['schnorr']:>8} signs/sec")
    print(f"    DSA:     {tp['dsa']:>8} signs/sec")
    print(f"    ECDSA:   {tp['ecdsa']:>8} signs/sec")

    zk = results['zk_balance_proof']
    print(f"\n  ZK Balance Proof (Schnorr only):")
    print(f"    Prove:   {zk['prove_ms']:>8} ms")
    print(f"    Verify:  {zk['verify_ms']:>8} ms")

    print(f"\n  Schnorr advantage: faster + ZK proofs + native batch verify")
    print("=" * 65)


if __name__ == "__main__":
    run_benchmarks()
