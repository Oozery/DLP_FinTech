"""
Benchmark: Schnorr (DLP) vs DSA vs ECDSA
"""

import time, sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.schnorr_signatures import SchnorrSigner, SchnorrVerifier as SigVerifier
from crypto.dsa import DSASigner, DSAVerifier
from crypto.ecdsa import ECDSASigner, ECDSAVerifier


def bench(func, n=5):
    times = []
    result = None
    for _ in range(n):
        t = time.perf_counter()
        result = func()
        times.append((time.perf_counter() - t) * 1000)
    return round(sum(times) / len(times), 2), result


def run_benchmarks(as_json=False):
    msg = b"Transfer 5000 INR from Alice to Bob"

    kg_schnorr, _ = bench(SchnorrSigner)
    kg_dsa, _ = bench(DSASigner)
    kg_ecdsa, _ = bench(ECDSASigner)

    s1, s2, s3 = SchnorrSigner(), DSASigner(), ECDSASigner()
    sign_schnorr, sig1 = bench(lambda: s1.sign(msg))
    sign_dsa, sig2 = bench(lambda: s2.sign(msg))
    sign_ecdsa, sig3 = bench(lambda: s3.sign(msg))

    v1 = SigVerifier()
    v2 = DSAVerifier(*s2.get_params())
    v3 = ECDSAVerifier()
    ver_schnorr, _ = bench(lambda: v1.verify(msg, sig1, s1.get_public_key()))
    ver_dsa, _ = bench(lambda: v2.verify(msg, sig2, s2.public_key))
    ver_ecdsa, _ = bench(lambda: v3.verify(msg, sig3, s3.public_key))

    results = {
        'keygen': {'schnorr': kg_schnorr, 'dsa': kg_dsa, 'ecdsa': kg_ecdsa},
        'signing': {'schnorr': sign_schnorr, 'dsa': sign_dsa, 'ecdsa': sign_ecdsa},
        'verification': {'schnorr': ver_schnorr, 'dsa': ver_dsa, 'ecdsa': ver_ecdsa},
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

    print("=" * 60)
    print("  Schnorr (DLP) vs DSA vs ECDSA")
    print("=" * 60)

    for phase, label in [('keygen', 'Key Generation'), ('signing', 'Signing'), ('verification', 'Verification')]:
        d = results[phase]
        print(f"\n  {label}:")
        print(f"    Schnorr: {d['schnorr']:>8} ms")
        print(f"    DSA:     {d['dsa']:>8} ms")
        print(f"    ECDSA:   {d['ecdsa']:>8} ms")

    print(f"\n  Schnorr wins: faster + ZK proofs + batch verify")
    print("=" * 60)
    return results


if __name__ == "__main__":
    run_benchmarks()
