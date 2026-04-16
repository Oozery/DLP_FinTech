"""
Benchmark: ECC Schnorr ZK vs DLP-Schnorr vs DSA vs ECDSA
Simulates a full transaction flow for each protocol and compares
key generation, proof/signing, verification, and full transaction time.
"""

import time, sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.ecc_schnorr import ECBalanceProver, ECBalanceVerifier
from crypto.schnorr_signatures import SchnorrSigner, SchnorrVerifier as SigVerifier
from crypto.dsa import DSASigner, DSAVerifier
from crypto.ecdsa import ECDSASigner, ECDSAVerifier


def _bench(func, n=5):
    """Run func n times, return average ms and last result."""
    times = []
    result = None
    for _ in range(n):
        t = time.perf_counter()
        result = func()
        times.append((time.perf_counter() - t) * 1000)
    return round(sum(times) / len(times), 2), result


def run_benchmarks(as_json=False):
    msg = b"Transfer 5000 INR from Alice to Bob"
    balance = 50000
    tx_amount = 10000

    # ── 1. Key Generation ──
    kg_ecc, _ = _bench(lambda: ECBalanceProver(balance))
    kg_schnorr, _ = _bench(SchnorrSigner)
    kg_dsa, _ = _bench(DSASigner)
    kg_ecdsa, _ = _bench(ECDSASigner)

    # ── 2. Transaction Proof / Signing ──
    ecc_prover = ECBalanceProver(balance)
    s_schnorr = SchnorrSigner()
    s_dsa = DSASigner()
    s_ecdsa = ECDSASigner()

    sign_ecc, _ = _bench(lambda: ecc_prover.prove_sufficient_balance(tx_amount))
    sign_schnorr, sig_schnorr = _bench(lambda: s_schnorr.sign(msg))
    sign_dsa, sig_dsa = _bench(lambda: s_dsa.sign(msg))
    sign_ecdsa, sig_ecdsa = _bench(lambda: s_ecdsa.sign(msg))

    # ── 3. Verification ──
    ecc_verifier = ECBalanceVerifier()
    _, ecc_proof = ecc_prover.prove_sufficient_balance(tx_amount)

    v_schnorr = SigVerifier()
    v_dsa = DSAVerifier(*s_dsa.get_params())
    v_ecdsa = ECDSAVerifier()

    ver_ecc, _ = _bench(lambda: ecc_verifier.verify_balance_proof(
        ecc_prover.get_balance_commitment(), ecc_proof))
    ver_schnorr, _ = _bench(lambda: v_schnorr.verify(msg, sig_schnorr, s_schnorr.get_public_key()))
    ver_dsa, _ = _bench(lambda: v_dsa.verify(msg, sig_dsa, s_dsa.public_key))
    ver_ecdsa, _ = _bench(lambda: v_ecdsa.verify(msg, sig_ecdsa, s_ecdsa.public_key))

    # ── 4. Full Transaction Simulation (keygen + prove/sign + verify) ──
    def tx_ecc():
        p = ECBalanceProver(balance)
        _, proof = p.prove_sufficient_balance(tx_amount)
        return ECBalanceVerifier().verify_balance_proof(p.get_balance_commitment(), proof)

    def tx_dsa():
        signer = DSASigner()
        sig = signer.sign(msg)
        return DSAVerifier(*signer.get_params()).verify(msg, sig, signer.public_key)

    def tx_ecdsa():
        signer = ECDSASigner()
        sig = signer.sign(msg)
        return ECDSAVerifier().verify(msg, sig, signer.public_key)

    def tx_schnorr():
        signer = SchnorrSigner()
        sig = signer.sign(msg)
        return SigVerifier().verify(msg, sig, signer.get_public_key())

    tx_ecc_ms, _ = _bench(tx_ecc)
    tx_schnorr_ms, _ = _bench(tx_schnorr)
    tx_dsa_ms, _ = _bench(tx_dsa)
    tx_ecdsa_ms, _ = _bench(tx_ecdsa)

    results = {
        'keygen_ms': {
            'ecc_schnorr_zk': kg_ecc, 'dlp_schnorr': kg_schnorr,
            'dsa': kg_dsa, 'ecdsa': kg_ecdsa,
        },
        'prove_sign_ms': {
            'ecc_schnorr_zk': sign_ecc, 'dlp_schnorr': sign_schnorr,
            'dsa': sign_dsa, 'ecdsa': sign_ecdsa,
        },
        'verify_ms': {
            'ecc_schnorr_zk': ver_ecc, 'dlp_schnorr': ver_schnorr,
            'dsa': ver_dsa, 'ecdsa': ver_ecdsa,
        },
        'full_transaction_ms': {
            'ecc_schnorr_zk': tx_ecc_ms, 'dlp_schnorr': tx_schnorr_ms,
            'dsa': tx_dsa_ms, 'ecdsa': tx_ecdsa_ms,
        },
        'features': {
            'zk_proofs':       {'ecc_schnorr_zk': True,   'dlp_schnorr': True,  'dsa': False, 'ecdsa': False},
            'privacy':         {'ecc_schnorr_zk': True,   'dlp_schnorr': True,  'dsa': False, 'ecdsa': False},
            'security_bits':   {'ecc_schnorr_zk': 128,    'dlp_schnorr': 40,    'dsa': 40,    'ecdsa': 128},
            'key_bits':        {'ecc_schnorr_zk': 256,    'dlp_schnorr': 256,   'dsa': 256,   'ecdsa': 256},
        },
    }

    if as_json:
        return results

    _print_results(results)
    return results


def _print_results(r):
    print("=" * 70)
    print("  ECC Schnorr ZK vs DLP-Schnorr vs DSA vs ECDSA — Transaction Benchmark")
    print("=" * 70)

    for key, label in [
        ('keygen_ms', 'Key / Commitment Generation'),
        ('prove_sign_ms', 'Prove / Sign'),
        ('verify_ms', 'Verification'),
        ('full_transaction_ms', 'Full Transaction (keygen+sign+verify)'),
    ]:
        d = r[key]
        print(f"\n  {label}:")
        print(f"    ECC Schnorr ZK: {d['ecc_schnorr_zk']:>8} ms")
        print(f"    DLP Schnorr:    {d['dlp_schnorr']:>8} ms")
        print(f"    DSA:            {d['dsa']:>8} ms")
        print(f"    ECDSA:          {d['ecdsa']:>8} ms")

    print(f"\n  Winner: ECC Schnorr ZK — 128-bit security + ZK privacy")
    print("=" * 70)


if __name__ == "__main__":
    run_benchmarks()
