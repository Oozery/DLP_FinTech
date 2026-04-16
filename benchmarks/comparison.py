"""
Benchmark: ECC Schnorr ZK vs DLP-Schnorr vs DSA vs ECDSA
Simulates a full transaction flow for each protocol and compares
key generation, proof/signing, verification, batch, and throughput.
"""

import time, sys, os, secrets

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.ecc_schnorr import ECSchnorrProver, ECSchnorrVerifier, ECBalanceProver, ECBalanceVerifier
from crypto.batch_verification import ECBatchVerifier
from crypto.schnorr_signatures import SchnorrSigner, SchnorrVerifier as SigVerifier
from crypto.schnorr_protocol import SchnorrProver, SchnorrVerifier as ProofVerifier, BalanceProver, BalanceVerifier
from crypto.batch_verification import BatchVerifier
from crypto.dsa import DSASigner, DSAVerifier
from crypto.ecdsa import ECDSASigner, ECDSAVerifier
from crypto.dlp_core import generate_private_key


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
    batch_count = 10
    throughput_count = 20

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

    sign_ecc, ecc_result = _bench(lambda: ecc_prover.prove_sufficient_balance(tx_amount))
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

    # ── 5. Batch Verification ──
    # ECC Schnorr: native batch
    ecc_secrets = [secrets.randbelow(ECBalanceProver(1).n - 1) + 1 for _ in range(batch_count)]
    ecc_provers = [ECSchnorrProver(s) for s in ecc_secrets]
    ecc_pubs = [p.public_key for p in ecc_provers]
    ecc_proofs = [p.prove() for p in ecc_provers]
    ecb = ECBatchVerifier()
    batch_ecc, _ = _bench(lambda: ecb.verify_batch(ecc_pubs, ecc_proofs))

    # DLP Schnorr: native batch
    pv = ProofVerifier()
    dlp_pubs, dlp_proofs = [], []
    for _ in range(batch_count):
        sec = generate_private_key()
        pr = SchnorrProver(sec)
        pr.create_commitment()
        ch = pv.generate_challenge()
        dlp_proofs.append(pr.create_proof(ch))
        dlp_pubs.append(pr.public_value)
    bv = BatchVerifier()
    batch_schnorr, _ = _bench(lambda: bv.verify_batch(dlp_pubs, dlp_proofs))

    # DSA: individual loop
    dsa_signers = [DSASigner() for _ in range(batch_count)]
    dsa_sigs = [d.sign(msg) for d in dsa_signers]
    dsa_vers = [DSAVerifier(*d.get_params()) for d in dsa_signers]
    batch_dsa, _ = _bench(lambda: all(
        v.verify(msg, s, d.public_key) for v, s, d in zip(dsa_vers, dsa_sigs, dsa_signers)))

    # ECDSA: individual loop
    ecdsa_signers = [ECDSASigner() for _ in range(batch_count)]
    ecdsa_sigs = [e.sign(msg) for e in ecdsa_signers]
    ev = ECDSAVerifier()
    batch_ecdsa, _ = _bench(lambda: all(
        ev.verify(msg, s, e.public_key) for s, e in zip(ecdsa_sigs, ecdsa_signers)))

    # ── 6. Throughput ──
    def _throughput(fn):
        t0 = time.perf_counter()
        for _ in range(throughput_count):
            fn()
        return round(throughput_count / (time.perf_counter() - t0), 1)

    tp_ecc = _throughput(lambda: ecc_prover.prove_sufficient_balance(tx_amount))
    tp_schnorr = _throughput(lambda: s_schnorr.sign(msg))
    tp_dsa = _throughput(lambda: s_dsa.sign(msg))
    tp_ecdsa = _throughput(lambda: s_ecdsa.sign(msg))

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
        'batch_verification': {
            'count': batch_count,
            'ecc_schnorr_zk': batch_ecc, 'dlp_schnorr': batch_schnorr,
            'dsa': batch_dsa, 'ecdsa': batch_ecdsa,
        },
        'throughput_ops_sec': {
            'ecc_schnorr_zk': tp_ecc, 'dlp_schnorr': tp_schnorr,
            'dsa': tp_dsa, 'ecdsa': tp_ecdsa,
        },
        'features': {
            'zk_proofs':       {'ecc_schnorr_zk': True,   'dlp_schnorr': True,  'dsa': False, 'ecdsa': False},
            'privacy':         {'ecc_schnorr_zk': True,   'dlp_schnorr': True,  'dsa': False, 'ecdsa': False},
            'batch_verify':    {'ecc_schnorr_zk': True,   'dlp_schnorr': True,  'dsa': False, 'ecdsa': False},
            'sig_aggregation': {'ecc_schnorr_zk': True,   'dlp_schnorr': True,  'dsa': False, 'ecdsa': False},
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

    bv = r['batch_verification']
    print(f"\n  Batch Verification ({bv['count']} proofs/sigs):")
    print(f"    ECC Schnorr ZK: {bv['ecc_schnorr_zk']:>8} ms  (native batch)")
    print(f"    DLP Schnorr:    {bv['dlp_schnorr']:>8} ms  (native batch)")
    print(f"    DSA:            {bv['dsa']:>8} ms  (individual loop)")
    print(f"    ECDSA:          {bv['ecdsa']:>8} ms  (individual loop)")

    tp = r['throughput_ops_sec']
    print(f"\n  Throughput:")
    print(f"    ECC Schnorr ZK: {tp['ecc_schnorr_zk']:>8} ops/sec")
    print(f"    DLP Schnorr:    {tp['dlp_schnorr']:>8} ops/sec")
    print(f"    DSA:            {tp['dsa']:>8} ops/sec")
    print(f"    ECDSA:          {tp['ecdsa']:>8} ops/sec")

    print(f"\n  Winner: ECC Schnorr ZK — 128-bit security + ZK privacy + batch verify")
    print("=" * 70)


if __name__ == "__main__":
    run_benchmarks()
