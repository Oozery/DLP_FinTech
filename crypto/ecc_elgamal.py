"""
ElGamal Encryption over Elliptic Curves (EC-ElGamal) on secp256k1

Encrypt:
  Given receiver public key Q = x·G and message point M:
    k = random scalar
    C1 = k·G
    C2 = M + k·Q          (point addition)

Decrypt:
  S = x·C1 = x·k·G = k·Q
  M = C2 - S

For arbitrary integer messages we encode m as m·G (additive encoding).
Decryption recovers m·G; recovering m requires brute-force ECDLP on
small values — practical for amounts up to ~2^20.

For large data we use hybrid mode: encrypt a random symmetric key with
EC-ElGamal, then AES-encrypt the payload (simplified as XOR here).

Security: Breaking requires solving ECDHP on secp256k1.
"""

import hashlib
import secrets
from typing import Tuple
from .ecdsa import ECCurve, ECPoint

_curve = ECCurve()


class ECElGamalKeypair:
    """EC-ElGamal keypair: private scalar x, public point Q = x·G."""

    def __init__(self):
        self.private_key = secrets.randbelow(_curve.n - 1) + 1
        self.public_key = _curve.mul(self.private_key, _curve.G)


class ECElGamalCiphertext:
    """Ciphertext pair (C1, C2) — both EC points."""

    def __init__(self, c1: ECPoint, c2: ECPoint):
        self.c1 = c1
        self.c2 = c2

    def to_dict(self) -> dict:
        return {
            'c1_x': hex(self.c1.x) if not self.c1.is_infinity else '0',
            'c2_x': hex(self.c2.x) if not self.c2.is_infinity else '0',
        }


class ECElGamalEncryption:
    """Encrypt / decrypt integer messages using EC-ElGamal."""

    def encrypt(self, message_int: int, public_key: ECPoint) -> ECElGamalCiphertext:
        """Encrypt an integer m: encode as M = m·G, then ElGamal."""
        M = _curve.mul(message_int, _curve.G)
        k = secrets.randbelow(_curve.n - 1) + 1
        C1 = _curve.mul(k, _curve.G)
        C2 = _curve.add(M, _curve.mul(k, public_key))
        return ECElGamalCiphertext(C1, C2)

    def decrypt(self, ct: ECElGamalCiphertext, private_key: int, max_val: int = 1 << 20) -> int:
        """
        Decrypt: recover M = C2 - x·C1, then brute-force m from M = m·G.
        Only practical for m < max_val.
        """
        S = _curve.mul(private_key, ct.c1)
        # -S: negate y coordinate
        neg_S = ECPoint(S.x, (_curve.p - S.y) % _curve.p, _curve)
        M = _curve.add(ct.c2, neg_S)

        # Baby-step giant-step would be faster; linear scan is fine for demo
        acc = ECPoint.infinity(_curve)
        for i in range(max_val + 1):
            if acc.is_infinity and M.is_infinity:
                return i
            if (not acc.is_infinity) and (not M.is_infinity) and acc.x == M.x and acc.y == M.y:
                return i
            acc = _curve.add(acc, _curve.G)
        raise ValueError(f"Could not decrypt — message exceeds {max_val}")


class ECElGamalHybrid:
    """
    Hybrid encryption: EC-ElGamal encrypts a random symmetric key,
    symmetric cipher (XOR for demo) encrypts the payload.
    """

    def encrypt(self, data: bytes, public_key: ECPoint) -> dict:
        sym_key_int = secrets.randbelow(_curve.n - 1) + 1
        sym_key = hashlib.sha256(sym_key_int.to_bytes(32, 'big')).digest()

        # Encrypt symmetric key with EC-ElGamal (point, not brute-force)
        k = secrets.randbelow(_curve.n - 1) + 1
        C1 = _curve.mul(k, _curve.G)
        S = _curve.mul(k, public_key)
        # Derive mask from shared point
        mask = hashlib.sha256(S.x.to_bytes(32, 'big')).digest()
        encrypted_sym = bytes(a ^ b for a, b in zip(sym_key, mask))

        # Encrypt data with symmetric key
        key_stream = (sym_key * (len(data) // 32 + 1))[:len(data)]
        encrypted_data = bytes(a ^ b for a, b in zip(data, key_stream))

        return {'C1': C1, 'encrypted_sym': encrypted_sym, 'encrypted_data': encrypted_data}

    def decrypt(self, package: dict, private_key: int) -> bytes:
        C1 = package['C1']
        S = _curve.mul(private_key, C1)
        mask = hashlib.sha256(S.x.to_bytes(32, 'big')).digest()
        sym_key = bytes(a ^ b for a, b in zip(package['encrypted_sym'], mask))

        key_stream = (sym_key * (len(package['encrypted_data']) // 32 + 1))[:len(package['encrypted_data'])]
        return bytes(a ^ b for a, b in zip(package['encrypted_data'], key_stream))
