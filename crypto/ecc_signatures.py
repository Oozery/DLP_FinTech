"""
Schnorr Digital Signatures over Elliptic Curves (secp256k1)

Sign:
  Private key x, public key Q = x·G
  k = random, R = k·G
  e = H(R.x ‖ Q.x ‖ message)
  s = (k + e·x) mod n
  Signature = (R, s)

Verify:
  e = H(R.x ‖ Q.x ‖ message)
  s·G == R + e·Q

Security: Forging requires solving ECDLP on secp256k1.
"""

import hashlib
import secrets
from .ecdsa import ECCurve, ECPoint

_curve = ECCurve()


class ECSchnorrSignature:
    """Schnorr signature (R point, s scalar)."""

    def __init__(self, R: ECPoint, s: int):
        self.R = R
        self.s = s

    def to_dict(self) -> dict:
        return {
            'R_x': hex(self.R.x) if not self.R.is_infinity else '0',
            'R_y': hex(self.R.y) if not self.R.is_infinity else '0',
            's': hex(self.s),
        }


def _sig_challenge(R: ECPoint, Q: ECPoint, message: bytes) -> int:
    h = hashlib.sha256()
    h.update(R.x.to_bytes(32, 'big'))
    h.update(Q.x.to_bytes(32, 'big'))
    h.update(message)
    return int.from_bytes(h.digest(), 'big') % _curve.n


class ECSchnorrSigner:
    """Sign messages with ECC Schnorr."""

    def __init__(self, private_key: int = None):
        self.private_key = private_key or (secrets.randbelow(_curve.n - 1) + 1)
        self.public_key = _curve.mul(self.private_key, _curve.G)

    def sign(self, message: bytes) -> ECSchnorrSignature:
        k = secrets.randbelow(_curve.n - 1) + 1
        R = _curve.mul(k, _curve.G)
        e = _sig_challenge(R, self.public_key, message)
        s = (k + e * self.private_key) % _curve.n
        return ECSchnorrSignature(R, s)


class ECSchnorrSigVerifier:
    """Verify ECC Schnorr signatures."""

    def verify(self, message: bytes, sig: ECSchnorrSignature, public_key: ECPoint) -> bool:
        e = _sig_challenge(sig.R, public_key, message)
        lhs = _curve.mul(sig.s, _curve.G)
        rhs = _curve.add(sig.R, _curve.mul(e, public_key))
        if lhs.is_infinity or rhs.is_infinity:
            return False
        return lhs.x == rhs.x and lhs.y == rhs.y


class ECTransactionSigner:
    """Sign transaction data (sender|receiver|amount|timestamp)."""

    def __init__(self, private_key: int = None):
        self._signer = ECSchnorrSigner(private_key)

    @property
    def public_key(self) -> ECPoint:
        return self._signer.public_key

    def sign_transaction(self, sender: str, receiver: str, amount: int, timestamp: str) -> ECSchnorrSignature:
        msg = f"{sender}|{receiver}|{amount}|{timestamp}".encode()
        return self._signer.sign(msg)


class ECTransactionVerifier:
    """Verify signed transactions."""

    def __init__(self):
        self._verifier = ECSchnorrSigVerifier()

    def verify_transaction(self, sender: str, receiver: str, amount: int,
                           timestamp: str, sig: ECSchnorrSignature,
                           public_key: ECPoint) -> bool:
        msg = f"{sender}|{receiver}|{amount}|{timestamp}".encode()
        return self._verifier.verify(msg, sig, public_key)
