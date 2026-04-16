"""
Elliptic Curve Diffie-Hellman (ECDH) Key Exchange on secp256k1

Protocol:
  Alice: a (secret), A = a·G (public)
  Bob:   b (secret), B = b·G (public)
  Shared secret: S = a·B = b·A = ab·G  (same point)
  Session key:   SHA-256(S.x)

Security: Computing ab·G from A and B requires solving ECDHP.
"""

import hashlib
import secrets
from .ecdsa import ECCurve, ECPoint

_curve = ECCurve()


class ECDHParty:
    """One party in an ECDH key exchange."""

    def __init__(self, name: str = ""):
        self.name = name
        self.private_key = secrets.randbelow(_curve.n - 1) + 1
        self.public_key = _curve.mul(self.private_key, _curve.G)
        self.shared_secret = None
        self.session_key = None

    def compute_shared_secret(self, other_public: ECPoint) -> ECPoint:
        self.shared_secret = _curve.mul(self.private_key, other_public)
        self.session_key = hashlib.sha256(
            self.shared_secret.x.to_bytes(32, 'big')
        ).digest()
        return self.shared_secret

    def get_session_key(self) -> bytes:
        if self.session_key is None:
            raise ValueError("Shared secret not computed yet")
        return self.session_key


class ECDHKeyExchange:
    """Perform a full ECDH exchange between two parties."""

    def __init__(self, name_a: str = "Alice", name_b: str = "Bob"):
        self.party_a = ECDHParty(name_a)
        self.party_b = ECDHParty(name_b)

    def exchange(self) -> bytes:
        """Run key exchange, return the shared session key."""
        self.party_a.compute_shared_secret(self.party_b.public_key)
        self.party_b.compute_shared_secret(self.party_a.public_key)
        assert self.party_a.session_key == self.party_b.session_key
        return self.party_a.session_key
