"""
Digital Signature Algorithm (DSA) Implementation
Based on DLP, but more complex than Schnorr

Used for benchmark comparison against Schnorr.
DSA requires modular inverse during signing — extra overhead.
"""

import hashlib
import secrets
from .dlp_core import DLPParameters, mod_exp


class DSASigner:
    def __init__(self):
        p, _, _ = DLPParameters.get_parameters()
        self.q = (p - 1) // 2
        self.p = p
        self.g = mod_exp(3, 2, self.p)
        self.private_key = secrets.randbelow(self.q - 1) + 1
        self.public_key = mod_exp(self.g, self.private_key, self.p)

    def sign(self, message: bytes) -> tuple:
        while True:
            k = secrets.randbelow(self.q - 1) + 1
            r = mod_exp(self.g, k, self.p) % self.q
            if r == 0: continue
            h = int.from_bytes(hashlib.sha256(message).digest(), 'big') % self.q or 1
            k_inv = pow(k, self.q - 2, self.q)
            s = (k_inv * (h + self.private_key * r)) % self.q
            if s == 0: continue
            return r, s

    def get_public_key(self):
        return self.public_key

    def get_params(self):
        return self.p, self.g, self.q


class DSAVerifier:
    def __init__(self, p, g, q):
        self.p, self.g, self.q = p, g, q

    def verify(self, message: bytes, signature: tuple, public_key: int) -> bool:
        r, s = signature
        if not (0 < r < self.q and 0 < s < self.q): return False
        h = int.from_bytes(hashlib.sha256(message).digest(), 'big') % self.q
        w = pow(s, self.q - 2, self.q)
        u1, u2 = (h * w) % self.q, (r * w) % self.q
        v = (mod_exp(self.g, u1, self.p) * mod_exp(public_key, u2, self.p)) % self.p % self.q
        return v == r
