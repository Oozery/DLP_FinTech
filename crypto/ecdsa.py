"""
ECDSA (Elliptic Curve Digital Signature Algorithm) Implementation
Based on ECDLP — the elliptic curve variant of DLP

Uses secp256k1 curve parameters (same curve as Bitcoin).
More complex than Schnorr due to elliptic curve point arithmetic.
"""

import hashlib
import secrets


class ECPoint:
    """Point on an elliptic curve"""
    def __init__(self, x, y, curve):
        self.x, self.y, self.curve = x, y, curve
        self.is_infinity = x is None

    @staticmethod
    def infinity(curve):
        pt = ECPoint(None, None, curve)
        pt.is_infinity = True
        return pt


class ECCurve:
    """secp256k1 elliptic curve: y^2 = x^3 + 7 mod p"""
    def __init__(self):
        self.p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        self.a, self.b = 0, 7
        self.n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        self.G = ECPoint(
            0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
            0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
            self)

    def add(self, P, Q):
        """Elliptic curve point addition"""
        if P.is_infinity: return Q
        if Q.is_infinity: return P
        if P.x == Q.x and P.y != Q.y: return ECPoint.infinity(self)
        if P.x == Q.x:
            lam = (3 * P.x * P.x + self.a) * pow(2 * P.y, self.p - 2, self.p) % self.p
        else:
            lam = (Q.y - P.y) * pow(Q.x - P.x, self.p - 2, self.p) % self.p
        x3 = (lam * lam - P.x - Q.x) % self.p
        y3 = (lam * (P.x - x3) - P.y) % self.p
        return ECPoint(x3, y3, self)

    def mul(self, k, P):
        """Scalar multiplication via double-and-add"""
        R, A = ECPoint.infinity(self), P
        while k > 0:
            if k & 1: R = self.add(R, A)
            A = self.add(A, A)
            k >>= 1
        return R


class ECDSASigner:
    def __init__(self):
        self.curve = ECCurve()
        self.private_key = secrets.randbelow(self.curve.n - 1) + 1
        self.public_key = self.curve.mul(self.private_key, self.curve.G)

    def sign(self, message: bytes) -> tuple:
        h = int.from_bytes(hashlib.sha256(message).digest(), 'big') % self.curve.n
        while True:
            k = secrets.randbelow(self.curve.n - 1) + 1
            R = self.curve.mul(k, self.curve.G)
            r = R.x % self.curve.n
            if r == 0: continue
            s = (pow(k, self.curve.n - 2, self.curve.n) * (h + self.private_key * r)) % self.curve.n
            if s == 0: continue
            return r, s

    def get_public_key(self):
        return self.public_key


class ECDSAVerifier:
    def __init__(self):
        self.curve = ECCurve()

    def verify(self, message: bytes, signature: tuple, public_key) -> bool:
        r, s = signature
        h = int.from_bytes(hashlib.sha256(message).digest(), 'big') % self.curve.n
        s_inv = pow(s, self.curve.n - 2, self.curve.n)
        u1, u2 = (h * s_inv) % self.curve.n, (r * s_inv) % self.curve.n
        P = self.curve.add(
            self.curve.mul(u1, self.curve.G),
            self.curve.mul(u2, public_key))
        if P.is_infinity: return False
        return P.x % self.curve.n == r
