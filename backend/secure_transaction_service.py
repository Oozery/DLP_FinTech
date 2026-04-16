"""
Secure Transaction Service — Full ECC Crypto Pipeline

Transaction flow:
  1. ECDH key exchange  → sender & receiver establish shared session key
  2. EC-ElGamal encrypt → transaction data encrypted with receiver's public key
  3. ECC Schnorr sign   → sender signs the transaction for non-repudiation
  4. ECC Schnorr ZK     → sender proves sufficient balance without revealing it
  5. Verify signature   → receiver/server verifies sender's signature
  6. Verify ZK proof    → server verifies balance proof
  7. Decrypt            → receiver decrypts transaction data

All operations use secp256k1 scalar multiplication.
"""

import json
import uuid
from datetime import datetime
from typing import Dict, Optional

from crypto.ecc_diffie_hellman import ECDHParty
from crypto.ecc_elgamal import ECElGamalKeypair, ECElGamalHybrid
from crypto.ecc_signatures import ECTransactionSigner, ECTransactionVerifier
from crypto.ecc_schnorr import ECBalanceProver, ECBalanceVerifier


class SecureUser:
    """User with full ECC key material."""

    def __init__(self, user_id: str, name: str, balance: int):
        if balance < 0:
            raise ValueError("Balance cannot be negative")
        self.user_id = user_id
        self.name = name
        self.balance = balance

        # ECDH identity (for key exchange)
        self.ecdh = ECDHParty(name)
        # EC-ElGamal keypair (for encryption)
        self.encryption_keys = ECElGamalKeypair()
        # ECC Schnorr signing key (for signatures)
        self.tx_signer = ECTransactionSigner()
        # ECC Schnorr ZK prover (for balance proofs)
        self._refresh_prover()

    def _refresh_prover(self):
        self.prover = ECBalanceProver(self.balance)
        self.balance_commitment = self.prover.get_balance_commitment()

    def update_balance(self, delta: int):
        new = self.balance + delta
        if new < 0:
            raise ValueError("Balance cannot go negative")
        self.balance = new
        self._refresh_prover()

    def to_dict(self) -> dict:
        return {
            'user_id': self.user_id,
            'name': self.name,
            'balance': self.balance,
            'balance_commitment': hex(self.balance_commitment.x) if not self.balance_commitment.is_infinity else '0x0',
            'encryption_pub': hex(self.encryption_keys.public_key.x)[:24] + '...',
            'signing_pub': hex(self.tx_signer.public_key.x)[:24] + '...',
        }


class SecureTransactionService:
    """Full pipeline: ECDH → encrypt → sign → ZK prove → verify → decrypt."""

    def __init__(self):
        self.users: Dict[str, SecureUser] = {}
        self.transactions = {}
        self._sig_verifier = ECTransactionVerifier()
        self._balance_verifier = ECBalanceVerifier()
        self._hybrid = ECElGamalHybrid()

    def create_user(self, name: str, balance: int) -> SecureUser:
        uid = str(uuid.uuid4())
        user = SecureUser(uid, name, balance)
        self.users[uid] = user
        return user

    def get_user(self, uid: str) -> Optional[SecureUser]:
        return self.users.get(uid)

    def process_secure_transaction(self, sender_id: str, receiver_id: str, amount: int) -> dict:
        sender = self.users.get(sender_id)
        receiver = self.users.get(receiver_id)
        if not sender or not receiver:
            return {'success': False, 'error': 'Invalid sender or receiver'}
        if amount <= 0:
            return {'success': False, 'error': 'Invalid amount'}

        tx_id = str(uuid.uuid4())
        ts = datetime.now().isoformat()
        steps = []

        # ── Step 1: ECDH key exchange ──
        sender_ecdh = ECDHParty(sender.name)
        receiver_ecdh = ECDHParty(receiver.name)
        sender_ecdh.compute_shared_secret(receiver_ecdh.public_key)
        receiver_ecdh.compute_shared_secret(sender_ecdh.public_key)
        session_key = sender_ecdh.get_session_key()
        steps.append({
            'step': 1, 'name': 'ECDH Key Exchange',
            'detail': f'Session key established ({len(session_key)*8}-bit)',
            'session_key_preview': session_key.hex()[:16] + '...',
        })

        # ── Step 2: Encrypt transaction data with EC-ElGamal hybrid ──
        tx_data = json.dumps({
            'sender': sender_id, 'receiver': receiver_id,
            'amount': amount, 'timestamp': ts,
        }).encode()
        encrypted = self._hybrid.encrypt(tx_data, receiver.encryption_keys.public_key)
        steps.append({
            'step': 2, 'name': 'EC-ElGamal Encryption',
            'detail': f'Transaction data encrypted ({len(tx_data)} bytes → {len(encrypted["encrypted_data"])} bytes)',
            'encrypted_preview': encrypted['encrypted_data'][:16].hex() + '...',
        })

        # ── Step 3: Sender signs the transaction ──
        signature = sender.tx_signer.sign_transaction(sender_id, receiver_id, amount, ts)
        steps.append({
            'step': 3, 'name': 'ECC Schnorr Signature',
            'detail': 'Sender signed transaction for non-repudiation',
            'signature': signature.to_dict(),
        })

        # ── Step 4: ZK proof of sufficient balance ──
        can_prove, zk_proof = sender.prover.prove_sufficient_balance(amount)
        if not can_prove:
            steps.append({'step': 4, 'name': 'ZK Balance Proof', 'detail': 'FAILED — insufficient balance'})
            return {'success': False, 'error': 'Insufficient balance', 'steps': steps}
        steps.append({
            'step': 4, 'name': 'ZK Balance Proof',
            'detail': f'Proved balance ≥ ₹{amount} without revealing it ({zk_proof.num_chunks} chunk(s))',
            'proof': zk_proof.to_dict(),
        })

        # ── Step 5: Verify signature ──
        sig_valid = self._sig_verifier.verify_transaction(
            sender_id, receiver_id, amount, ts, signature, sender.tx_signer.public_key)
        steps.append({
            'step': 5, 'name': 'Signature Verification',
            'detail': 'VALID' if sig_valid else 'INVALID',
            'valid': sig_valid,
        })
        if not sig_valid:
            return {'success': False, 'error': 'Invalid signature', 'steps': steps}

        # ── Step 6: Verify ZK proof ──
        zk_valid = self._balance_verifier.verify_balance_proof(sender.balance_commitment, zk_proof)
        steps.append({
            'step': 6, 'name': 'ZK Proof Verification',
            'detail': 'VALID' if zk_valid else 'INVALID',
            'valid': zk_valid,
        })
        if not zk_valid:
            return {'success': False, 'error': 'Invalid balance proof', 'steps': steps}

        # ── Step 7: Decrypt (receiver side) ──
        decrypted = self._hybrid.decrypt(encrypted, receiver.encryption_keys.private_key)
        decrypted_data = json.loads(decrypted.decode())
        steps.append({
            'step': 7, 'name': 'EC-ElGamal Decryption',
            'detail': f'Receiver decrypted transaction: ₹{decrypted_data["amount"]}',
            'decrypted_amount': decrypted_data['amount'],
        })

        # ── Execute transfer ──
        sender.update_balance(-amount)
        receiver.update_balance(amount)

        result = {
            'success': True,
            'transaction_id': tx_id,
            'timestamp': ts,
            'amount': amount,
            'sender': sender.to_dict(),
            'receiver': receiver.to_dict(),
            'steps': steps,
        }
        self.transactions[tx_id] = result
        return result
