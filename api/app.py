"""
REST API for Privacy-Preserving Payment System
Provides endpoints for user management and transactions
"""

import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from backend import TransactionService

app = Flask(__name__, static_folder='../frontend', static_url_path='')
CORS(app)


@app.route('/')
def serve_frontend():
    """Serve the frontend application"""
    return send_from_directory(app.static_folder, 'index.html')

# Initialize transaction service
transaction_service = TransactionService()


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'Privacy-Preserving Payment System',
        'version': '1.0.0'
    })


@app.route('/api/users', methods=['POST'])
def create_user():
    """
    Create a new user
    Body: { "name": "string", "initial_balance": number }
    """
    data = request.get_json()
    
    if not data or 'name' not in data or 'initial_balance' not in data:
        return jsonify({'error': 'Missing required fields'}), 400
    
    try:
        user = transaction_service.create_user(
            name=data['name'],
            initial_balance=int(data['initial_balance'])
        )
        
        return jsonify({
            'success': True,
            'user': user.to_dict(),
            'message': 'User created successfully'
        }), 201
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/users/<user_id>', methods=['GET'])
def get_user(user_id):
    """Get user information (without revealing actual balance)"""
    user_info = transaction_service.get_user_balance_info(user_id)
    
    if not user_info:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify(user_info)


@app.route('/api/users/<user_id>/balance', methods=['GET'])
def get_user_balance(user_id):
    """
    Get user balance commitment (for demo purposes, also returns actual balance)
    In production, actual balance would never be exposed via API
    """
    user = transaction_service.get_user(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'user_id': user.user_id,
        'name': user.name,
        'balance': user.balance,  # Only for demo
        'balance_commitment': hex(user.balance_commitment.x) if not user.balance_commitment.is_infinity else '0x0',
        'note': 'In production, actual balance would not be exposed'
    })


@app.route('/api/transactions', methods=['POST'])
def create_transaction():
    """
    Create a new transaction with ZK proof verification
    Body: {
        "sender_id": "string",
        "receiver_id": "string", 
        "amount": number
    }
    """
    data = request.get_json()
    
    required_fields = ['sender_id', 'receiver_id', 'amount']
    if not data or not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    
    try:
        result = transaction_service.initiate_transaction(
            sender_id=data['sender_id'],
            receiver_id=data['receiver_id'],
            amount=int(data['amount'])
        )
        
        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 400
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/transactions/<transaction_id>', methods=['GET'])
def get_transaction(transaction_id):
    """Get transaction details"""
    transaction = transaction_service.get_transaction(transaction_id)
    
    if not transaction:
        return jsonify({'error': 'Transaction not found'}), 404
    
    return jsonify(transaction)


@app.route('/api/users/<user_id>/transactions', methods=['GET'])
def get_user_transactions(user_id):
    """Get all transactions for a user"""
    transactions = transaction_service.get_user_transactions(user_id)
    
    return jsonify({
        'user_id': user_id,
        'transactions': transactions,
        'count': len(transactions)
    })


@app.route('/api/demo/setup', methods=['POST'])
def demo_setup():
    """
    Setup demo users for testing
    Creates sample users with initial balances
    """
    try:
        # Create demo users
        alice = transaction_service.create_user('Alice', 10000)
        bob = transaction_service.create_user('Bob', 5000)
        charlie = transaction_service.create_user('Charlie', 15000)
        
        return jsonify({
            'success': True,
            'message': 'Demo users created',
            'users': {
                'alice': alice.to_dict(),
                'bob': bob.to_dict(),
                'charlie': charlie.to_dict()
            }
        }), 201
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500



@app.route('/api/chunked-demo', methods=['POST'])
def chunked_balance_demo():
    """
    Demo: prove balance that exceeds ECC curve order (n).
    Body: { "balance_multiplier": number, "balance_offset": number, "tx_amount": number }
    balance = multiplier * n + offset
    """
    from crypto import ECBalanceProver, ECBalanceVerifier
    from crypto.ecdsa import ECCurve

    data = request.get_json() or {}
    multiplier = int(data.get('balance_multiplier', 2))
    offset = int(data.get('balance_offset', 5000))
    tx_amount = int(data.get('tx_amount', 1000))

    n = ECCurve().n
    balance = multiplier * n + offset

    try:
        prover = ECBalanceProver(balance)
        chunks = prover.chunks
        chunk_commitments = [
            hex(Q.x) if not Q.is_infinity else '0x0'
            for Q in prover.get_chunk_public_keys()
        ]
        combined = prover.get_balance_commitment()
        combined_commitment = hex(combined.x) if not combined.is_infinity else '0x0'

        reconstructed = sum(c * (n ** i) for i, c in enumerate(chunks))

        can_prove, proof = prover.prove_sufficient_balance(tx_amount)
        verifier = ECBalanceVerifier()
        valid = False
        if can_prove:
            valid = verifier.verify_balance_proof(prover.get_balance_commitment(), proof)

        return jsonify({
            'success': True,
            'n_hex': hex(n)[:20] + '...',
            'n_bits': n.bit_length(),
            'balance_hex': hex(balance)[:20] + '...',
            'balance_bits': balance.bit_length(),
            'balance_formula': f'{multiplier} × n + {offset}',
            'num_chunks': len(chunks),
            'chunks': chunks,
            'chunk_commitments': chunk_commitments,
            'combined_commitment': combined_commitment[:30] + '...',
            'reconstruction_matches': reconstructed == balance,
            'tx_amount': tx_amount,
            'can_prove': can_prove,
            'proof_valid': valid,
            'proof_num_chunks': proof.num_chunks if proof else 0,
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


from backend.secure_transaction_service import SecureTransactionService
secure_service = SecureTransactionService()


@app.route('/api/secure/setup', methods=['POST'])
def secure_setup():
    """Create demo users with full ECC key material."""
    try:
        alice = secure_service.create_user('Alice', 10000)
        bob = secure_service.create_user('Bob', 5000)
        charlie = secure_service.create_user('Charlie', 15000)
        return jsonify({
            'success': True,
            'users': {
                'alice': alice.to_dict(),
                'bob': bob.to_dict(),
                'charlie': charlie.to_dict(),
            }
        }), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/secure/transaction', methods=['POST'])
def secure_transaction():
    """Run full crypto pipeline: ECDH → encrypt → sign → ZK prove → verify → decrypt."""
    data = request.get_json()
    if not data or not all(k in data for k in ('sender_id', 'receiver_id', 'amount')):
        return jsonify({'error': 'Missing required fields'}), 400
    try:
        result = secure_service.process_secure_transaction(
            data['sender_id'], data['receiver_id'], int(data['amount']))
        return jsonify(result), 200 if result['success'] else 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/benchmark', methods=['GET'])
def run_benchmark():
    """Run ECC Schnorr ZK vs DLP-Schnorr vs DSA vs ECDSA comparison."""
    from benchmarks.comparison import run_benchmarks
    try:
        return jsonify({'success': True, 'results': run_benchmarks(as_json=True)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
