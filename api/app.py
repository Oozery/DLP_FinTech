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
        'balance_commitment': hex(user.balance_commitment),
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


@app.route('/api/benchmark', methods=['GET'])
def run_benchmark():
    """Run Schnorr vs DSA vs ECDSA benchmark"""
    try:
        from benchmarks.comparison import run_benchmarks
        results = run_benchmarks(as_json=True)
        return jsonify({'success': True, 'results': results})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/chunked-demo', methods=['POST'])
def chunked_balance_demo():
    """
    Demo: prove balance that exceeds DLP subgroup order (q).
    Body: { "balance_multiplier": number, "balance_offset": number, "tx_amount": number }
    balance = multiplier * q + offset
    """
    from crypto import DLPParameters, BalanceProver, BalanceVerifier

    data = request.get_json() or {}
    multiplier = int(data.get('balance_multiplier', 2))
    offset = int(data.get('balance_offset', 5000))
    tx_amount = int(data.get('tx_amount', 1000))

    _, _, q = DLPParameters.get_parameters()
    balance = multiplier * q + offset

    try:
        prover = BalanceProver(balance)
        chunks = prover.chunks
        chunk_commitments = [hex(c) for c in prover.get_chunk_commitments()]
        combined_commitment = hex(prover.get_balance_commitment())

        # Reconstruct to prove correctness
        reconstructed = sum(c * (q ** i) for i, c in enumerate(chunks))

        # Generate and verify proof
        can_prove, proof = prover.prove_sufficient_balance(tx_amount)
        verifier = BalanceVerifier()
        valid = False
        if can_prove:
            valid = verifier.verify_balance_proof(
                prover.get_balance_commitment(), proof,
                chunk_commitments=prover.get_chunk_commitments())

        return jsonify({
            'success': True,
            'q_hex': hex(q)[:20] + '...',
            'q_bits': q.bit_length(),
            'balance_hex': hex(balance)[:20] + '...',
            'balance_bits': balance.bit_length(),
            'balance_formula': f'{multiplier} × q + {offset}',
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


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
