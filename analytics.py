from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime
import sqlite3

analytics_blueprint = Blueprint('analytics', __name__)

# Connect to the SQLite database
def get_db_connection():
    conn = sqlite3.connect('polls.db')
    conn.row_factory = sqlite3.Row
    return conn

@analytics_blueprint.route('/poll/analytics/<int:poll_id>', methods=['GET'])
@jwt_required()
def poll_analytics(poll_id):
    conn = get_db_connection()
    current_user = get_jwt_identity()
    
    try:
        # Retrieve poll data
        poll = conn.execute("SELECT * FROM polls WHERE id = ?", (poll_id,)).fetchone()
        if not poll:
            return jsonify({"error": "Poll not found"}), 404

        # Check if the poll has expired
        if datetime.fromisoformat(poll['expiry']) < datetime.utcnow():
            return jsonify({"error": "Poll has expired"}), 403

        options = poll['options'].split(',')
        votes = list(map(int, poll['votes'].split(',')))
        total_votes = sum(votes)

        # Calculate analytics
        analytics = {
            'total_votes': total_votes,
            'options': [
                {
                    'option': option,
                    'votes': vote,
                    'percentage': round((vote / total_votes) * 100, 2) if total_votes > 0 else 0
                }
                for option, vote in zip(options, votes)
            ],
            'created_at': poll['created_at'],
            'expiry': poll['expiry'],
            'status': 'active' if poll['expiry'] > datetime.utcnow().isoformat() else 'expired',
            'created_by': poll['created_by']
        }

        return jsonify({"analytics": analytics}), 200

    except Exception as e:
        return jsonify({"error": "An error occurred", "details": str(e)}), 500
    finally:
        conn.close()