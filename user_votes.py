from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
import sqlite3
from datetime import datetime

user_votes_blueprint = Blueprint('user_votes', __name__)

# Connect to the SQLite database
def get_db_connection():
    conn = sqlite3.connect('polls.db')
    conn.row_factory = sqlite3.Row
    return conn

# Create the user_votes table if it doesn't exist
def create_user_votes_table():
    conn = get_db_connection()
    conn.execute('''CREATE TABLE IF NOT EXISTS user_votes (
                    user_id TEXT NOT NULL,
                    poll_id INTEGER NOT NULL,
                    PRIMARY KEY (user_id, poll_id),
                    FOREIGN KEY (poll_id) REFERENCES polls (id))''')
    conn.commit()
    conn.close()

# Ensure the table is created when the app starts
create_user_votes_table()

# Helper function to decode token and get user_id
def decode_token():
    return get_jwt_identity()

# Vote Route
@user_votes_blueprint.route('/vote/<int:poll_id>/<int:option_index>', methods=['POST'])
@jwt_required()
def vote(poll_id, option_index):
    user_id = decode_token()
    conn = get_db_connection()
    
    try:
        conn.execute('BEGIN TRANSACTION')
        
        # Check if the user has already voted in this poll
        existing_vote = conn.execute("SELECT * FROM user_votes WHERE user_id = ? AND poll_id = ?", (user_id, poll_id)).fetchone()
        if existing_vote:
            conn.execute('ROLLBACK')
            return jsonify({"error": "You have already voted in this poll"}), 400
        
        # Retrieve poll data
        poll = conn.execute("SELECT * FROM polls WHERE id = ?", (poll_id,)).fetchone()
        if not poll:
            conn.execute('ROLLBACK')
            return jsonify({"error": "Poll not found"}), 404

        if datetime.fromisoformat(poll['expiry']) < datetime.utcnow():
            conn.execute('ROLLBACK')
            return jsonify({"error": "Poll has expired"}), 403
        
        options = poll['options'].split(',')
        votes = list(map(int, poll['votes'].split(',')))

        if not (0 <= option_index < len(options)):
            conn.execute('ROLLBACK')
            return jsonify({"error": "Invalid option index"}), 400

        votes[option_index] += 1
        votes_str = ','.join(map(str, votes))

        conn.execute("UPDATE polls SET votes = ? WHERE id = ?", (votes_str, poll_id))
        conn.execute("INSERT INTO user_votes (user_id, poll_id) VALUES (?, ?)", (user_id, poll_id))
        conn.execute('COMMIT')
        return jsonify({"message": "Vote recorded", "poll": {
            'id': poll['id'],
            'question': poll['question'],
            'options': options,
            'votes': votes,
            'expiry': poll['expiry'],
            'created_by': poll['created_by']
        }}), 200

    except Exception as e:
        conn.execute('ROLLBACK')
        return jsonify({"error": "An error occurred", "details": str(e)}), 500
    finally:
        conn.close()

# Retrieve User Votes
@user_votes_blueprint.route('/my_votes', methods=['GET'])
@jwt_required()
def my_votes():
    user_id = decode_token()
    conn = get_db_connection()
    user_votes = conn.execute("SELECT poll_id FROM user_votes WHERE user_id = ?", (user_id,)).fetchall()
    conn.close()

    return jsonify({"polls_voted": [vote['poll_id'] for vote in user_votes]}), 200