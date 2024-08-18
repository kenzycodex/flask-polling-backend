from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
from flask_jwt_extended import jwt_required, get_jwt_identity
import sqlite3

poll_expiry_blueprint = Blueprint('poll_expiry', __name__)

# Connect to the SQLite database
def get_db_connection():
    conn = sqlite3.connect('polls.db')
    conn.row_factory = sqlite3.Row
    return conn

# Create the polls table if it doesn't exist
def create_polls_table():
    conn = get_db_connection()
    conn.execute('''CREATE TABLE IF NOT EXISTS polls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    question TEXT NOT NULL,
                    options TEXT NOT NULL,
                    votes TEXT NOT NULL,
                    expiry DATETIME NOT NULL,
                    created_by TEXT NOT NULL,
                    UNIQUE(question, created_by))''')
    conn.commit()
    conn.close()

# Ensure the table is created when the app starts
create_polls_table()

@poll_expiry_blueprint.route('/create_poll', methods=['POST'])
@jwt_required()
def create_poll():
    try:
        data = request.get_json()
        current_user = get_jwt_identity()

        # Validate incoming data
        question = data.get('question')
        options = data.get('options')
        days_until_expiry = data.get('days_until_expiry')

        if not question or not options:
            return jsonify({"error": "Question and options are required"}), 400
        if not isinstance(options, list) or len(options) < 2:
            return jsonify({"error": "Options must be a list with at least two items"}), 400
        if not isinstance(days_until_expiry, (int, float)) or days_until_expiry <= 0:
            return jsonify({"error": "Expiry must be a positive number"}), 400

        # Calculate expiry time
        expiry = datetime.utcnow() + timedelta(days=float(days_until_expiry))

        options_str = ','.join(options)
        votes_str = ','.join(['0'] * len(options))

        conn = get_db_connection()
        try:
            # Check if a poll with the same question and creator already exists
            existing_poll = conn.execute('''SELECT * FROM polls 
                                           WHERE question = ? AND created_by = ?''',
                                        (question, current_user)).fetchone()
            if existing_poll:
                conn.close()
                return jsonify({"error": "Poll already exists"}), 409
            
            # Insert poll into the database
            conn.execute('''INSERT INTO polls (question, options, votes, expiry, created_by) 
                            VALUES (?, ?, ?, ?, ?)''', 
                         (question, options_str, votes_str, expiry.isoformat(), current_user))
            conn.commit()
            return jsonify({"message": "Poll created"}), 201
        except Exception as e:
            conn.rollback()
            return jsonify({"error": str(e)}), 500
        finally:
            conn.close()

    except Exception as e:
        return jsonify({"error": "Invalid input", "details": str(e)}), 400

@poll_expiry_blueprint.route('/vote/<int:poll_id>/<int:option_index>', methods=['POST'])
@jwt_required()
def vote(poll_id, option_index):
    user_id = get_jwt_identity()
    conn = get_db_connection()
    
    try:
        conn.execute('BEGIN TRANSACTION')
        
        # Check if the user has already voted in this poll
        existing_vote = conn.execute("SELECT * FROM user_votes WHERE user_id = ? AND poll_id = ?", (user_id, poll_id)).fetchone()
        if existing_vote:
            conn.execute('ROLLBACK')
            conn.close()
            return jsonify({"error": "You have already voted in this poll"}), 400
        
        # Retrieve poll data
        poll = conn.execute("SELECT * FROM polls WHERE id = ?", (poll_id,)).fetchone()
        if not poll:
            conn.execute('ROLLBACK')
            conn.close()
            return jsonify({"error": "Poll not found"}), 404

        # Check if the poll has expired
        if datetime.fromisoformat(poll['expiry']) < datetime.utcnow():
            conn.execute('ROLLBACK')
            conn.close()
            return jsonify({"error": "Poll has expired"}), 403
        
        options = poll['options'].split(',')
        votes = list(map(int, poll['votes'].split(',')))

        if not (0 <= option_index < len(options)):
            conn.execute('ROLLBACK')
            conn.close()
            return jsonify({"error": "Invalid option index"}), 400

        votes[option_index] += 1
        votes_str = ','.join(map(str, votes))

        # Update poll votes and record user's vote
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

@poll_expiry_blueprint.route('/polls', methods=['GET'])
def get_polls():
    conn = get_db_connection()
    polls = conn.execute("SELECT * FROM polls").fetchall()
    conn.close()
    
    polls_list = [{
        'id': poll['id'],
        'question': poll['question'],
        'options': poll['options'].split(','),
        'votes': list(map(int, poll['votes'].split(','))),
        'expiry': poll['expiry'],
        'created_by': poll['created_by']
    } for poll in polls]
    
    return jsonify({"polls": polls_list}), 200

@poll_expiry_blueprint.route('/polls/<int:poll_id>', methods=['GET'])
def get_poll(poll_id):
    conn = get_db_connection()
    poll = conn.execute("SELECT * FROM polls WHERE id = ?", (poll_id,)).fetchone()
    conn.close()

    if poll:
        return jsonify({
            'id': poll['id'],
            'question': poll['question'],
            'options': poll['options'].split(','),
            'votes': list(map(int, poll['votes'].split(','))),
            'expiry': poll['expiry'],
            'created_by': poll['created_by']
        }), 200
    
    return jsonify({"error": "Poll not found"}), 404