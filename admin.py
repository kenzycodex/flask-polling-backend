import os
from flask import Blueprint, jsonify, request, abort
from werkzeug.security import check_password_hash
from flask_jwt_extended import jwt_required
from dotenv import load_dotenv
import sqlite3

# Load environment variables
load_dotenv()

# Create a Blueprint for admin operations
admin_blueprint = Blueprint('admin', __name__)

# Function to connect to the database
def get_db_connection(db_name):
    conn = sqlite3.connect(db_name)
    conn.row_factory = sqlite3.Row
    return conn

# Admin login and operations route
@admin_blueprint.route('/admin', methods=['POST'])
def admin_login():
    admin_key = os.getenv('ADMIN_KEY')
    admin_password_hash = os.getenv('ADMIN_PASSWORD_HASH')

    data = request.get_json()
    key = data.get('key')
    password = data.get('password')

    if not key or not password:
        abort(401, description="Admin key and password are required")

    if key != admin_key or not check_password_hash(admin_password_hash, password):
        abort(403, description="Invalid admin key or password")

    # Connect to users and polls databases
    conn_users = get_db_connection('users.db')
    conn_polls = get_db_connection('polls.db')

    # Fetch data from the respective tables
    users = conn_users.execute('SELECT * FROM users').fetchall()
    polls = conn_polls.execute('SELECT * FROM polls').fetchall()

    # Close both connections
    conn_users.close()
    conn_polls.close()

    # Return data as JSON
    return jsonify({
        "users": [dict(user) for user in users],
        "polls": [dict(poll) for poll in polls]
    }), 200

# Admin route to view user votes
@admin_blueprint.route('/admin/user_votes', methods=['GET'])
def admin_view_user_votes():
    conn_users = get_db_connection('users.db')
    conn_polls = get_db_connection('polls.db')

    # Fetch all user votes
    user_votes = conn_users.execute('SELECT * FROM user_votes').fetchall()

    # Format response
    user_votes_data = []
    for vote in user_votes:
        poll = conn_polls.execute('SELECT * FROM polls WHERE id = ?', (vote['poll_id'],)).fetchone()
        if poll:
            user_votes_data.append({
                "user_id": vote['user_id'],
                "poll_id": vote['poll_id'],
                "poll_question": poll['question']
            })

    conn_users.close()
    conn_polls.close()

    return jsonify({"user_votes": user_votes_data}), 200

# Admin route to view individual user details by user_id
@admin_blueprint.route('/admin/user/<string:user_id>', methods=['GET'])
def admin_view_user_details(user_id):
    conn_users = get_db_connection('users.db')

    user = conn_users.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

    conn_users.close()

    if user:
        return jsonify(dict(user)), 200
    else:
        return jsonify({"error": "User not found"}), 404

# Admin route to view individual poll details by poll_id
@admin_blueprint.route('/admin/poll/<int:poll_id>', methods=['GET'])
def admin_view_poll_details(poll_id):
    conn_polls = get_db_connection('polls.db')

    poll = conn_polls.execute('SELECT * FROM polls WHERE id = ?', (poll_id,)).fetchone()

    conn_polls.close()

    if poll:
        return jsonify(dict(poll)), 200
    else:
        return jsonify({"error": "Poll not found"}), 404