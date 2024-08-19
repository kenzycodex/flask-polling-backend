import os
import datetime
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

# Function to log admin actions
def log_admin_action(action, ip_address):
    conn = get_db_connection('admin_actions.db')
    conn.execute(
        'CREATE TABLE IF NOT EXISTS actions (timestamp TEXT, action TEXT, ip_address TEXT)'
    )
    conn.execute(
        'INSERT INTO actions (timestamp, action, ip_address) VALUES (?, ?, ?)',
        (datetime.datetime.now().isoformat(), action, ip_address)
    )
    conn.commit()
    conn.close()

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

    # Log successful login
    log_admin_action('Admin login successful', request.remote_addr)

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
    conn_polls = get_db_connection('polls.db')  # Correct database connection

    # Fetch all user votes
    user_votes = conn_polls.execute('SELECT * FROM user_votes').fetchall()

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

    conn_polls.close()

    return jsonify({"user_votes": user_votes_data}), 200

# Admin route to view individual user details by user_id
@admin_blueprint.route('/admin/user/<string:user_id>', methods=['GET'])
def admin_view_user_details(user_id):
    conn_users = get_db_connection('users.db')

    user = conn_users.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

    conn_users.close()

    if user:
        # Log the action
        log_admin_action(f'Viewed details for user ID {user_id}', request.remote_addr)
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
        # Log the action
        log_admin_action(f'Viewed details for poll ID {poll_id}', request.remote_addr)
        return jsonify(dict(poll)), 200
    else:
        return jsonify({"error": "Poll not found"}), 404

# Admin route to activate/deactivate user by user_id
@admin_blueprint.route('/admin/user/<string:user_id>/status', methods=['PATCH'])
def admin_update_user_status(user_id):
    status = request.json.get('status')

    if status not in ['active', 'inactive']:
        abort(400, description="Invalid status. Must be 'active' or 'inactive'.")

    conn = get_db_connection('users.db')
    conn.execute(
        'UPDATE users SET status = ? WHERE id = ?',
        (status, user_id)
    )
    conn.commit()
    conn.close()

    # Log the action
    log_admin_action(f'Updated status for user ID {user_id} to {status}', request.remote_addr)

    return jsonify({"message": "User status updated successfully"}), 200

# Admin route to delete user by user_id
@admin_blueprint.route('/admin/user/<string:user_id>', methods=['DELETE'])
def admin_delete_user(user_id):
    conn = get_db_connection('users.db')
    conn.execute(
        'DELETE FROM users WHERE id = ?',
        (user_id,)
    )
    conn.commit()
    conn.close()

    # Log the action
    log_admin_action(f'Deleted user ID {user_id}', request.remote_addr)

    return jsonify({"message": "User deleted successfully"}), 200

# Admin route to get poll insights and analytics
@admin_blueprint.route('/admin/poll/analytics', methods=['GET'])
def admin_poll_analytics():
    conn_polls = get_db_connection('polls.db')  # Database connection for polls
    conn_users = get_db_connection('polls.db')  # Database connection for user_votes

    # Analytics data
    analytics = {}

    try:
        # Total votes
        total_votes_query = 'SELECT COUNT(*) FROM user_votes'
        total_votes = conn_users.execute(total_votes_query).fetchone()[0]
        analytics['total_votes'] = total_votes

        # Active vs. expired polls
        current_time = datetime.datetime.now()
        active_polls_query = 'SELECT COUNT(*) FROM polls WHERE expiry_date > ?'
        expired_polls_query = 'SELECT COUNT(*) FROM polls WHERE expiry_date <= ?'
        active_polls = conn_polls.execute(active_polls_query, (current_time,)).fetchone()[0]
        expired_polls = conn_polls.execute(expired_polls_query, (current_time,)).fetchone()[0]
        analytics['active_polls'] = active_polls
        analytics['expired_polls'] = expired_polls

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn_polls.close()
        conn_users.close()

    return jsonify(analytics), 200