import os
from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
from flask_jwt_extended import jwt_required, get_jwt_identity
import pymysql.cursors
from pymysql import MySQLError

poll_expiry_blueprint = Blueprint('poll_expiry', __name__)

# Connect to the MySQL database
def get_db_connection():
    try:
        conn = pymysql.connect(
            host=os.getenv('MYSQL_HOST'),
            user=os.getenv('MYSQL_USER'),
            password=os.getenv('MYSQL_PASSWORD'),
            database=os.getenv('MYSQL_DATABASE'),
            port=int(os.getenv('MYSQL_PORT')),  
            cursorclass=pymysql.cursors.DictCursor
        )
        return conn
    except MySQLError as e:
        print(f"Error connecting to MySQL: {e}")
        raise

# Create the polls table if it doesn't exist
def create_polls_table():
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS polls (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            question TEXT NOT NULL,
                            options TEXT NOT NULL,
                            votes TEXT NOT NULL,
                            expiry DATETIME NOT NULL,
                            created_by VARCHAR(255) NOT NULL,
                            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                            UNIQUE KEY(question(255), created_by))''')  # Specified length for TEXT column
        cursor.execute('''CREATE TABLE IF NOT EXISTS user_votes (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            user_id VARCHAR(255) NOT NULL,
                            poll_id INT NOT NULL,
                            UNIQUE(user_id, poll_id),
                            FOREIGN KEY (poll_id) REFERENCES polls(id) ON DELETE CASCADE)''')
        conn.commit()
    except MySQLError as e:
        print(f"Error creating tables: {e}")
    finally:
        if cursor:
            cursor.close()
        if conn:
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
        cursor = conn.cursor()
        try:
            # Check if a poll with the same question and creator already exists
            cursor.execute('''SELECT * FROM polls 
                              WHERE question = %s AND created_by = %s''',
                           (question, current_user))
            existing_poll = cursor.fetchone()
            if existing_poll:
                return jsonify({"error": "Poll already exists"}), 409

            # Insert poll into the database
            cursor.execute('''INSERT INTO polls (question, options, votes, expiry, created_by, created_at) 
                              VALUES (%s, %s, %s, %s, %s, %s)''',
                           (question, options_str, votes_str, expiry.isoformat(), current_user, datetime.utcnow()))
            conn.commit()
            return jsonify({"message": "Poll created"}), 201
        except MySQLError as e:
            conn.rollback()
            return jsonify({"error": str(e)}), 500
        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        return jsonify({"error": "Invalid input", "details": str(e)}), 400

@poll_expiry_blueprint.route('/vote/<int:poll_id>/<int:option_index>', methods=['POST'])
@jwt_required()
def vote(poll_id, option_index):
    user_id = get_jwt_identity()
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Check if the user has already voted in this poll
        cursor.execute("SELECT * FROM user_votes WHERE user_id = %s AND poll_id = %s", (user_id, poll_id))
        existing_vote = cursor.fetchone()
        if existing_vote:
            return jsonify({"error": "You have already voted in this poll"}), 400
        
        # Retrieve poll data
        cursor.execute("SELECT * FROM polls WHERE id = %s", (poll_id,))
        poll = cursor.fetchone()
        if not poll:
            return jsonify({"error": "Poll not found"}), 404

        # Check if the poll has expired
        if poll['expiry'] < datetime.utcnow():
            return jsonify({"error": "Poll has expired"}), 403
        
        options = poll['options'].split(',')
        votes = list(map(int, poll['votes'].split(',')))

        if not (0 <= option_index < len(options)):
            return jsonify({"error": "Invalid option index"}), 400

        votes[option_index] += 1
        votes_str = ','.join(map(str, votes))

        # Update poll votes and record user's vote
        cursor.execute("UPDATE polls SET votes = %s WHERE id = %s", (votes_str, poll_id))
        cursor.execute("INSERT INTO user_votes (user_id, poll_id) VALUES (%s, %s)", (user_id, poll_id))
        conn.commit()

        return jsonify({"message": "Vote recorded", "poll": {
            'id': poll['id'],
            'question': poll['question'],
            'options': options,
            'votes': votes,
            'expiry': poll['expiry'],
            'created_by': poll['created_by'],
            'created_at': poll['created_at']
        }}), 200

    except MySQLError as e:
        conn.rollback()
        return jsonify({"error": "An error occurred", "details": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@poll_expiry_blueprint.route('/polls', methods=['GET'])
def get_polls():
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM polls")
        polls = cursor.fetchall()
        
        polls_list = [{
            'id': poll['id'],
            'question': poll['question'],
            'options': poll['options'].split(','),
            'votes': list(map(int, poll['votes'].split(','))),
            'expiry': poll['expiry'],
            'created_by': poll['created_by'],
            'created_at': poll['created_at']
        } for poll in polls]
        
        return jsonify({"polls": polls_list}), 200
    except MySQLError as e:
        return jsonify({"error": "An error occurred", "details": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@poll_expiry_blueprint.route('/polls/<int:poll_id>', methods=['GET'])
def get_poll(poll_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM polls WHERE id = %s", (poll_id,))
        poll = cursor.fetchone()

        if poll:
            return jsonify({
                'id': poll['id'],
                'question': poll['question'],
                'options': poll['options'].split(','),
                'votes': list(map(int, poll['votes'].split(','))),
                'expiry': poll['expiry'],
                'created_by': poll['created_by'],
                'created_at': poll['created_at']
            }), 200
        
        return jsonify({"error": "Poll not found"}), 404
    except MySQLError as e:
        return jsonify({"error": "An error occurred", "details": str(e)}), 500
    finally:
        cursor.close()
        conn.close()