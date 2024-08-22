import os
from flask import Blueprint, jsonify
from datetime import datetime
import pymysql.cursors
from pymysql import MySQLError

analytics_blueprint = Blueprint('analytics', __name__)

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

@analytics_blueprint.route('/polls/analytics/votes', methods=['GET'])
def get_votes_analytics():
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('''SELECT p.id, p.question, p.options, p.votes
                          FROM polls p''')
        polls = cursor.fetchall()
        
        analytics = []
        for poll in polls:
            votes = list(map(int, poll['votes'].split(',')))
            total_votes = sum(votes)
            options = poll['options'].split(',')
            analytics.append({
                'poll_id': poll['id'],
                'question': poll['question'],
                'total_votes': total_votes,
                'options': [{'option': options[i], 'votes': votes[i]} for i in range(len(options))]
            })
        
        return jsonify({"votes_analytics": analytics}), 200
    
    except MySQLError as e:
        return jsonify({"error": "An error occurred", "details": str(e)}), 500
    
    finally:
        cursor.close()
        conn.close()

@analytics_blueprint.route('/polls/analytics/users', methods=['GET'])
def get_users_analytics():
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('''SELECT uv.user_id, COUNT(*) as vote_count
                          FROM user_votes uv
                          JOIN polls p ON uv.poll_id = p.id
                          WHERE p.expiry >= %s
                          GROUP BY uv.user_id''', (datetime.utcnow(),))
        user_votes = cursor.fetchall()
        
        return jsonify({"user_votes_analytics": user_votes}), 200

    except MySQLError as e:
        return jsonify({"error": "An error occurred", "details": str(e)}), 500
    
    finally:
        cursor.close()
        conn.close()

@analytics_blueprint.route('/polls/analytics/expiry', methods=['GET'])
def get_expiry_analytics():
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('''SELECT id, question, expiry, TIMESTAMPDIFF(DAY, NOW(), expiry) AS days_until_expiry
                          FROM polls
                          WHERE expiry >= %s
                          ORDER BY expiry ASC''', (datetime.utcnow(),))
        expiry_data = cursor.fetchall()

        return jsonify({"expiry_analytics": expiry_data}), 200

    except MySQLError as e:
        return jsonify({"error": "An error occurred", "details": str(e)}), 500
    
    finally:
        cursor.close()
        conn.close()