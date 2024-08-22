from flask import Blueprint, jsonify, current_app, request
from flask_caching import Cache
import pymysql.cursors
import os
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

cache_blueprint = Blueprint('cache', __name__)

# Configure Flask-Caching with SimpleCache
cache = Cache(config={'CACHE_TYPE': 'SimpleCache'})

# Database connection management
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
    except Exception as e:
        logger.error(f"Error connecting to MySQL: {e}")
        raise

# Initialize cache before any request
@cache_blueprint.before_app_request
def setup_cache():
    cache.init_app(current_app)

# Generate a unique cache key based on the request
def generate_cache_key(*args, **kwargs):
    return f"{request.endpoint}:{':'.join(map(str, args))}:{':'.join(f'{k}={v}' for k, v in kwargs.items())}"

# Cached poll results route
@cache_blueprint.route('/poll/<int:poll_id>')
@cache.cached(timeout=60, key_prefix=generate_cache_key)
def cached_poll_results(poll_id):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
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
    except Exception as e:
        logger.error(f"Error fetching poll {poll_id}: {e}")
        return jsonify({"error": "An error occurred", "details": str(e)}), 500

# Cached all polls route
@cache_blueprint.route('/polls')
@cache.cached(timeout=60, key_prefix=generate_cache_key)
def cached_polls():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
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
    except Exception as e:
        logger.error(f"Error fetching polls: {e}")
        return jsonify({"error": "An error occurred", "details": str(e)}), 500

# Cached user votes route
@cache_blueprint.route('/user_votes/<string:user_id>')
@cache.cached(timeout=60, key_prefix=generate_cache_key)
def cached_user_votes(user_id):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT * FROM user_votes WHERE user_id = %s", (user_id,))
                user_votes = cursor.fetchall()

                if user_votes:
                    return jsonify({"user_votes": user_votes}), 200
                else:
                    return jsonify({"message": f"No votes found for user_id '{user_id}'"}), 404
    except Exception as e:
        logger.error(f"Error fetching user votes for {user_id}: {e}")
        return jsonify({"error": "An error occurred", "details": str(e)}), 500

# Cached poll statistics route
@cache_blueprint.route('/poll_stats/<int:poll_id>')
@cache.cached(timeout=60, key_prefix=generate_cache_key)
def cached_poll_stats(poll_id):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) as total_votes FROM user_votes WHERE poll_id = %s", (poll_id,))
                total_votes = cursor.fetchone()

                cursor.execute("SELECT * FROM polls WHERE id = %s", (poll_id,))
                poll = cursor.fetchone()

                if poll:
                    return jsonify({
                        'poll': {
                            'id': poll['id'],
                            'question': poll['question'],
                            'options': poll['options'].split(','),
                            'votes': list(map(int, poll['votes'].split(','))),
                            'expiry': poll['expiry'],
                            'created_by': poll['created_by'],
                            'created_at': poll['created_at']
                        },
                        'total_votes': total_votes['total_votes']
                    }), 200

                return jsonify({"error": "Poll not found"}), 404
    except Exception as e:
        logger.error(f"Error fetching poll stats for {poll_id}: {e}")
        return jsonify({"error": "An error occurred", "details": str(e)}), 500