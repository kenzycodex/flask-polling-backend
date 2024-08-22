import os
import re
import logging
import hashlib
import hmac
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, current_app, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token, get_jwt, create_refresh_token
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pymysql.cursors
from pymysql import MySQLError
from functools import wraps

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

security_blueprint = Blueprint('security', __name__)

# Rate limiter
limiter = Limiter(
    get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

jwt = None

def init_jwt(_jwt):
    global jwt
    jwt = _jwt

    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        jti = jwt_payload["jti"]
        return is_token_blacklisted(jti)

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
        logger.error(f"Error connecting to MySQL: {e}")
        raise

# Input validation function with strict rules
def is_valid_input(input_str, input_type):
    if input_type == 'username':
        return re.match(r'^[a-zA-Z0-9_]{4,20}$', input_str) is not None
    elif input_type == 'email':
        return re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', input_str) is not None
    elif input_type == 'password':
        # At least 8 characters, 1 uppercase, 1 lowercase, 1 number, 1 special character
        return re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', input_str) is not None
    return False

# Custom password hashing function
def hash_password(password):
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt + key

# Custom password verification function
def verify_password(stored_password, provided_password):
    salt = stored_password[:32]
    stored_key = stored_password[32:]
    new_key = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
    return hmac.compare_digest(stored_key, new_key)

# CSRF protection
def csrf_protect():
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if request.method == "POST":
                token = request.headers.get('X-CSRFToken')
                if not token or token != session.get('csrf_token'):
                    return jsonify({"error": "CSRF token missing or invalid"}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Enforce HTTPS and add security headers
@security_blueprint.before_app_request
def before_request():
    if not request.is_secure and current_app.config.get('ENV') == 'production':
        return jsonify({"error": "HTTPS required"}), 403
    
    # Add security headers
    @current_app.after_request
    def add_security_headers(response):
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        return response

# User registration
@security_blueprint.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
@csrf_protect()
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')

    if not all([username, password, email]):
        return jsonify({"error": "All fields are required"}), 400

    if not is_valid_input(username, 'username') or not is_valid_input(email, 'email') or not is_valid_input(password, 'password'):
        return jsonify({"error": "Invalid input format"}), 400

    hashed_password = hash_password(password)

    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                           (username, email, hashed_password))
        conn.commit()
        logger.info(f"User {username} registered successfully")
        return jsonify({"message": "User registered successfully"}), 201
    except MySQLError as e:
        logger.error(f"Error registering user: {e}")
        return jsonify({"error": "Registration failed"}), 500
    finally:
        conn.close()

# User login
@security_blueprint.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
@csrf_protect()
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()

        if user and verify_password(user['password'], password):
            access_token = create_access_token(
                identity=username, 
                expires_delta=timedelta(minutes=15),
                fresh=True
            )
            refresh_token = create_refresh_token(identity=username)
            logger.info(f"User {username} logged in successfully")
            return jsonify({
                "access_token": access_token,
                "refresh_token": refresh_token
            }), 200
        return jsonify({"error": "Invalid credentials"}), 401
    except MySQLError as e:
        logger.error(f"Error during login: {e}")
        return jsonify({"error": "Login failed"}), 500
    finally:
        conn.close()

# Password reset
@security_blueprint.route('/reset_password', methods=['POST'])
@limiter.limit("3 per hour")
@jwt_required(fresh=True)
@csrf_protect()
def reset_password():
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')

    if not current_password or not new_password:
        return jsonify({"error": "Current and new passwords are required"}), 400

    if not is_valid_input(new_password, 'password'):
        return jsonify({"error": "New password does not meet security requirements"}), 400

    username = get_jwt_identity()

    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()

            if user and verify_password(user['password'], current_password):
                hashed_password = hash_password(new_password)
                cursor.execute("UPDATE users SET password = %s WHERE username = %s", (hashed_password, username))
                conn.commit()
                logger.info(f"Password reset successful for user {username}")
                return jsonify({"message": "Password reset successful"}), 200
            return jsonify({"error": "Current password is incorrect"}), 401
    except MySQLError as e:
        logger.error(f"Error resetting password: {e}")
        return jsonify({"error": "Password reset failed"}), 500
    finally:
        conn.close()

# User logout
@security_blueprint.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("INSERT INTO tokens_blacklist (jti, blacklisted_on) VALUES (%s, %s)", 
                           (jti, datetime.utcnow()))
        conn.commit()
        logger.info(f"User logged out successfully. Token blacklisted: {jti}")
        return jsonify({"message": "Successfully logged out"}), 200
    except MySQLError as e:
        logger.error(f"Error logging out: {e}")
        return jsonify({"error": "Logout failed"}), 500
    finally:
        conn.close()

# Check if a token is blacklisted
def is_token_blacklisted(jti):
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM tokens_blacklist WHERE jti = %s", (jti,))
            result = cursor.fetchone()
        return result is not None
    except MySQLError as e:
        logger.error(f"Error checking token blacklist: {e}")
        return True
    finally:
        conn.close()

# Refresh token endpoint
@security_blueprint.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity, fresh=False)
    return jsonify(access_token=access_token), 200

# Generate CSRF token
@security_blueprint.route('/get-csrf-token', methods=['GET'])
def get_csrf_token():
    token = os.urandom(16).hex()
    session['csrf_token'] = token
    return jsonify({"csrf_token": token}), 200

# Password strength checker
def check_password_strength(password):
    score = 0
    if len(password) >= 8:
        score += 1
    if re.search(r'[A-Z]', password):
        score += 1
    if re.search(r'[a-z]', password):
        score += 1
    if re.search(r'\d', password):
        score += 1
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1
    return score

# Route to check password strength
@security_blueprint.route('/check-password-strength', methods=['POST'])
@limiter.limit("10 per minute")
def check_password_strength_route():
    data = request.get_json()
    password = data.get('password')
    if not password:
        return jsonify({"error": "Password is required"}), 400
    strength = check_password_strength(password)
    return jsonify({"strength": strength}), 200

# Two-factor authentication setup (simulated)
@security_blueprint.route('/setup-2fa', methods=['POST'])
@jwt_required()
def setup_2fa():
    # In a real implementation, you would generate and store a secret key
    # and return a QR code for the user to scan with their authenticator app
    username = get_jwt_identity()
    secret_key = os.urandom(32).hex()
    # Store the secret key securely (in the database) associated with the user
    return jsonify({"message": "2FA setup successful", "secret_key": secret_key}), 200

# Verify 2FA code (simulated)
@security_blueprint.route('/verify-2fa', methods=['POST'])
@jwt_required()
def verify_2fa():
    data = request.get_json()
    code = data.get('code')
    username = get_jwt_identity()
    # In a real implementation, you would verify the code against the stored secret key
    if code == "123456":  # This is a placeholder. Use a proper 2FA verification in production.
        return jsonify({"message": "2FA verification successful"}), 200
    return jsonify({"error": "Invalid 2FA code"}), 401