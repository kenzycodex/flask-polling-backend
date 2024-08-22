import os
import re
import logging
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_jwt_extended import create_access_token, jwt_required, get_jwt
import pymysql.cursors
from pymysql import MySQLError
from factor_auth import send_2fa_code_internal, verify_2fa_code_internal

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

auth_blueprint = Blueprint('auth', __name__)

# Connect to the MySQL database with error handling and logging
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
        logger.info('Connected to MySQL database')
        return conn
    except MySQLError as e:
        logger.error(f"Error connecting to MySQL: {e}")
        raise

# Create the users and blacklist tables if they don't exist
def create_users_table():
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                          id INT AUTO_INCREMENT PRIMARY KEY,
                          full_name VARCHAR(255) NOT NULL,
                          email VARCHAR(255) UNIQUE NOT NULL,
                          username VARCHAR(255) UNIQUE NOT NULL,
                          phone_number VARCHAR(20) NOT NULL,
                          location VARCHAR(255) NOT NULL,
                          password VARCHAR(255) NOT NULL,
                          status VARCHAR(20) DEFAULT 'inactive',
                          two_factor_code VARCHAR(6),
                          code_expires_at DATETIME)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS tokens_blacklist (
                          id INT AUTO_INCREMENT PRIMARY KEY,
                          jti VARCHAR(255) UNIQUE NOT NULL,
                          blacklisted_on DATETIME NOT NULL)''')
        conn.commit()
        logger.info("Users and blacklist tables created successfully")
    except MySQLError as e:
        logger.error(f"Error creating tables: {e}")
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# Ensure the table is created when the app starts
create_users_table()

# Email validation regex
def is_valid_email(email):
    return re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email)

# Username validation regex
def is_valid_username(username):
    return re.match(r'^[a-zA-Z0-9_.-]+$', username)

# Phone number validation regex
def is_valid_phone_number(phone_number):
    return re.match(r'^\+?[0-9]{10,15}$', phone_number)

# Route to register a new user
@auth_blueprint.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    full_name = data.get('full_name')
    email = data.get('email')
    username = data.get('username')
    phone_number = data.get('phone_number')
    location = data.get('location')
    password = data.get('password')
    confirm_password = data.get('confirm_password')

    # Validate incoming data
    if not all([full_name, email, username, phone_number, location, password, confirm_password]):
        return jsonify({"error": "All fields are required"}), 400
    if not is_valid_email(email):
        return jsonify({"error": "Invalid email format"}), 400
    if not is_valid_username(username):
        return jsonify({"error": "Invalid username format"}), 400
    if not is_valid_phone_number(phone_number):
        return jsonify({"error": "Invalid phone number format"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters long"}), 400
    if password != confirm_password:
        return jsonify({"error": "Passwords do not match"}), 400

    hashed_password = generate_password_hash(password)

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if email already exists
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        existing_user = cursor.fetchone()
        if existing_user:
            return jsonify({"error": "Email already exists"}), 409
        
        # Insert new user
        cursor.execute('''INSERT INTO users (full_name, email, username, phone_number, location, password) 
                          VALUES (%s, %s, %s, %s, %s, %s)''',
                       (full_name, email, username, phone_number, location, hashed_password))
        conn.commit()
        
        logger.debug(f"User {username} inserted into database. Attempting to send verification email.")

        # Send 2FA code to the user's email
        success, message = send_2fa_code_internal(email, "Welcome! Please verify your account")
        if success:
            logger.info(f"User {username} registered successfully. Verification email sent.")
            return jsonify({"message": "User registered successfully. A verification code has been sent to your email."}), 201
        else:
            logger.error(f"Failed to send verification email to {email}: {message}")
            return jsonify({"error": "Failed to send verification email"}), 500
    except pymysql.IntegrityError as e:
        logger.error(f"Integrity error during user registration: {e}")
        if 'email' in str(e):
            return jsonify({"error": "Email already exists"}), 409
        elif 'username' in str(e):
            return jsonify({"error": "Username already exists"}), 409
    except MySQLError as e:
        logger.error(f"Error saving user to the database: {e}")
        return jsonify({"error": "Database error occurred"}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# Route to verify 2FA code
@auth_blueprint.route('/verify', methods=['POST'])
def verify():
    data = request.get_json()
    email = data.get('email')
    verification_code = data.get('verification_code')

    if not email or not verification_code:
        return jsonify({"error": "Email and verification code are required"}), 400

    # Verify the 2FA code
    success, message = verify_2fa_code_internal(email, verification_code)
    if success:
        logger.info(f"User {email} verified and activated successfully.")
        return jsonify({"message": "Account verified successfully. You can now log in."}), 200
    else:
        logger.warning(f"Failed to verify 2FA code for {email}: {message}")
        return jsonify({"error": message}), 400

# Route to log in a user
@auth_blueprint.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    login_info = data.get('login_info')  # This could be either email or username
    password = data.get('password')

    # Validate incoming data
    if not login_info or not password:
        return jsonify({"error": "Login information and password are required"}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s OR username = %s", (login_info, login_info))
        user = cursor.fetchone()

        if user and user['status'] == 'inactive':
            return jsonify({"error": "Account not verified. Please check your email for the verification code."}), 403

        if user and check_password_hash(user['password'], password):
            # Create a new token that expires in 1 hour
            token = create_access_token(identity=user['username'], expires_delta=timedelta(hours=1))
            logger.info(f"User {user['username']} logged in successfully.")
            return jsonify({'token': token}), 200
        else:
            logger.warning(f"Login failed for {login_info}. Invalid credentials.")
            return jsonify({'error': 'Invalid credentials'}), 401
    except MySQLError as e:
        logger.error(f"Error retrieving user from database: {e}")
        return jsonify({"error": "Database error occurred"}), 500
    finally:
        cursor.close()
        conn.close()

# Route to reset password
@auth_blueprint.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.get_json()
    identifier = data.get('identifier')  # Could be either email or phone number

    if not identifier:
        return jsonify({"error": "Email or phone number is required"}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT email FROM users WHERE email = %s OR phone_number = %s", (identifier, identifier))
        user = cursor.fetchone()

        if user:
            email = user['email']
            success, message = send_2fa_code_internal(email, "Reset your password")
            if success:
                logger.info(f"Password reset initiated for {email}. Verification code sent.")
                return jsonify({"message": "A verification code has been sent to your email."}), 200
            else:
                logger.error(f"Failed to send password reset verification code to {email}: {message}")
                return jsonify({"error": "Failed to send verification code"}), 500
        else:
            logger.warning(f"Password reset requested for non-existent email or phone number: {identifier}")
            return jsonify({"error": "Email or phone number not found"}), 404
    except MySQLError as e:
        logger.error(f"Database error during password reset: {e}")
        return jsonify({"error": "Database error occurred"}), 500
    finally:
        cursor.close()
        conn.close()

# Route to confirm password reset with verification code
@auth_blueprint.route('/confirm_reset', methods=['POST'])
def confirm_reset():
    data = request.get_json()
    email = data.get('email')
    verification_code = data.get('verification_code')
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')

    # Validate incoming data
    if not all([email, verification_code, new_password, confirm_password]):
        return jsonify({"error": "All fields are required"}), 400
    if len(new_password) < 6:
        return jsonify({"error": "Password must be at least 6 characters long"}), 400
    if new_password != confirm_password:
        return jsonify({"error": "Passwords do not match"}), 400

    try:
        # Verify the 2FA code before allowing password reset
        success, message = verify_2fa_code_internal(email, verification_code)
        if success:
            hashed_password = generate_password_hash(new_password)
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_password, email))
            conn.commit()
            logger.info(f"Password reset successfully for {email}.")
            return jsonify({"message": "Password reset successfully. You can now log in with your new password."}), 200
        else:
            logger.warning(f"Invalid verification code for password reset: {email}")
            return jsonify({"error": message}), 400
    except MySQLError as e:
        logger.error(f"Database error during password reset confirmation: {e}")
        return jsonify({"error": "Database error occurred"}), 500
    finally:
        cursor.close()
        conn.close()

# Route to log out a user (invalidate token)
@auth_blueprint.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]  # JTI is "JWT ID", a unique identifier for a JWT
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO tokens_blacklist (jti, blacklisted_on) VALUES (%s, %s)", (jti, datetime.utcnow()))
        conn.commit()
        logger.info(f"User logged out successfully. Token {jti} blacklisted.")
        return jsonify({"message": "Successfully logged out"}), 200
    except MySQLError as e:
        logger.error(f"Error logging out user: {e}")
        return jsonify({"error": "Database error occurred"}), 500
    finally:
        cursor.close()
        conn.close()

# Route to get user profile
@auth_blueprint.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    conn = None
    cursor = None
    try:
        # Get the current user's username from JWT
        username = get_jwt_identity()

        logger.debug(f"Username extracted from JWT: {username}")

        # Connect to the database
        conn = get_db_connection()
        
        # Use DictCursor to fetch results as a dictionary
        cursor = conn.cursor(pymysql.cursors.DictCursor)

        # Fetch the user's profile information using the username
        cursor.execute("SELECT full_name, email, username, phone_number, location FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        logger.debug(f"User data fetched: {user}")

        # Check if user exists
        if user is None:
            logger.warning(f"Profile access attempt for non-existent user with username: {username}")
            return jsonify({"error": "User not found"}), 404

        # Return user data directly since it's already a dictionary
        logger.info(f"Profile accessed for user with username: {username}.")
        return jsonify(user), 200

    except MySQLError as e:
        logger.error(f"Database error while accessing profile for user with username {username}: {e}")
        return jsonify({"error": "Database error occurred"}), 500

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# Function to check if a token is blacklisted
def is_token_blacklisted(jti):
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM tokens_blacklist WHERE jti = %s", (jti,))
        result = cursor.fetchone()
        return result is not None
    except MySQLError as e:
        logger.error(f"Error checking token blacklist status: {e}")
        return True  # If there's an error, assume the token is blacklisted for safety
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()