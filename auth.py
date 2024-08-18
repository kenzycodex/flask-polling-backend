import sqlite3
from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (create_access_token, jwt_required, get_jwt_identity, JWTManager, get_jti)
from flask_jwt_extended import get_jwt
from datetime import timedelta
from datetime import datetime
import re

auth_blueprint = Blueprint('auth', __name__)

# Connect to the SQLite database
def get_db_connection():
    conn = sqlite3.connect('users.db')  # This will create the database if it doesn't exist
    conn.row_factory = sqlite3.Row
    return conn

# Create the users and blacklist tables if they don't exist
def create_users_table():
    conn = get_db_connection()
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    full_name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    username TEXT UNIQUE NOT NULL,
                    phone_number TEXT NOT NULL,
                    location TEXT NOT NULL,
                    password TEXT NOT NULL)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS tokens_blacklist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    jti TEXT NOT NULL UNIQUE,
                    blacklisted_on DATETIME NOT NULL)''')
    conn.commit()
    conn.close()

# Ensure the table is created when the app starts
create_users_table()

# Email validation regex (modify based on your username rules)
def is_valid_email(email):
    return re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email)

# Username validation regex
def is_valid_username(username):
    return re.match(r'^[a-zA-Z0-9_.-]+$', username)

# Phone number validation regex (simple format check)
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
    
    # Save user to the database
    conn = get_db_connection()
    try:
        conn.execute('''INSERT INTO users (full_name, email, username, phone_number, location, password) 
                        VALUES (?, ?, ?, ?, ?, ?)''', 
                     (full_name, email, username, phone_number, location, hashed_password))
        conn.commit()
        return jsonify({"message": "User registered successfully"}), 201
    except sqlite3.IntegrityError as e:
        if 'email' in str(e):
            return jsonify({"error": "Email already exists"}), 409
        elif 'username' in str(e):
            return jsonify({"error": "Username already exists"}), 409
    finally:
        conn.close()

# Route to log in a user (using either email or username)
@auth_blueprint.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    login_info = data.get('login_info')  # This could be either email or username
    password = data.get('password')

    # Validate incoming data
    if not login_info or not password:
        return jsonify({"error": "Login information and password are required"}), 400

    # Retrieve user from the database
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE email = ? OR username = ?", (login_info, login_info)).fetchone()
    conn.close()

    if user and check_password_hash(user['password'], password):
        # Create a new token that expires in 1 hour
        token = create_access_token(identity=user['username'], expires_delta=timedelta(hours=1))
        return jsonify({'token': token}), 200

    return jsonify({'error': 'Invalid credentials'}), 401

# Route to log out (blacklist token)
@auth_blueprint.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    # Get the current JWT data (including jti)
    jwt_data = get_jwt()
    jti = jwt_data['jti']  # Extract the JWT ID from the token

    conn = get_db_connection()
    try:
        # Insert the blacklisted token into the tokens_blacklist table
        conn.execute("INSERT INTO tokens_blacklist (jti, blacklisted_on) VALUES (?, ?)", (jti, datetime.utcnow()))
        conn.commit()
        return jsonify({"message": "Successfully logged out"}), 200
    except sqlite3.IntegrityError:
        return jsonify({"error": "Token has already been blacklisted"}), 400
    finally:
        conn.close()

# Check if token is blacklisted before processing requests
@auth_blueprint.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    # Get the current JWT data (including jti) using get_jwt
    jwt_data = get_jwt()
    jti = jwt_data['jti']  # Extract the jti (JWT ID) from the token

    # Connect to the database
    conn = get_db_connection()

    # Check if the token is blacklisted
    blacklisted_token = conn.execute("SELECT id FROM tokens_blacklist WHERE jti = ?", (jti,)).fetchone()

    # Close the connection after fetching the data
    conn.close()

    # If the token is blacklisted, return an error message
    if blacklisted_token:
        return jsonify({"message": "Token has been blacklisted. Access denied."}), 401

    # If not blacklisted, return the user's profile
    return jsonify({
        "message": "User profile data",
        "jti": jti
    }), 200