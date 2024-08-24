# super_admin.py

import os
import logging
from flask import Blueprint, request, jsonify
from werkzeug.security import check_password_hash
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, get_jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv
import pymysql
from pymysql.cursors import DictCursor
from functools import wraps
from admin import generate_2fa_code, send_email

load_dotenv()

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

super_admin_blueprint = Blueprint('super_admin', __name__)

# Database connection
def get_db_connection():
    return pymysql.connect(
        host=os.getenv('MYSQL_HOST'),
        port=int(os.getenv('MYSQL_PORT')),
        user=os.getenv('MYSQL_USER'),
        password=os.getenv('MYSQL_PASSWORD'),
        database=os.getenv('MYSQL_DATABASE'),
        cursorclass=DictCursor
    )

# Create necessary tables
def create_tables():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Create super_admin_status table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS super_admin_status (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    status ENUM('active', 'inactive') NOT NULL,
                    last_login DATETIME,
                    last_logout DATETIME
                )
            """)
            
            # Create tokens_blacklist table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tokens_blacklist (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    jti VARCHAR(36) UNIQUE NOT NULL,
                    created_at DATETIME NOT NULL
                )
            """)

            # Create twofa_codes table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS twofa_codes (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    email VARCHAR(255) NOT NULL,
                    code VARCHAR(6) NOT NULL,
                    expires_at DATETIME NOT NULL
                )
            """)
        conn.commit()
    finally:
        conn.close()

create_tables()

# Helper functions
def is_token_blacklisted(jti):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM tokens_blacklist WHERE jti = %s", (jti,))
            return cursor.fetchone() is not None
    finally:
        conn.close()

def blacklist_token(jti):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("INSERT INTO tokens_blacklist (jti, created_at) VALUES (%s, %s)",
                           (jti, datetime.now()))
        conn.commit()
    finally:
        conn.close()

def update_super_admin_status(email, status):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            if status == 'active':
                cursor.execute("""
                    INSERT INTO super_admin_status (email, status, last_login)
                    VALUES (%s, %s, %s)
                    ON DUPLICATE KEY UPDATE status = %s, last_login = %s
                """, (email, status, datetime.now(), status, datetime.now()))
            else:
                cursor.execute("""
                    UPDATE super_admin_status
                    SET status = %s, last_logout = %s
                    WHERE email = %s
                """, (status, datetime.now(), email))
        conn.commit()
    finally:
        conn.close()

def super_admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        current_user = get_jwt_identity()
        if current_user != os.getenv('SUPER_ADMIN_EMAIL'):
            return jsonify({"error": "Super admin access required"}), 403
        return fn(*args, **kwargs)
    return wrapper

@super_admin_blueprint.route('/login', methods=['POST'])
def super_admin_login():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400

        if email != os.getenv('SUPER_ADMIN_EMAIL'):
            logger.warning(f"Invalid login attempt for super admin with email: {email}")
            return jsonify({"error": "Invalid credentials"}), 401

        if not check_password_hash(os.getenv('SUPER_ADMIN_PASSWORD_HASH'), password):
            logger.warning(f"Invalid password attempt for super admin with email: {email}")
            return jsonify({"error": "Invalid credentials"}), 401

        # Generate and send 2FA code
        code = generate_2fa_code()
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO twofa_codes (code, expires_at, email) VALUES (%s, %s, %s)",
                    (code, datetime.now() + timedelta(minutes=10), email)
                )
            conn.commit()
        except pymysql.IntegrityError as e:
            logger.error(f"Database integrity error: {str(e)}")
            return jsonify({"error": "An error occurred while processing your request"}), 500
        finally:
            conn.close()

        send_email(email, "Super Admin Login Verification", "login_verification", code=code, username="Super Admin")
        logger.info(f"2FA code sent to super admin email: {email}")

        return jsonify({"message": "2FA code sent to your email"}), 200

    except Exception as e:
        logger.error(f"Unexpected error in super_admin_login: {str(e)}")
        return jsonify({"error": "An unexpected error occurred"}), 500

@super_admin_blueprint.route('/verify_2fa', methods=['POST'])
def super_admin_verify_2fa():
    try:
        data = request.json
        email = data.get('email')
        code = data.get('code')

        if not email or not code:
            return jsonify({"error": "Email and 2FA code are required"}), 400

        if email != os.getenv('SUPER_ADMIN_EMAIL'):
            logger.warning(f"Invalid 2FA verification attempt for email: {email}")
            return jsonify({"error": "Invalid credentials"}), 401

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT * FROM twofa_codes WHERE email = %s AND code = %s AND expires_at > NOW()",
                    (email, code)
                )
                valid_code = cursor.fetchone()

                if valid_code:
                    cursor.execute("DELETE FROM twofa_codes WHERE id = %s", (valid_code['id'],))
                    conn.commit()

                    # Create access token with 1 day expiration
                    access_token = create_access_token(identity=email, expires_delta=timedelta(days=1))
                    update_super_admin_status(email, 'active')
                    logger.info(f"Super admin successfully authenticated: {email}")
                    return jsonify(access_token=access_token), 200
                else:
                    logger.warning(f"Invalid or expired 2FA code for email: {email}")
                    return jsonify({"error": "Invalid or expired 2FA code"}), 401
        finally:
            conn.close()

    except Exception as e:
        logger.error(f"Unexpected error in super_admin_verify_2fa: {str(e)}")
        return jsonify({"error": "An unexpected error occurred"}), 500

@super_admin_blueprint.route('/logout', methods=['POST'])
@jwt_required()
@super_admin_required
def super_admin_logout():
    try:
        jti = get_jwt()['jti']
        blacklist_token(jti)
        current_user = get_jwt_identity()
        update_super_admin_status(current_user, 'inactive')
        logger.info(f"Super admin logged out: {current_user}")
        return jsonify({"message": "Successfully logged out"}), 200
    except Exception as e:
        logger.error(f"Unexpected error in super_admin_logout: {str(e)}")
        return jsonify({"error": "An unexpected error occurred"}), 500

@super_admin_blueprint.route('/dashboard', methods=['GET'])
@jwt_required()
@super_admin_required
def super_admin_dashboard():
    return jsonify({"message": "Super Admin Dashboard"}), 200

# Super admin approval route
@super_admin_blueprint.route('/approve_admin/<int:admin_id>', methods=['POST'])
@jwt_required()
@super_admin_required
def approve_admin(admin_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Check if the admin exists and is in pending status
            cursor.execute("SELECT * FROM admins WHERE id = %s AND status = 'pending'", (admin_id,))
            admin = cursor.fetchone()
            
            if not admin:
                return jsonify({"error": "Admin not found or already approved"}), 404

            # Update admin status to active
            cursor.execute("UPDATE admins SET status = 'active' WHERE id = %s", (admin_id,))
            conn.commit()

            # Send approval email
            send_email(admin['email'], "Admin Account Approved", "admin_approval", 
                       username=admin['username'])

        logger.info(f"Admin with ID {admin_id} approved by super admin")
        return jsonify({"message": f"Admin with ID {admin_id} approved and notification sent"}), 200
    except Exception as e:
        conn.rollback()
        logger.error(f"Error approving admin: {str(e)}")
        return jsonify({"error": "An error occurred while approving the admin"}), 500
    finally:
        conn.close()
        
@super_admin_blueprint.route('/deny_admin/<int:admin_id>', methods=['POST'])
@jwt_required()
@super_admin_required
def deny_admin(admin_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Check if the admin exists and is in pending status
            cursor.execute("SELECT * FROM admins WHERE id = %s AND status = 'pending'", (admin_id,))
            admin = cursor.fetchone()
            
            if not admin:
                return jsonify({"error": "Admin not found or already processed"}), 404

            # Delete the admin
            cursor.execute("DELETE FROM admins WHERE id = %s", (admin_id,))
            conn.commit()
        
        # Send denial email
        send_email(admin['email'], "Admin Account Request Denied", "admin_denial", 
                   username=admin['username'])
        
        logger.info(f"Admin with ID {admin_id} denied by super admin")
        return jsonify({"message": f"Admin with ID {admin_id} denied and notification sent"}), 200
    except Exception as e:
        conn.rollback()
        logger.error(f"Error denying admin: {str(e)}")
        return jsonify({"error": "An error occurred while denying the admin"}), 500
    finally:
        conn.close()

# Add more super admin specific routes as needed