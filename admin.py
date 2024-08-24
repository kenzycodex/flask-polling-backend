import os
import random
import string
import smtplib
import logging
from flask import Blueprint, request, jsonify, render_template_string, abort
from datetime import datetime, timedelta
import pymysql.cursors
from pymysql import MySQLError, InterfaceError, OperationalError
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from werkzeug.security import generate_password_hash, check_password_hash
import dns.resolver
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity

admin_blueprint = Blueprint('admin', __name__)

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Utility function to connect to the database
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
        logger.error(f"Database connection error: {e}")
        raise

# Generate a random 6-digit 2FA code
def generate_2fa_code():
    return ''.join(random.choices(string.digits, k=6))

# Function to verify email domain's MX records
def verify_email_domain(email):
    domain = email.split('@')[-1]
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ['8.8.8.8', '8.8.4.4']  # Google's public DNS servers
        resolver.resolve(domain, 'MX')
        return True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        logger.warning(f"No MX record found for domain: {domain}")
        return False
    except Exception as e:
        logger.error(f"Error verifying email domain: {e}")
        return False

# Send email with the appropriate template
def send_email(to_email, subject, template_name, **kwargs):
    try:
        from_email = os.getenv('SMTP_EMAIL')
        from_name = "Let's Poll"
        password = os.getenv('SMTP_PASSWORD')
        smtp_host = os.getenv('SMTP_HOST')
        smtp_port = int(os.getenv('SMTP_PORT'))

        logger.debug(f"Attempting to verify email domain for: {to_email}")
        if not verify_email_domain(to_email):
            raise ValueError(f"Invalid email domain for: {to_email}")
        logger.debug("Email domain verification successful")
        logger.debug(f"Attempting to send email to {to_email} via {smtp_host}:{smtp_port}")

        msg = MIMEMultipart('alternative')
        msg['From'] = f"{from_name} <{from_email}>"
        msg['To'] = to_email
        msg['Subject'] = subject

        # Plain text version
        text = "Please view this email in an HTML-compatible email client."
        part1 = MIMEText(text, 'plain')

        # HTML version
        try:
            # Define the path to the email_messages directory
            template_dir = os.path.join(os.path.dirname(__file__), 'email_messages')
            # Construct the full path to the HTML template file
            template_path = os.path.join(template_dir, f'{template_name}.html')
            
            with open(template_path, 'r', encoding='utf-8') as file:
                html_template = file.read()

            # Render the HTML template with provided kwargs
            html = render_template_string(html_template, **kwargs)
            part2 = MIMEText(html, 'html')

        except Exception as e:
            logger.error(f"Error rendering template {template_name}.html: {e}")
            return False

        msg.attach(part1)
        msg.attach(part2)

        # Add custom headers
        msg['X-Priority'] = '1'
        msg['X-MSMail-Priority'] = 'High'
        msg['Importance'] = 'High'
        msg['List-Unsubscribe'] = f'<mailto:{from_email}?subject=Unsubscribe>'
        msg['List-Unsubscribe-Post'] = 'List-Unsubscribe=One-Click'

        server = smtplib.SMTP(smtp_host, smtp_port)
        server.starttls()
        server.login(from_email, password)
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()

        logger.info(f"Email sent successfully to {to_email}")
        return True
    except Exception as e:
        logger.error(f"Error sending email: {e}")
        return False

# Create necessary tables
def create_tables():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Create admins table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS admins (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    is_super_admin BOOLEAN DEFAULT FALSE,
                    status ENUM('active', 'inactive', 'pending') DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Create 2FA codes table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS twofa_codes (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    admin_id INT,
                    code VARCHAR(6) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    FOREIGN KEY (admin_id) REFERENCES admins(id)
                )
            ''')

        conn.commit()
    finally:
        conn.close()

# Initialize tables
create_tables()

# Admin registration route
@admin_blueprint.route('/register', methods=['POST'])
def register_admin():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({"error": "Missing required fields"}), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Check if username or email already exists
            cursor.execute("SELECT * FROM admins WHERE username = %s OR email = %s", (username, email))
            if cursor.fetchone():
                return jsonify({"error": "Username or email already exists"}), 409

            # Hash the password
            hashed_password = generate_password_hash(password)

            # Insert new admin with 'pending' status
            cursor.execute(
                "INSERT INTO admins (username, email, password_hash, status) VALUES (%s, %s, %s, 'pending')",
                (username, email, hashed_password)
            )
            conn.commit()

        # Send verification email to super admin
        super_admin_email = os.getenv('SUPER_ADMIN_EMAIL')
        subject = "New Admin Registration Request"
        send_email(super_admin_email, subject, "admin_registration_request", username=username, email=email)

        return jsonify({"message": "Admin registration request sent for approval"}), 201
    except Exception as e:
        logger.error(f"Error in admin registration: {e}")
        return jsonify({"error": "An error occurred during registration"}), 500
    finally:
        conn.close()

# Admin login route
@admin_blueprint.route('/login', methods=['POST'])
def admin_login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM admins WHERE username = %s AND status = 'active'", (username,))
            admin = cursor.fetchone()

            if admin and check_password_hash(admin['password_hash'], password):
                # Generate and send 2FA code
                code = generate_2fa_code()
                cursor.execute(
                    "INSERT INTO twofa_codes (code, expires_at, email) VALUES (%s, %s, %s)",
                    (code, datetime.now() + timedelta(minutes=10), admin['email'])
                )
                conn.commit()

                send_email(admin['email'], "Admin Login Verification", "login_verification", 
                           code=code, username=admin['username'])

                return jsonify({"message": "2FA code sent to your email"}), 200
            else:
                return jsonify({"error": "Invalid credentials or inactive account"}), 401
    except Exception as e:
        logger.error(f"Error in admin login: {e}")
        return jsonify({"error": "An error occurred during login"}), 500
    finally:
        conn.close()

# 2FA Verification Route
@admin_blueprint.route('/verify_2fa', methods=['POST'])
def verify_2fa():
    data = request.json
    username = data.get('username')
    code = data.get('code')

    if not username or not code:
        return jsonify({"error": "Missing username or 2FA code"}), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, email FROM admins WHERE username = %s", (username,))
            admin = cursor.fetchone()

            if not admin:
                return jsonify({"error": "Admin not found"}), 404

            cursor.execute(
                "SELECT * FROM twofa_codes WHERE email = %s AND code = %s AND expires_at > NOW()",
                (admin['email'], code)
            )
            valid_code = cursor.fetchone()

            if valid_code:
                # Delete used code
                cursor.execute("DELETE FROM twofa_codes WHERE id = %s", (valid_code['id'],))
                conn.commit()

                # Create JWT token               
                access_token = create_access_token(identity=username, expires_delta=timedelta(days=5))
                return jsonify(access_token=access_token), 200
            else:
                return jsonify({"error": "Invalid or expired 2FA code"}), 401
    except Exception as e:
        logger.error(f"Error in 2FA verification: {e}")
        return jsonify({"error": "An error occurred during verification"}), 500
    finally:
        conn.close()

# Helper function to check if user is super admin
def is_super_admin(username):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT is_super_admin FROM admins WHERE username = %s", (username,))
            admin = cursor.fetchone()
            return admin and admin['is_super_admin']
    finally:
        conn.close()

# Admin password reset request route
@admin_blueprint.route('/reset_password_request', methods=['POST'])
def reset_password_request():
    email = request.json.get('email')
    if not email:
        return jsonify({"error": "Email is required"}), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, username FROM admins WHERE email = %s", (email,))
            admin = cursor.fetchone()
            if not admin:
                return jsonify({"error": "Admin not found"}), 404

            reset_code = generate_2fa_code()
            cursor.execute(
                "INSERT INTO twofa_codes (email, code, expires_at) VALUES (%s, %s, %s)",
                (email, reset_code, datetime.now() + timedelta(minutes=30))
            )
            conn.commit()

            send_email(email, "Password Reset Code", "password_reset_request", 
                       username=admin['username'], reset_code=reset_code)
            return jsonify({"message": "Password reset code sent to your email"}), 200
    except Exception as e:
        logger.error(f"Error in password reset request: {e}")
        return jsonify({"error": "An error occurred during password reset request"}), 500
    finally:
        conn.close()

# Admin password reset route
@admin_blueprint.route('/reset_password', methods=['POST'])
def reset_password():
    email = request.json.get('email')
    reset_code = request.json.get('reset_code')
    new_password = request.json.get('new_password')

    if not email or not reset_code or not new_password:
        return jsonify({"error": "Missing required fields"}), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, username FROM admins WHERE email = %s", (email,))
            admin = cursor.fetchone()
            if not admin:
                return jsonify({"error": "Admin not found"}), 404

            cursor.execute(
                "SELECT * FROM twofa_codes WHERE email = %s AND code = %s AND expires_at > NOW()",
                (email, reset_code)
            )
            valid_code = cursor.fetchone()

            if not valid_code:
                return jsonify({"error": "Invalid or expired reset code"}), 400

            hashed_password = generate_password_hash(new_password)
            cursor.execute("UPDATE admins SET password_hash = %s WHERE id = %s", (hashed_password, admin['id']))
            cursor.execute("DELETE FROM twofa_codes WHERE id = %s", (valid_code['id'],))
            conn.commit()

            send_email(email, "Password Reset Successful", "password_reset_success", username=admin['username'])
            return jsonify({"message": "Password reset successfully"}), 200
    except Exception as e:
        logger.error(f"Error in password reset: {e}")
        return jsonify({"error": "An error occurred during password reset"}), 500
    finally:
        conn.close()

# Admin profile route
@admin_blueprint.route('/profile', methods=['GET'])
@jwt_required()
def admin_profile():
    current_user = get_jwt_identity()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, username, email, is_super_admin, status FROM admins WHERE username = %s", (current_user,))
            admin = cursor.fetchone()
            if not admin:
                return jsonify({"error": "Admin not found"}), 404
            return jsonify(admin), 200
    except Exception as e:
        logger.error(f"Error fetching admin profile: {e}")
        return jsonify({"error": "An error occurred while fetching admin profile"}), 500
    finally:
        conn.close()

# Update admin profile route
@admin_blueprint.route('/update_profile', methods=['PUT'])
@jwt_required()
def update_admin_profile():
    current_user = get_jwt_identity()
    data = request.json
    new_email = data.get('email')
    new_password = data.get('password')

    if not new_email and not new_password:
        logger.warning(f"No updates provided for user: {current_user}")
        return jsonify({"error": "No updates provided"}), 400

    # Get and process sensitive values
    sensitive_values_str = os.getenv('SENSITIVE_VALUES', '')
    sensitive_values = sensitive_values_str.split(',') if sensitive_values_str else []

    if new_email and new_email in sensitive_values:
        logger.warning(f"Attempt to use sensitive email for user: {current_user}")
        return jsonify({"error": "This email address is not allowed"}), 400

    if new_password and new_password in sensitive_values:
        logger.warning(f"Attempt to use sensitive password for user: {current_user}")
        return jsonify({"error": "This password is not allowed"}), 400

    try:
        conn = get_db_connection()
    except (InterfaceError, OperationalError) as e:
        logger.error(f"Database connection error: {e}")
        return jsonify({"error": "Unable to connect to the database. Please try again later."}), 503

    try:
        with conn.cursor() as cursor:
            updates = []
            values = []
            if new_email:
                updates.append("email = %s")
                values.append(new_email)
            if new_password:
                updates.append("password_hash = %s")
                values.append(generate_password_hash(new_password))
            
            values.append(current_user)
            update_query = f"UPDATE admins SET {', '.join(updates)} WHERE username = %s"
            cursor.execute(update_query, tuple(values))
            
            if cursor.rowcount == 0:
                logger.warning(f"Admin not found or no changes made for user: {current_user}")
                return jsonify({"error": "Admin not found or no changes made"}), 404
            conn.commit()

            if new_email:
                try:
                    send_email(new_email, "Profile Update Notification", "profile_update", username=current_user)
                except Exception as email_error:
                    logger.error(f"Failed to send email notification: {email_error}")
                    # Continue execution even if email sending fails

            logger.info(f"Profile updated successfully for user: {current_user}")
            return jsonify({"message": "Profile updated successfully"}), 200
    except Exception as e:
        logger.error(f"Error updating admin profile for user {current_user}: {e}")
        return jsonify({"error": "An error occurred while updating the profile"}), 500
    finally:
        conn.close()

# Error handlers
@admin_blueprint.errorhandler(400)
def bad_request(e):
    return jsonify(error=str(e)), 400

@admin_blueprint.errorhandler(401)
def unauthorized(e):
    return jsonify(error=str(e)), 401

@admin_blueprint.errorhandler(403)
def forbidden(e):
    return jsonify(error=str(e)), 403

@admin_blueprint.errorhandler(404)
def not_found(e):
    return jsonify(error=str(e)), 404

@admin_blueprint.errorhandler(500)
def internal_server_error(e):
    return jsonify(error="Internal server error"), 500