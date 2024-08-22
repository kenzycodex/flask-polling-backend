import os
import random
import string
import smtplib
import logging
from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
import pymysql.cursors
from pymysql import MySQLError
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from werkzeug.security import generate_password_hash

factor_auth_blueprint = Blueprint('factor_auth', __name__)

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

# Send email with the 2FA code
def send_2fa_email(to_email, subject, message):
    try:
        from_email = os.getenv('SMTP_EMAIL')
        password = os.getenv('SMTP_PASSWORD')
        smtp_host = os.getenv('SMTP_HOST')
        smtp_port = int(os.getenv('SMTP_PORT'))
        
        logger.debug(f"Attempting to send email to {to_email} via {smtp_host}:{smtp_port}")

        msg = MIMEMultipart()
        msg['From'] = from_email
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(message, 'plain'))

        server = smtplib.SMTP(smtp_host, smtp_port)
        server.starttls()
        server.login(from_email, password)
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()
        logger.info(f"2FA email sent successfully to {to_email}")
    except Exception as e:
        logger.error(f"Failed to send email: {e}", exc_info=True)
        raise

# Endpoint to send 2FA code
@factor_auth_blueprint.route('/send_2fa_code', methods=['POST'])
def send_2fa_code():
    data = request.get_json()
    email = data.get('email')
    subject = data.get('subject', "Your 2FA Code for Account Verification")

    if not email:
        return jsonify({"error": "Email is required"}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if not user:
            logger.warning(f"No user found with email: {email}")
            return jsonify({"error": "No user found with this email"}), 404

        # Generate and save 2FA code with expiry time
        code = generate_2fa_code()
        expiry_time = datetime.utcnow() + timedelta(minutes=10)  # Code expires in 10 minutes
        cursor.execute(
            "UPDATE users SET two_factor_code = %s, code_expires_at = %s WHERE email = %s",
            (code, expiry_time, email)
        )
        conn.commit()

        # Send 2FA code via email
        message = f"Your 2FA code is {code}. Please verify your account within 10 minutes."
        send_2fa_email(email, subject, message)

        logger.info(f"2FA code sent successfully to {email}")
        return jsonify({"message": "2FA code sent successfully"}), 200

    except MySQLError as e:
        logger.error(f"Database error while sending 2FA code: {e}")
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    except Exception as e:
        logger.error(f"Failed to send 2FA code: {e}")
        return jsonify({"error": f"Failed to send 2FA code: {str(e)}"}), 500
    finally:
        cursor.close()
        conn.close()

# Endpoint to verify the 2FA code
@factor_auth_blueprint.route('/verify_2fa_code', methods=['POST'])
def verify_2fa_code():
    data = request.get_json()
    email = data.get('email')
    code = data.get('code')

    if not email or not code:
        return jsonify({"error": "Email and code are required"}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if not user:
            logger.warning(f"No user found with email: {email}")
            return jsonify({"error": "No user found with this email"}), 404

        if user['two_factor_code'] != code:
            logger.warning(f"Invalid 2FA code attempt for email: {email}")
            return jsonify({"error": "Invalid 2FA code"}), 400

        if datetime.utcnow() > user['code_expires_at']:
            logger.warning(f"Expired 2FA code attempt for email: {email}")
            return jsonify({"error": "2FA code has expired"}), 400

        # Update user's status to 'active' after successful verification
        cursor.execute("UPDATE users SET status = 'active', two_factor_code = NULL, code_expires_at = NULL WHERE email = %s", (email,))
        conn.commit()

        logger.info(f"2FA code verified successfully for {email}")
        return jsonify({"message": "2FA code verified successfully"}), 200

    except MySQLError as e:
        logger.error(f"Database error while verifying 2FA code: {e}")
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    finally:
        cursor.close()
        conn.close()

# Function to be called from other parts of the application
def send_2fa_code_internal(email, subject="Your 2FA Code"):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if not user:
            logger.warning(f"No user found with email: {email}")
            return False, "No user found with this email"

        # Generate and save 2FA code with expiry time
        code = generate_2fa_code()
        expiry_time = datetime.utcnow() + timedelta(minutes=10)  # Code expires in 10 minutes
        cursor.execute(
            "UPDATE users SET two_factor_code = %s, code_expires_at = %s WHERE email = %s",
            (code, expiry_time, email)
        )
        conn.commit()

        # Send 2FA code via email
        message = f"Your 2FA code is {code}. Please use this code within 10 minutes."
        send_2fa_email(email, subject, message)

        logger.info(f"2FA code sent successfully to {email}")
        return True, "2FA code sent successfully"

    except MySQLError as e:
        logger.error(f"Database error while sending 2FA code: {e}")
        return False, f"Database error: {str(e)}"
    except Exception as e:
        logger.error(f"Failed to send 2FA code: {e}")
        return False, f"Failed to send 2FA code: {str(e)}"
    finally:
        cursor.close()
        conn.close()

# Function to be called from other parts of the application
def verify_2fa_code_internal(email, code):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if not user:
            logger.warning(f"No user found with email: {email}")
            return False, "No user found with this email"

        if user['two_factor_code'] != code:
            logger.warning(f"Invalid 2FA code attempt for email: {email}")
            return False, "Invalid 2FA code"

        if datetime.utcnow() > user['code_expires_at']:
            logger.warning(f"Expired 2FA code attempt for email: {email}")
            return False, "2FA code has expired"

        # Update user's status to 'active' after successful verification
        cursor.execute("UPDATE users SET status = 'active', two_factor_code = NULL, code_expires_at = NULL WHERE email = %s", (email,))
        conn.commit()

        logger.info(f"2FA code verified successfully for {email}")
        return True, "2FA code verified successfully"

    except MySQLError as e:
        logger.error(f"Database error while verifying 2FA code: {e}")
        return False, f"Database error: {str(e)}"
    finally:
        cursor.close()
        conn.close()