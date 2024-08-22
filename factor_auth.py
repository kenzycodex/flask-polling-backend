import os
import random
import string
import smtplib
import logging
from flask import Blueprint, request, jsonify, render_template_string
from datetime import datetime, timedelta
import pymysql.cursors
from pymysql import MySQLError
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from werkzeug.security import generate_password_hash
import dns.resolver

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

# HTML email template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ email_purpose }} Code</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #ffffff;
            background-color: #333333;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            border: 1px solid #ddd;
            border-radius: 5px;
        }
        .code {
            font-size: 24px;
            font-weight: bold;
            color: #007bff;
            text-align: center;
            padding: 10px;
            background-color: #f8f9fa;
            border-radius: 5px;
        }
        .spam-note {
            font-size: 12px;
            color: #cccccc;
            margin-top: 20px;
            padding: 10px;
            background-color: #444444;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>Your {{ email_purpose }} Code</h2>
        <p>Hello,</p>
        <p>Your {{ email_purpose }} code is:</p>
        <p class="code">{{ code }}</p>
        <p>This code will expire in 10 minutes. If you didn't request this code, please ignore this email.</p>
        <p>Best regards,<br>Let's Poll Team</p>
        <div class="spam-note">
            <strong>Note:</strong> If this email appears in your spam folder, please mark it as "Not Spam" to ensure you receive our communications in the future.
        </div>
    </div>
</body>
</html>
"""

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

# Send email with the 2FA code
def send_2fa_email(to_email, subject, code, email_purpose):
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
        text = f"Your {email_purpose} code is: {code}\nThis code will expire in 10 minutes."
        part1 = MIMEText(text, 'plain')

        # HTML version
        html = render_template_string(HTML_TEMPLATE, code=code, email_purpose=email_purpose)
        part2 = MIMEText(html, 'html')

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
        logger.info(f"{email_purpose} email sent successfully to {to_email}")
    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {str(e)}", exc_info=True)
        raise

# Endpoint to send 2FA code
@factor_auth_blueprint.route('/send_2fa_code', methods=['POST'])
def send_2fa_code():
    data = request.get_json()
    email = data.get('email')
    purpose = data.get('purpose', 'verification')

    if not email:
        return jsonify({"error": "Email is required"}), 400

    if purpose not in ['verification', 'password_reset']:
        return jsonify({"error": "Invalid purpose"}), 400

    try:
        success, message = send_2fa_code_internal(email, purpose)
        if success:
            return jsonify({"message": message}), 200
        else:
            return jsonify({"error": message}), 400

    except Exception as e:
        logger.error(f"Failed to send 2FA code: {e}")
        return jsonify({"error": f"Failed to send 2FA code: {str(e)}"}), 500

# Endpoint to verify the 2FA code
@factor_auth_blueprint.route('/verify_2fa_code', methods=['POST'])
def verify_2fa_code():
    data = request.get_json()
    email = data.get('email')
    code = data.get('code')

    if not email or not code:
        return jsonify({"error": "Email and code are required"}), 400

    try:
        success, message = verify_2fa_code_internal(email, code)
        if success:
            return jsonify({"message": message}), 200
        else:
            return jsonify({"error": message}), 400

    except Exception as e:
        logger.error(f"Failed to verify 2FA code: {e}")
        return jsonify({"error": f"Failed to verify 2FA code: {str(e)}"}), 500

# Function to be called from other parts of the application
def send_2fa_code_internal(email, purpose="verification"):
    if purpose == 'verification':
        subject = "Account Verification Code"
        email_purpose = "account verification"
    elif purpose == 'password_reset':
        subject = "Password Reset Code"
        email_purpose = "password reset"
    else:
        logger.error(f"Invalid purpose: {purpose}")
        return False, "Invalid purpose"

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
        expiry_time = datetime.utcnow() + timedelta(minutes=10)
        cursor.execute(
            "UPDATE users SET two_factor_code = %s, code_expires_at = %s WHERE email = %s",
            (code, expiry_time, email)
        )
        conn.commit()

        # Send 2FA code via email
        send_2fa_email(email, subject, code, email_purpose)

        logger.info(f"2FA code sent successfully to {email} for {email_purpose}")
        return True, f"2FA code sent successfully for {email_purpose}"

    except ValueError as e:
        logger.error(f"Invalid email: {e}")
        return False, str(e)
    except MySQLError as e:
        logger.error(f"Database error while sending 2FA code: {e}")
        return False, f"Database error: {str(e)}"
    except Exception as e:
        logger.error(f"Failed to send 2FA code: {e}")
        return False, f"Failed to send 2FA code: {str(e)}"
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# Function to verify 2FA code internally
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
        if cursor:
            cursor.close()
        if conn:
            conn.close()