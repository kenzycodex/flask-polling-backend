import os
from dotenv import load_dotenv
from flask import Flask, jsonify, request, abort
import logging
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from werkzeug.security import check_password_hash

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Initialize CORS
CORS(app)

# Set configurations using environment variables
app.config['DEBUG'] = os.getenv('FLASK_DEBUG') == 'True'
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')

# Set the secret key for JWT
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')

# Set up logging
logging.basicConfig(level=logging.DEBUG)

# Initialize JWTManager
jwt = JWTManager(app)

# Import feature modules
from auth import auth_blueprint
from poll_expiry import poll_expiry_blueprint
from user_votes import user_votes_blueprint
from analytics import analytics_blueprint
from caching import cache_blueprint
from admin import admin_blueprint  

# Register blueprints
app.register_blueprint(auth_blueprint)
app.register_blueprint(poll_expiry_blueprint)
app.register_blueprint(user_votes_blueprint)
app.register_blueprint(analytics_blueprint)
app.register_blueprint(cache_blueprint)
app.register_blueprint(admin_blueprint)  

# Default route
@app.route('/')
def home():
    return "Welcome to the Advanced Polling Platform!"

# Start the Flask app with host and port from environment variables
if __name__ == '__main__':
    host = os.getenv('FLASK_HOST', '0.0.0.0')  # Default to '0.0.0.0' if not set
    port = int(os.getenv('FLASK_PORT', 8080))  # Default to port 8080 if not set
    app.run(host=host, port=port)