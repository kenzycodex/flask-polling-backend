import os
from dotenv import load_dotenv
from flask import Flask, jsonify
import logging
from flask_cors import CORS
from flask_jwt_extended import JWTManager
import mysql.connector
from mysql.connector import Error
from datetime import timedelta

# Load environment variables from .env file
load_dotenv()

def create_app(config_name=None):
    app = Flask(__name__)

    # Initialize CORS
    CORS(app)

    # Set configurations using environment variables
    app.config['DEBUG'] = os.getenv('FLASK_DEBUG') == 'True'
    app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')

    # MySQL configurations
    app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
    app.config['MYSQL_PORT'] = int(os.getenv('MYSQL_PORT'))
    app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
    app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
    app.config['MYSQL_DATABASE'] = os.getenv('MYSQL_DATABASE')

    # Set the secret key for JWT
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=15)
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)

    # Set up logging
    logging.basicConfig(level=logging.DEBUG, 
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    logger = logging.getLogger(__name__)

    # Initialize JWTManager
    jwt = JWTManager(app)

    # Import feature modules
    from auth import auth_blueprint
    from poll_expiry import poll_expiry_blueprint
    from analytics import analytics_blueprint
    from caching import cache_blueprint
    from factor_auth import factor_auth_blueprint
    #from security import security_blueprint, init_jwt
    #from admin import admin_blueprint

    # Initialize JWT in security module
    #init_jwt(jwt)

    # Register blueprints
    app.register_blueprint(auth_blueprint)
    app.register_blueprint(poll_expiry_blueprint)
    app.register_blueprint(analytics_blueprint)
    app.register_blueprint(cache_blueprint, url_prefix='/cache')
    app.register_blueprint(factor_auth_blueprint)
    #app.register_blueprint(security_blueprint)
    #app.register_blueprint(admin_blueprint)

    # Test MySQL connection route
    @app.route('/test-db', methods=['GET'])
    def test_db_connection():
        try:
            conn = mysql.connector.connect(
                host=app.config['MYSQL_HOST'],
                port=app.config['MYSQL_PORT'],
                user=app.config['MYSQL_USER'],
                password=app.config['MYSQL_PASSWORD'],
                database=app.config['MYSQL_DATABASE']
            )
            if conn.is_connected():
                logger.info('Successfully connected to the database')
                return jsonify({"message": "Database connection successful"}), 200
        except Error as e:
            logger.error(f"Database connection error: {e}")
            return jsonify({"error": "Failed to connect to database"}), 500
        finally:
            if 'conn' in locals() and conn.is_connected():
                conn.close()

    # Default route
    @app.route('/')
    def home():
        return "Welcome to the Advanced Polling Platform!"

    return app

# Start the Flask app with host and port from environment variables
if __name__ == '__main__':
    host = os.getenv('FLASK_HOST', '0.0.0.0')  
    port = int(os.getenv('FLASK_PORT', 5000))  
    app = create_app()
    try:
        app.run(host=host, port=port)
    except Exception as e:
        logging.error(f"Failed to start the server: {e}")
        raise
        
app = create_app()