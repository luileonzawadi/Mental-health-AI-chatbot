import os
import base64
import requests
from flask import Flask, render_template, request, redirect, url_for, make_response, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required,
    set_access_cookies, unset_jwt_cookies, get_jwt_identity
)
from flask_socketio import SocketIO, emit
from cryptography.fernet import Fernet
from nacl import public
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from datetime import datetime, timedelta
import mimetypes
import eventlet
eventlet.monkey_patch()

# Load environment variables
load_dotenv()

# Configuration
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(24))
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
    if SQLALCHEMY_DATABASE_URI and SQLALCHEMY_DATABASE_URI.startswith('postgres://'):
        SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI.replace('postgres://', 'postgresql://', 1)
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'pool_timeout': 30,
        'pool_size': 20,
        'max_overflow': 30
    }
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', os.urandom(24))
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_TOKEN_LOCATION = ['cookies']
    JWT_COOKIE_SECURE = os.environ.get('PRODUCTION', 'False') == 'True'
    JWT_COOKIE_HTTPONLY = True
    JWT_COOKIE_CSRF_PROTECT = False
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Initialize encryption
FERNET_KEY = os.environ.get("FERNET_KEY", Fernet.generate_key().decode())
fernet = Fernet(FERNET_KEY.encode())

# Database Models (unchanged from your original)
class User(db.Model):
    # ... (keep your existing User model code)

class ChatHistory(db.Model):
    # ... (keep your existing ChatHistory model code)

class Topic(db.Model):
    # ... (keep your existing Topic model code)

class FileUpload(db.Model):
    # ... (keep your existing FileUpload model code)

# Helper Functions
def create_db_tables():
    """Ensure database tables are created"""
    with app.app_context():
        try:
            db.create_all()
            print("Database tables created successfully")
        except Exception as e:
            print(f"Error creating database tables: {e}")
            raise

def get_db_session():
    """Get a new database session"""
    return db.session

# Improved OpenRouter Integration
def chat_with_openrouter(message):
    """Enhanced with better error handling and logging"""
    try:
        url = "https://openrouter.ai/api/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {os.environ.get('OPENROUTER_API_KEY')}",
            "Content-Type": "application/json"
        }

        system_instruction = """..."""  # Your existing instruction

        data = {
            "model": "deepseek/deepseek-r1-0528:free",
            "messages": [
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": message}
            ],
            "temperature": 0.7,
            "max_tokens": 500
        }

        response = requests.post(url, headers=headers, json=data, timeout=30)
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]
    
    except requests.exceptions.RequestException as e:
        print(f"OpenRouter API Request Error: {e}")
    except Exception as e:
        print(f"OpenRouter Processing Error: {e}")
    return "Sorry, I couldn't process your message right now."

# Enhanced Routes
@app.route('/')
def login_form():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    try:
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        
        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400
            
        session = get_db_session()
        user = session.query(User).filter_by(email=email).first()
        
        if not user or not user.check_password(password):
            return jsonify({"error": "Invalid credentials"}), 401
            
        access_token = create_access_token(identity=str(user.id))
        response = make_response(jsonify({"success": True, "redirect": url_for('chat')}))
        set_access_cookies(response, access_token)
        return response
        
    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({"error": "An error occurred during login"}), 500

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            email = request.form.get('email', '').strip()
            password = request.form.get('password', '').strip()
            
            if not email or not password:
                return jsonify({"error": "Email and password are required"}), 400
                
            session = get_db_session()
            if session.query(User).filter_by(email=email).first():
                return jsonify({"error": "Email already exists"}), 400
                
            private_key = public.PrivateKey.generate()
            encrypted_private = fernet.encrypt(bytes(private_key))
            user = User(
                email=email,
                public_key=base64.b64encode(bytes(private_key.public_key)).decode(),
                private_key=base64.b64encode(encrypted_private).decode()
            )
            user.set_password(password)
            
            session.add(user)
            session.commit()
            return jsonify({"success": True, "redirect": url_for('login_form')})
            
        except Exception as e:
            session.rollback()
            print(f"Registration error: {str(e)}")
            return jsonify({"error": "An error occurred during registration"}), 500
            
    return render_template('register.html')

# ... (keep your other routes but update them to use get_db_session())

# Error Handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Resource not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

# SocketIO Events
@socketio.on('connect')
def handle_connect():
    print(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    print(f"Client disconnected: {request.sid}")

# ... (keep your existing socketio handlers)

# Application Startup
def initialize_app():
    create_db_tables()
    print("Application initialization complete")

if __name__ == '__main__':
    initialize_app()
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, 
                host='0.0.0.0', 
                port=port, 
                debug=os.environ.get('FLASK_DEBUG', 'False') == 'True',
                log_output=True)