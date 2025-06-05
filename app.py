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
from sqlalchemy.exc import SQLAlchemyError
eventlet.monkey_patch()

# Load environment variables
load_dotenv()

# Configuration
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(24).hex())
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
    if SQLALCHEMY_DATABASE_URI and SQLALCHEMY_DATABASE_URI.startswith('postgres://'):
        SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI.replace('postgres://', 'postgresql://', 1)
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'pool_timeout': 30,
        'pool_size': 10,
        'max_overflow': 20
    }
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', os.urandom(24).hex())
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

# Database Models
class User(db.Model):
    __tablename__ = 'users'  # Explicit table name to avoid issues
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    public_key = db.Column(db.Text, nullable=True)
    private_key = db.Column(db.Text, nullable=True)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

class ChatHistory(db.Model):
    __tablename__ = 'chat_history'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    message = db.Column(db.Text, nullable=False)
    response = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    topic_id = db.Column(db.Integer, db.ForeignKey('topics.id'), nullable=True)

class Topic(db.Model):
    __tablename__ = 'topics'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    title = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    history = db.relationship('ChatHistory', backref='topic', lazy=True)

class FileUpload(db.Model):
    __tablename__ = 'file_uploads'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    filename = db.Column(db.String(255), nullable=False)
    filetype = db.Column(db.String(50), nullable=False)
    upload_time = db.Column(db.DateTime, default=datetime.utcnow)
    topic_id = db.Column(db.Integer, db.ForeignKey('topics.id'), nullable=True)

    def as_dict(self):
        return {
            "id": self.id,
            "filename": self.filename,
            "filetype": self.filetype,
            "upload_time": self.upload_time.isoformat(),
            "topic_id": self.topic_id
        }

# Helper Functions
def create_db_tables():
    """Ensure database tables are created properly"""
    with app.app_context():
        try:
            db.create_all()
            print("Database tables created successfully")
        except Exception as e:
            print(f"Error creating database tables: {str(e)}")
            raise

def get_db_session():
    """Get a fresh database session"""
    return db.session

# Improved OpenRouter Integration
def chat_with_openrouter(message):
    """Enhanced with better error handling and timeout"""
    try:
        url = "https://openrouter.ai/api/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {os.environ.get('OPENROUTER_API_KEY')}",
            "Content-Type": "application/json"
        }

        system_instruction = """You are a friendly, compassionate AI assistant trained in Cognitive Behavioral Therapy (CBT)..."""

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
    except Exception as e:
        print(f"OpenRouter Error: {str(e)}")
        return "Sorry, I couldn't process your message right now."

# Routes
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
        
        # Use a fresh session for login operation
        session = get_db_session()
        user = session.query(User).filter(User.email == email).first()
        
        if not user:
            return jsonify({"error": "Invalid credentials"}), 401
            
        if not user.check_password(password):
            return jsonify({"error": "Invalid credentials"}), 401
            
        access_token = create_access_token(identity=str(user.id))
        response = make_response(jsonify({
            "success": True, 
            "redirect": url_for('chat')
        }))
        set_access_cookies(response, access_token)
        return response
        
    except SQLAlchemyError as e:
        session.rollback()
        print(f"Database error during login: {str(e)}")
        return jsonify({"error": "Database error occurred"}), 500
    except Exception as e:
        print(f"Unexpected error during login: {str(e)}")
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
            if session.query(User).filter(User.email == email).first():
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
            
        except SQLAlchemyError as e:
            session.rollback()
            print(f"Database error during registration: {str(e)}")
            return jsonify({"error": "Database error occurred"}), 500
        except Exception as e:
            print(f"Unexpected error during registration: {str(e)}")
            return jsonify({"error": "An error occurred during registration"}), 500
            
    return render_template('register.html')

# ... (keep your other routes with similar error handling improvements)

# Database Health Check Endpoint
@app.route('/db-health')
def db_health_check():
    try:
        # Test connection
        db.session.execute("SELECT 1")
        # Test User table
        user_count = db.session.query(User).count()
        return jsonify({
            "status": "healthy",
            "user_count": user_count,
            "database_url": app.config['SQLALCHEMY_DATABASE_URI']
        })
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "error": str(e),
            "database_url": app.config['SQLALCHEMY_DATABASE_URI']
        }), 500

# Error Handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Resource not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

# Application Startup
def initialize_app():
    try:
        create_db_tables()
        print("Application initialization complete")
        print(f"Database URL: {app.config['SQLALCHEMY_DATABASE_URI']}")
    except Exception as e:
        print(f"Failed to initialize application: {str(e)}")
        raise

if __name__ == '__main__':
    initialize_app()
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, 
                host='0.0.0.0', 
                port=port, 
                debug=os.environ.get('FLASK_DEBUG', 'False') == 'True',
                log_output=True)