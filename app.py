import os
import base64
import requests
import time
import socket
import json
import traceback
import sys
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
from datetime import datetime, timedelta
import mimetypes
from sqlalchemy.exc import SQLAlchemyError
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
import eventlet
import flask
from dotenv import load_dotenv

# Load environment variables first
load_dotenv()

# Configure proxy settings if provided
http_proxy = os.environ.get('HTTP_PROXY')
https_proxy = os.environ.get('HTTPS_PROXY')
proxies = {
    'http': http_proxy,
    'https': https_proxy
} if http_proxy or https_proxy else None

if proxies:
    os.environ['HTTP_PROXY'] = http_proxy if http_proxy else ''
    os.environ['HTTPS_PROXY'] = https_proxy if https_proxy else ''
    print(f"Using proxies: HTTP={http_proxy}, HTTPS={https_proxy}")

# Set default timeout for socket operations
socket.setdefaulttimeout(30)

# Apply eventlet monkey patch
eventlet.monkey_patch()

# Get API key from environment variables
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")

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
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    public_key = db.Column(db.Text, nullable=True)
    private_key = db.Column(db.Text, nullable=True)
    is_medical_professional = db.Column(db.Boolean, default=False)

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
            if 'postgresql' in app.config['SQLALCHEMY_DATABASE_URI']:
                db.session.execute(db.text("CREATE SCHEMA IF NOT EXISTS public"))
                db.session.commit()
                
            print("Creating database tables...")
            db.create_all()
            print("Database tables created successfully")
        except Exception as e:
            print(f"Error creating database tables: {str(e)}")
            raise

def get_db_session():
    """Get a fresh database session"""
    return db.session

# Enhanced OpenRouter Integration
def chat_with_openrouter(message):
    try:
        system_instruction = (
            "You are a friendly, compassionate AI assistant trained in Cognitive Behavioral Therapy (CBT). "
            "You help users improve their mental and emotional well-being. "
            "Only respond to questions related to health and mental health. If a user asks anything unrelated, "
            "gently redirect them back to mental wellness topics."
        )

        data = {
            "model": "openai/gpt-3.5-turbo",
            "messages": [
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": message}
            ],
            "temperature": 0.7,
            "max_tokens": 500
        }

        print(f"Sending request to OpenRouter with data: {json.dumps(data, indent=2)}")

        url = "https://openrouter.ai/api/v1/chat/completions"  # Make sure this is your actual endpoint
        headers = {
            "Authorization": f"Bearer {os.getenv('OPENROUTER_API_KEY')}",
            "Content-Type": "application/json"
        }

        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = requests.post(
                    url,
                    headers=headers,
                    json=data,
                    timeout=30,
                    verify=False  # Only use this if you have SSL issues; otherwise, remove it for production
                )
                break
            except requests.exceptions.RequestException as e:
                print(f"Attempt {attempt+1} failed: {e}")
                if attempt == max_retries - 1:
                    raise

        if response.status_code == 200:
            return response.json()
        else:
            print(f"OpenRouter API error: {response.status_code} - {response.text}")
            return {"error": "Failed to get response from OpenRouter."}

    except Exception as e:
        print(f"Exception in chat_with_openrouter: {e}")
        return {"error": str(e)}
# Routes
@app.route('/')
def login_form():
    # Handle HEAD requests from monitoring services
    if request.method == 'HEAD':
        return '', 200
    return render_template('login.html')

@app.route('/robots.txt')
def robots():
    return """
User-agent: *
Allow: /
Sitemap: /sitemap.xml
"""

@app.route('/sitemap.xml')
def sitemap():
    host_url = request.host_url.rstrip('/')
    pages = [
        {'loc': host_url, 'priority': '1.0'},
        {'loc': f"{host_url}/login", 'priority': '0.8'},
        {'loc': f"{host_url}/register", 'priority': '0.8'},
        {'loc': f"{host_url}/chat", 'priority': '0.9'},
        {'loc': f"{host_url}/public-chat", 'priority': '0.7'}
    ]
    
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
    xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    
    for page in pages:
        xml += '  <url>\n'
        xml += f'    <loc>{page["loc"]}</loc>\n'
        xml += f'    <priority>{page["priority"]}</priority>\n'
        xml += '  </url>\n'
    
    xml += '</urlset>'
    
    response = make_response(xml)
    response.headers["Content-Type"] = "application/xml"
    return response

@app.route('/public-chat')
def public_chat():
    return render_template('chat_public.html')
    
@app.route('/chat', methods=['POST'])
def process_chat():
    try:
        data = request.json
        message = data.get('message', '')
        
        if not message:
            return jsonify({"error": "No message provided"}), 400
            
        # Get response from OpenRouter
        response = chat_with_openrouter(message)
        
        # Save to chat history if user is logged in
        try:
            from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
            # Try to verify JWT but continue if not available
            valid_jwt = False
            try:
                verify_jwt_in_request(optional=True)
                valid_jwt = True
            except:
                pass
                
            if valid_jwt:
                user_id = get_jwt_identity()
                if user_id:
                    chat_entry = ChatHistory(
                        user_id=user_id,
                        message=message,
                        response=response
                    )
                    db.session.add(chat_entry)
                    db.session.commit()
        except Exception as e:
            print(f"Error saving chat history: {str(e)}")
        
        return jsonify({"response": response})
    except Exception as e:
        print(f"Error in process_chat: {str(e)}")
        return jsonify({"error": "An error occurred processing your request"}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        
        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400
        
        try:
            inspector = db.inspect(db.engine)
            if 'users' not in inspector.get_table_names():
                create_db_tables()
                return jsonify({"error": "Please try again. Database was being set up."}), 500
            
            session = get_db_session()
            user = session.query(User).filter(User.email == email).first()
            
            if not user:
                return jsonify({"error": "Invalid credentials"}), 401
                
            if not user.check_password(password):
                return jsonify({"error": "Invalid credentials"}), 401
                
            access_token = create_access_token(identity=str(user.id))
            response = make_response(redirect('/chat'))
            set_access_cookies(response, access_token)
            return response
            
        except SQLAlchemyError as e:
            if session:
                session.rollback()
            print(f"Database error during login: {str(e)}")
            return jsonify({"error": "Database error occurred. Please try again."}), 500
    except Exception as e:
        print(f"Unexpected error during login: {str(e)}")
        return jsonify({"error": "An error occurred during login. Please try again."}), 500

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            name = request.form.get('name', '').strip()
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
                name=name,
                email=email,
                public_key=base64.b64encode(bytes(private_key.public_key)).decode(),
                private_key=base64.b64encode(encrypted_private).decode()
            )
            user.set_password(password)
            
            session.add(user)
            session.commit()
            
            # Return success message that will trigger a popup
            return jsonify({"success": True, "message": "Registration successful! You can now log in."})
            
        except SQLAlchemyError as e:
            session.rollback()
            print(f"Database error during registration: {str(e)}")
            return jsonify({"error": "Database error occurred"}), 500
        except Exception as e:
            print(f"Unexpected error during registration: {str(e)}")
            return jsonify({"error": "An error occurred during registration"}), 500
            
    return render_template('register.html')

@app.route('/chat')
@jwt_required()
def chat():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        user_name = user.name if user and user.name else user.email.split('@')[0]
        
        topics_by_date = {}
        try:
            topics = Topic.query.filter_by(user_id=user_id).order_by(Topic.created_at.desc()).all()
            for topic in topics:
                date_str = topic.created_at.strftime('%Y-%m-%d')
                if date_str not in topics_by_date:
                    topics_by_date[date_str] = []
                topics_by_date[date_str].append(topic)
        except Exception as e:
            print(f"Error fetching topics: {str(e)}")
        
        use_socketio = request.args.get('socketio', 'false').lower() == 'true'
        template = 'chat_socketio.html' if use_socketio else 'chat.html'
        
        return render_template(template, user_id=user_id, user_name=user_name, topics_by_date=topics_by_date)
    except Exception as e:
        print(f"Error accessing chat: {str(e)}")
        return redirect('/')

@app.route('/logout')
def logout():
    response = make_response(redirect('/'))
    unset_jwt_cookies(response)
    return response

@app.route('/test-api')
def test_api():
    """Endpoint to test OpenRouter API connectivity"""
    test_message = "Hello, this is a test message. Please respond with 'OK' if you receive this."
    
    try:
        response = chat_with_openrouter(test_message)
        
        return jsonify({
            "status": "success",
            "response": response,
            "api_key_set": bool(OPENROUTER_API_KEY),
            "proxy_settings": {
                "http": http_proxy,
                "https": https_proxy
            },
            "environment": {
                "python_version": sys.version,
                "flask_version": flask.__version__,
                "requests_version": requests.__version__
            }
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "error": str(e),
            "traceback": traceback.format_exc(),
            "api_key_set": bool(OPENROUTER_API_KEY)
        }), 500

# SocketIO event handlers
@socketio.on('connect')
def handle_connect():
    print("Client connected")

@socketio.on('disconnect')
def handle_disconnect():
    print("Client disconnected")

@socketio.on('send_message')
def handle_message(data):
    try:
        emit('bot_typing', broadcast=False)
        
        try:
            response = chat_with_openrouter(data['message'])
        except Exception as e:
            error_msg = f"API Error: {str(e)}"
            print(error_msg)
            emit('receive_message', {
                'user': 'System', 
                'message': 'Sorry, I encountered an error. Please try again later.'
            }, broadcast=False)
            return
        
        emit('receive_message', {
            'user': 'AI Assistant', 
            'message': response
        }, broadcast=False)
        
        try:
            user_id = get_jwt_identity()
            if user_id:
                chat_entry = ChatHistory(
                    user_id=user_id,
                    message=data['message'],
                    response=response
                )
                db.session.add(chat_entry)
                db.session.commit()
        except Exception as e:
            print(f"Error saving chat history: {str(e)}")
            
    except Exception as e:
        print(f"Error in handle_message: {str(e)}")
        emit('receive_message', {
            'user': 'System', 
            'message': 'Sorry, I encountered an unexpected error.'
        }, broadcast=False)

# Database Health Check Endpoint
@app.route('/db-health')
def db_health_check():
    try:
        db.session.execute("SELECT 1")
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

# Health check endpoint for monitoring services
@app.route('/health')
def health_check():
    return jsonify({"status": "ok"}), 200

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

# Initialize database tables
initialize_app()

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, 
                host='0.0.0.0', 
                port=port, 
                debug=os.environ.get('FLASK_DEBUG', 'False') == 'True',
                log_output=True)