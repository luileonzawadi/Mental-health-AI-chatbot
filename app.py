import os
import base64
import time
import socket
import json
import traceback
import sys
import asyncio
import httpx
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
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='gevent')

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
    return db.session

async def chat_with_openrouter(message):
    try:
        system_instruction = (
    "Your role is to support users with their mental and emotional well-being by listening, offering gentle encouragement, "
    "and helping them reflect on their thoughts and feelings. "
    "Respond with empathy and avoid sounding robotic or overly clinical.Be normal as a human being "
    "If a user repeatedly asks something unrelated to health or mental wellness, kindly guide them back by saying: "
    "Allow them if they want to name you so that you can understand clearly how they feel and relate with them"
    "'I'm here to support your mental and emotional well-being. Would you like to talk about how you're feeling?'"
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
        url = "https://openrouter.ai/api/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
            "Content-Type": "application/json",
            "HTTP-Referer": request.host_url if request else "https://mental-health-ai-chatbot.onrender.com",
            "X-Title": "Mental Health AI Chatbot"
        }
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(url, headers=headers, json=data)
        if response.status_code == 200:
            response_data = response.json()
            return response_data["choices"][0]["message"]["content"]
        else:
            error_msg = f"API Error: Status {response.status_code}"
            print(error_msg)
            return f"I'm sorry, I couldn't process your message right now. Please try again later. (Error {response.status_code})"
    except Exception as e:
        print(f"Exception in chat_with_openrouter: {str(e)}")
        return "I'm sorry, I encountered an error processing your message. Please try again later."

@app.route('/')
def login_form():
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
async def process_chat():
    try:
        data = request.json
        message = data.get('message', '')
        topic_id = data.get('topic_id')
        topic_title = data.get('topic_title', 'New Conversation')
        
        if not message:
            return jsonify({"error": "No message provided"}), 400
            
        # Get response from OpenRouter
        response = await chat_with_openrouter(message)
        
        # Save to chat history if user is logged in
        try:
            from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
            valid_jwt = False
            try:
                verify_jwt_in_request(optional=True)
                valid_jwt = True
            except:
                pass
            
            if valid_jwt:
                user_id = get_jwt_identity()
                if user_id:
                    # Create a new topic if needed
                    if not topic_id:
                        # Use first few words of message as topic title if not provided
                        if topic_title == 'New Conversation' and len(message) > 0:
                            words = message.split()
                            topic_title = ' '.join(words[:3]) + ('...' if len(words) > 3 else '')
                        
                        new_topic = Topic(
                            user_id=user_id,
                            title=topic_title
                        )
                        db.session.add(new_topic)
                        db.session.flush()  # Get the ID without committing
                        topic_id = new_topic.id
                    
                    # Save the chat entry
                    chat_entry = ChatHistory(
                        user_id=user_id,
                        message=message,
                        response=response,
                        topic_id=topic_id
                    )
                    db.session.add(chat_entry)
                    db.session.commit()
                    
                    return jsonify({
                        "response": response,
                        "topic_id": topic_id,
                        "topic_title": topic_title
                    })
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
                topics_by_date[date_str].append({
                    'id': topic.id,
                    'title': topic.title,
                    'created_at': topic.created_at
                })
        except Exception as e:
            print(f"Error fetching topics: {str(e)}")
        return render_template('chat.html', user_id=user_id, user_name=user_name, topics_by_date=topics_by_date)
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
        # Use asyncio.run for sync context
        response = asyncio.run(chat_with_openrouter(test_message))
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
                "requests_version": httpx.__version__
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
async def handle_message(data):
    try:
        emit('bot_typing', broadcast=False)
        try:
            response = await chat_with_openrouter(data['message'])
        except Exception as e:
            error_msg = f"API Error: {str(e)}"
            print(error_msg)
            emit('receive_message', {
                'user': 'System', 
                'message': 'Sorry, I encountered an error. Please try again later.'
            }, broadcast=False)
            return
            
        topic_id = data.get('topic_id')
        topic_title = data.get('topic_title', 'New Conversation')
        
        emit('receive_message', {
            'user': 'AI Assistant', 
            'message': response
        }, broadcast=False)
        
        try:
            user_id = get_jwt_identity()
            if user_id:
                # Create a new topic if needed
                if not topic_id:
                    # Use first few words of message as topic title if not provided
                    if topic_title == 'New Conversation' and len(data['message']) > 0:
                        words = data['message'].split()
                        topic_title = ' '.join(words[:3]) + ('...' if len(words) > 3 else '')
                    
                    new_topic = Topic(
                        user_id=user_id,
                        title=topic_title
                    )
                    db.session.add(new_topic)
                    db.session.flush()  # Get the ID without committing
                    topic_id = new_topic.id
                
                # Save the chat entry
                chat_entry = ChatHistory(
                    user_id=user_id,
                    message=data['message'],
                    response=json.dumps(response),
                    topic_id=topic_id
                )
                db.session.add(chat_entry)
                db.session.commit()
                
                # Emit topic information back to client
                emit('topic_updated', {
                    'topic_id': topic_id,
                    'topic_title': topic_title,
                    'created_at': datetime.utcnow().strftime('%Y-%m-%d')
                })
        except Exception as e:
            print(f"Error saving chat history: {str(e)}")
    except Exception as e:
        print(f"Error in handle_message: {str(e)}")
        emit('receive_message', {
            'user': 'System', 
            'message': 'Sorry, I encountered an unexpected error.'
        }, broadcast=False)

def initialize_app():
    try:
        create_db_tables()
        print("Application initialization complete")
        print(f"Database URL: {app.config['SQLALCHEMY_DATABASE_URI']}")
    except Exception as e:
        print(f"Failed to initialize application: {str(e)}")
        raise

initialize_app()

# API endpoints for topic management
@app.route('/api/topics', methods=['GET'])
@jwt_required()
def get_topics():
    try:
        user_id = get_jwt_identity()
        topics = Topic.query.filter_by(user_id=user_id).order_by(Topic.created_at.desc()).all()
        topics_by_date = {}
        
        for topic in topics:
            date_str = topic.created_at.strftime('%Y-%m-%d')
            if date_str not in topics_by_date:
                topics_by_date[date_str] = []
            
            topics_by_date[date_str].append({
                'id': topic.id,
                'title': topic.title,
                'created_at': topic.created_at.isoformat()
            })
            
        return jsonify({"success": True, "topics_by_date": topics_by_date})
    except Exception as e:
        print(f"Error fetching topics: {str(e)}")
        return jsonify({"error": "Failed to fetch topics"}), 500

@app.route('/api/topics/<int:topic_id>', methods=['GET'])
@jwt_required()
def get_topic_history(topic_id):
    try:
        user_id = get_jwt_identity()
        # Verify the topic belongs to the user
        topic = Topic.query.filter_by(id=topic_id, user_id=user_id).first()
        if not topic:
            return jsonify({"error": "Topic not found"}), 404
            
        # Get chat history for this topic
        history = ChatHistory.query.filter_by(topic_id=topic_id).order_by(ChatHistory.timestamp).all()
        
        chat_history = []
        for entry in history:
            chat_history.append({
                'id': entry.id,
                'message': entry.message,
                'response': entry.response,
                'timestamp': entry.timestamp.isoformat()
            })
            
        return jsonify({
            "success": True, 
            "topic": {
                "id": topic.id,
                "title": topic.title,
                "created_at": topic.created_at.isoformat()
            },
            "history": chat_history
        })
    except Exception as e:
        print(f"Error fetching topic history: {str(e)}")
        return jsonify({"error": "Failed to fetch topic history"}), 500

@app.route('/api/topics/<int:topic_id>', methods=['PUT'])
@jwt_required()
def update_topic(topic_id):
    try:
        user_id = get_jwt_identity()
        data = request.json
        new_title = data.get('title')
        
        if not new_title:
            return jsonify({"error": "Title is required"}), 400
            
        # Verify the topic belongs to the user
        topic = Topic.query.filter_by(id=topic_id, user_id=user_id).first()
        if not topic:
            return jsonify({"error": "Topic not found"}), 404
            
        # Update the title
        topic.title = new_title
        db.session.commit()
        
        return jsonify({
            "success": True, 
            "topic": {
                "id": topic.id,
                "title": topic.title,
                "created_at": topic.created_at.isoformat()
            }
        })
    except Exception as e:
        print(f"Error updating topic: {str(e)}")
        return jsonify({"error": "Failed to update topic"}), 500

@app.route('/api/topics/<int:topic_id>', methods=['DELETE'])
@jwt_required()
def delete_topic(topic_id):
    try:
        user_id = get_jwt_identity()
        
        # Verify the topic belongs to the user
        topic = Topic.query.filter_by(id=topic_id, user_id=user_id).first()
        if not topic:
            return jsonify({"error": "Topic not found"}), 404
            
        # Delete associated chat history first
        ChatHistory.query.filter_by(topic_id=topic_id).delete()
        
        # Delete the topic
        db.session.delete(topic)
        db.session.commit()
        
        return jsonify({"success": True, "message": "Topic deleted successfully"})
    except Exception as e:
        print(f"Error deleting topic: {str(e)}")
        return jsonify({"error": "Failed to delete topic"}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app,
                host='0.0.0.0',
                port=port,
                debug=os.environ.get('FLASK_DEBUG', 'False') == 'True',
                log_output=True)