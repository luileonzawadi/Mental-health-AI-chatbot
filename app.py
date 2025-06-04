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
from datetime import datetime
from flask import request, jsonify
import os
import mimetypes

# Load .env config
load_dotenv()
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY")
FERNET_KEY = os.environ.get("FERNET_KEY")

# For debugging, print only first few characters of API key
print("OPENROUTER_API_KEY loaded:", OPENROUTER_API_KEY[:10] + "..." if OPENROUTER_API_KEY else "Not found")

# Setup app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_secret_key_here')
# Use DATABASE_URL for Heroku or fallback to SQLite for local development
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
# Fix for Heroku PostgreSQL URL format
if app.config['SQLALCHEMY_DATABASE_URI'] and app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgres://'):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'your_jwt_secret_here')
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_SECURE'] = os.environ.get('PRODUCTION', 'False') == 'True'
app.config['JWT_COOKIE_HTTPONLY'] = True
app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
app.config['JWT_COOKIE_CSRF_PROTECT'] = False

socketio = SocketIO(app, cors_allowed_origins="*")
db = SQLAlchemy(app)
jwt = JWTManager(app)
fernet = Fernet(FERNET_KEY.encode() if FERNET_KEY else os.urandom(32))

# --------------------
# Database Models
# --------------------
class User(db.Model):
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
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    message = db.Column(db.Text, nullable=False)
    response = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    topic_id = db.Column(db.Integer, db.ForeignKey('topic.id'), nullable=True)

class Topic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    title = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    history = db.relationship('ChatHistory', backref='topic', lazy=True)

class FileUpload(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # If you want to link to a user
    filename = db.Column(db.String(255), nullable=False)
    filetype = db.Column(db.String(50), nullable=False)  # e.g., 'document' or 'audio'
    upload_time = db.Column(db.DateTime, default=datetime.utcnow)
    topic_id = db.Column(db.Integer, db.ForeignKey('topic.id'), nullable=True)  # Optional: link to a conversation/topic

    def as_dict(self):
        return {
            "id": self.id,
            "filename": self.filename,
            "filetype": self.filetype,
            "upload_time": self.upload_time.isoformat(),
            "topic_id": self.topic_id
        }
# -------------------
# AI Logic (OpenRouter)
# -------------------
def chat_with_openrouter(message):
    try:
        url = "https://openrouter.ai/api/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
            "Content-Type": "application/json"
        }

        system_instruction = (
            "You are a friendly, compassionate AI assistant trained in Cognitive Behavioral Therapy (CBT) "
            " You help users improve their mental and emotional well-being. "
            "Only respond to questions related to health and mental health. If a user asks anything unrelated, "
            "gently redirect them back to mental wellness topics. Avoid topics such as sports, politics, or technology."
        )

        data = {
            "model": "deepseek/deepseek-r1-0528:free",
            "messages": [
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": message}
            ]
        }

        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"]
        else:
            print("OpenRouter Error:", response.text)
            return "Sorry, I couldn't process your message right now."

    except Exception as e:
        print(f"OpenRouter API Error: {e}")
        return "Sorry, I couldn't process your message right now."

# --------------------
# Routes
# --------------------
@app.route('/')
def login_form():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    password = request.form.get('password')
    user = db.session.query(User).filter_by(email=email).first()
    if not user or not user.check_password(password):
        return "Invalid credentials", 401
    access_token = create_access_token(identity=str(user.id))
    response = make_response(redirect(url_for('chat')))
    set_access_cookies(response, access_token)
    return response

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        if User.query.filter_by(email=email).first():
            return "Email already exists", 400
        private_key = public.PrivateKey.generate()
        encrypted_private = fernet.encrypt(bytes(private_key))
        user = User(
            email=email,
            public_key=base64.b64encode(bytes(private_key.public_key)).decode(),
            private_key=base64.b64encode(encrypted_private).decode()
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login_form'))
    return render_template('register.html')

@app.route('/chat', methods=['GET', 'POST'])
@jwt_required()
def chat():
    user_id = int(get_jwt_identity())
    user = db.session.get(User, user_id)
    bot_reply = None

    if request.method == 'POST':
        user_message = request.form.get('message')
        conversation_id = request.form.get('conversation_id')

        if not user_message or user_message.strip() == "":
            return jsonify({"error": "Message cannot be empty."}), 400

        if conversation_id:
            topic = db.session.get(Topic, int(conversation_id))
        else:
            topic = Topic(user_id=user.id, title=user_message)
            db.session.add(topic)
            db.session.commit()

        bot_reply = chat_with_openrouter(user_message)
        chat_record = ChatHistory(user_id=user.id, message=user_message, response=bot_reply, topic_id=topic.id)
        db.session.add(chat_record)
        db.session.commit()

        return jsonify({"bot_reply": bot_reply, "conversation_id": topic.id})

    topics = Topic.query.filter_by(user_id=user.id).all()
    return render_template('index.html', username=user.email, bot_reply=bot_reply, topics=topics)

@app.route('/conversations')
@jwt_required()
def get_conversations():
    user_id = int(get_jwt_identity())
    topics = Topic.query.filter_by(user_id=user_id).order_by(Topic.created_at.desc()).all()
    return jsonify([
        {
            "id": t.id,
            "title": t.title,
            "created_at": t.created_at.strftime("%Y-%m-%d")
        } for t in topics
    ])

@app.route('/conversations/<int:topic_id>/delete', methods=['DELETE'])
@jwt_required()
def delete_conversation(topic_id):
    user_id = int(get_jwt_identity())
    topic = db.session.query(Topic).filter_by(id=topic_id, user_id=user_id).first()
    if topic:
        ChatHistory.query.filter_by(topic_id=topic_id).delete()
        db.session.delete(topic)
        db.session.commit()
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Topic not found or unauthorized"}), 404


@app.route('/conversations/<int:topic_id>/edit', methods=['POST'])
@jwt_required()
def edit_conversation(topic_id):
    new_title = request.json.get("title")
    topic = db.session.get(Topic, topic_id)
    if topic:
        topic.title = new_title
        db.session.commit()
        return jsonify({"success": True})
    return jsonify({"success": False}), 404

# Set upload folder - use a folder that Heroku can write to temporarily
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


@app.route('/upload', methods=['POST'])
@jwt_required()
def upload_document():
    user_id = int(get_jwt_identity())
    topic_id = request.form.get('topic_id')
    if 'document' not in request.files:
        return jsonify({'success': False, 'error': 'No file part'}), 400
    file = request.files['document']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No selected file'}), 400
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(filepath)

    # Save metadata in DB
    file_record = FileUpload(
        user_id=user_id,
        filename=file.filename,
        filetype='document',
        topic_id=topic_id
    )
    db.session.add(file_record)
    db.session.commit()

    # --- Analyze file content ---
    feedback = "Sorry, I couldn't analyze this file."
    mimetype, _ = mimetypes.guess_type(file.filename)
    try:
        # Example for .txt files
        if file.filename.endswith('.txt'):
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            prompt = f"Analyze the following document and provide feedback for mental health support:\n\n{content[:2000]}"
            feedback = chat_with_openrouter(prompt)
        # You can add PDF/DOCX support here if needed
    except Exception as e:
        feedback = f"Error analyzing file: {e}"

    # Optionally, save feedback as a chat message
    if topic_id:
        chat_record = ChatHistory(
            user_id=user_id,
            message=f"[Document uploaded: {file.filename}]",
            response=feedback,
            topic_id=topic_id
        )
        db.session.add(chat_record)
        db.session.commit()

    return jsonify({'success': True, 'filename': file.filename, 'feedback': feedback})

@app.route('/logout')
def logout():
    response = make_response(redirect(url_for('login_form')))
    unset_jwt_cookies(response)
    return response

# --------------------
# SocketIO Chat
# --------------------
@socketio.on('send_message')
def handle_send_message(data):
    user_message = data.get('message')
    user_id = data.get('user_id')

    bot_reply = chat_with_openrouter(user_message)

    history = ChatHistory(user_id=user_id, message=user_message, response=bot_reply)
    db.session.add(history)
    db.session.commit()

    emit('receive_message', {'user': 'CalmBot', 'message': bot_reply}, to=request.sid)

# --------------------
# Run App
# --------------------
if __name__ == '__main__':
    import eventlet
    import eventlet.wsgi
    with app.app_context():
        db.create_all()
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host='0.0.0.0', port=port)