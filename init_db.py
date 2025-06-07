#!/usr/bin/env python
# This script initializes the database for the Mental Health AI Chatbot
# Run this script directly to create all necessary database tables

import os
import sys
from sqlalchemy import text
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Create a minimal Flask app for database initialization
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
if app.config['SQLALCHEMY_DATABASE_URI'] and app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgres://'):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# Define minimal models
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    public_key = db.Column(db.Text, nullable=True)
    private_key = db.Column(db.Text, nullable=True)

class ChatHistory(db.Model):
    __tablename__ = 'chat_history'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    message = db.Column(db.Text, nullable=False)
    response = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, nullable=True)
    topic_id = db.Column(db.Integer, db.ForeignKey('topics.id'), nullable=True)

class Topic(db.Model):
    __tablename__ = 'topics'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    title = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, nullable=True)

class FileUpload(db.Model):
    __tablename__ = 'file_uploads'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    filename = db.Column(db.String(255), nullable=False)
    filetype = db.Column(db.String(50), nullable=False)
    upload_time = db.Column(db.DateTime, nullable=True)
    topic_id = db.Column(db.Integer, db.ForeignKey('topics.id'), nullable=True)

def init_db():
    """Initialize the database by creating all tables"""
    try:
        with app.app_context():
            # For PostgreSQL, ensure schema exists
            if 'postgresql' in app.config['SQLALCHEMY_DATABASE_URI']:
                db.session.execute(text("CREATE SCHEMA IF NOT EXISTS public"))
                db.session.commit()
                print("Created public schema")
            
            # Create all tables
            db.create_all()
            print("All database tables created successfully")
            
            # Verify tables were created
            if 'postgresql' in app.config['SQLALCHEMY_DATABASE_URI']:
                from sqlalchemy import inspect
                inspector = inspect(db.engine)
                tables = inspector.get_table_names()
                print(f"Tables in database: {tables}")
                
                if 'users' not in tables:
                    print("WARNING: 'users' table was not created!")
                else:
                    print("Verified 'users' table exists")
                    
        return True
    except Exception as e:
        print(f"Error initializing database: {str(e)}")
        return False

if __name__ == "__main__":
    print(f"Initializing database at: {app.config['SQLALCHEMY_DATABASE_URI']}")
    success = init_db()
    sys.exit(0 if success else 1)