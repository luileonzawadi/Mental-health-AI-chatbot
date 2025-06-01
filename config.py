import os
from dotenv import load_dotenv

# Load variables from .env file
load_dotenv()

class Config:
    # Core Secrets
    SECRET_KEY = os.getenv('SECRET_KEY', 'your_super_secret_key')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'your_jwt_secret_key')

    # Database
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # File Uploads
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB max file size
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'mp3', 'wav'}

    # Encryption
    FERNET_KEY = os.getenv('FERNET_KEY')

    # OpenAI
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')

 

