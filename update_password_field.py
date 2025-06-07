#!/usr/bin/env python
# Script to update the password field length in the database

import os
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def update_password_field():
    # Get database URL from environment
    db_url = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
    if db_url and db_url.startswith('postgres://'):
        db_url = db_url.replace('postgres://', 'postgresql://', 1)
    
    print(f"Connecting to database: {db_url}")
    
    # Create engine
    engine = create_engine(db_url)
    
    # Execute ALTER TABLE statement
    with engine.connect() as conn:
        try:
            conn.execute(text("ALTER TABLE users ALTER COLUMN password TYPE VARCHAR(255)"))
            conn.commit()
            print("Successfully altered password field to VARCHAR(255)")
            return True
        except Exception as e:
            print(f"Error altering password field: {str(e)}")
            return False

if __name__ == "__main__":
    update_password_field()