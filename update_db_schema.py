#!/usr/bin/env python
# Script to update the database schema with new columns

import os
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def update_db_schema():
    # Get database URL from environment
    db_url = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
    if db_url and db_url.startswith('postgres://'):
        db_url = db_url.replace('postgres://', 'postgresql://', 1)
    
    print(f"Connecting to database: {db_url}")
    
    # Create engine
    engine = create_engine(db_url)
    
    # Execute ALTER TABLE statements
    with engine.connect() as conn:
        try:
            # Check if name column exists
            result = conn.execute(text("SELECT column_name FROM information_schema.columns WHERE table_name='users' AND column_name='name'"))
            if result.rowcount == 0:
                print("Adding 'name' column to users table...")
                conn.execute(text("ALTER TABLE users ADD COLUMN name VARCHAR(100)"))
                conn.commit()
                print("Added 'name' column successfully")
            else:
                print("'name' column already exists")
                
            # Check if is_medical_professional column exists
            result = conn.execute(text("SELECT column_name FROM information_schema.columns WHERE table_name='users' AND column_name='is_medical_professional'"))
            if result.rowcount == 0:
                print("Adding 'is_medical_professional' column to users table...")
                conn.execute(text("ALTER TABLE users ADD COLUMN is_medical_professional BOOLEAN DEFAULT FALSE"))
                conn.commit()
                print("Added 'is_medical_professional' column successfully")
            else:
                print("'is_medical_professional' column already exists")
                
            return True
        except Exception as e:
            print(f"Error updating database schema: {str(e)}")
            return False

if __name__ == "__main__":
    update_db_schema()