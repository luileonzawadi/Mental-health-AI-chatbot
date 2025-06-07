#!/usr/bin/env python
# Script to update the User table to add the is_medical_professional column

from app import app, db
from sqlalchemy import Column, Boolean

def update_user_table():
    with app.app_context():
        try:
            # Check if the column already exists
            columns = [column.name for column in db.inspect(db.engine).get_columns('users')]
            
            if 'is_medical_professional' not in columns:
                print("Adding 'is_medical_professional' column to users table...")
                # Add the column
                db.engine.execute('ALTER TABLE users ADD COLUMN is_medical_professional BOOLEAN DEFAULT FALSE')
                print("Column added successfully")
            else:
                print("'is_medical_professional' column already exists")
                
            return True
        except Exception as e:
            print(f"Error updating users table: {str(e)}")
            return False

if __name__ == "__main__":
    update_user_table()