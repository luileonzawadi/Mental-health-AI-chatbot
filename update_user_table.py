#!/usr/bin/env python
# Script to update the User table to add the name column

from app import app, db
from sqlalchemy import Column, String

def update_user_table():
    with app.app_context():
        try:
            # Check if the name column already exists
            columns = [column.name for column in db.inspect(db.engine).get_columns('users')]
            
            if 'name' not in columns:
                print("Adding 'name' column to users table...")
                # Add the name column
                db.engine.execute('ALTER TABLE users ADD COLUMN name VARCHAR(100)')
                print("Column added successfully")
            else:
                print("'name' column already exists")
                
            return True
        except Exception as e:
            print(f"Error updating users table: {str(e)}")
            return False

if __name__ == "__main__":
    update_user_table()