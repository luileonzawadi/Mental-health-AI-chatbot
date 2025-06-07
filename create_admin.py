#!/usr/bin/env python
# Script to create an admin user in the database

from app import app, db, User
import sys

def create_admin_user(email, password, name="Admin"):
    with app.app_context():
        try:
            # Check if the users table exists
            inspector = db.inspect(db.engine)
            if 'users' not in inspector.get_table_names():
                print("Creating database tables...")
                db.create_all()
                print("Tables created successfully")
            
            # Check if user already exists
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                print(f"User with email {email} already exists")
                return False
            
            # Create new admin user
            user = User(
                email=email,
                name=name,
                is_medical_professional=True
            )
            user.set_password(password)
            
            db.session.add(user)
            db.session.commit()
            print(f"Admin user {email} created successfully")
            return True
        except Exception as e:
            print(f"Error creating admin user: {str(e)}")
            return False

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python create_admin.py <email> <password> [name]")
        sys.exit(1)
    
    email = sys.argv[1]
    password = sys.argv[2]
    name = sys.argv[3] if len(sys.argv) > 3 else "Admin"
    
    success = create_admin_user(email, password, name)
    sys.exit(0 if success else 1)