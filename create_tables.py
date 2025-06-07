# filepath: c:\Users\leonm\Desktop\Mental health AI chatbot\create_tables.py
from app import app, db
import sys

def main():
    try:
        with app.app_context():
            # Check if we're using PostgreSQL
            if 'postgresql' in app.config['SQLALCHEMY_DATABASE_URI']:
                # Create schema if needed
                db.session.execute(db.text("CREATE SCHEMA IF NOT EXISTS public"))
                db.session.commit()
                
                # Check if tables exist
                inspector = db.inspect(db.engine)
                tables = inspector.get_table_names()
                print(f"Existing tables: {tables}")
                
                # Create tables if they don't exist
                if 'users' not in tables:
                    print("Creating database tables...")
                    db.create_all()
                    print("Database tables created successfully")
                else:
                    print("Tables already exist, skipping creation")
            else:
                # For SQLite or other databases
                db.create_all()
                print("Database tables created successfully")
    except Exception as e:
        print(f"Error creating database tables: {str(e)}")
        sys.exit(1)
    
    print("Tables created successfully.")
    return 0

if __name__ == "__main__":
    sys.exit(main())