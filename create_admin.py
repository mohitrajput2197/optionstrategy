# create_admin.py
from app import app, db, User
from werkzeug.security import generate_password_hash

def create_first_admin(username, password):
    with app.app_context():
        # Check if any admin already exists
        if User.query.filter_by(is_admin=True).first():
            print("An admin user already exists.")
            return

        # Check if the chosen username is taken
        if User.query.filter_by(username=username).first():
            print(f"Error: Username '{username}' is already taken.")
            return

        # Create the new admin user
        hashed_password = generate_password_hash(password)
        new_admin = User(username=username, password=hashed_password, is_admin=True)
        db.session.add(new_admin)
        db.session.commit()
        print(f"Admin user '{username}' created successfully!")

if __name__ == '__main__':
    print("--- Create First Admin User ---")
    admin_username = input("Enter admin username: ")
    admin_password = input("Enter admin password: ")
    
    if admin_username and admin_password:
        create_first_admin(admin_username, admin_password)
    else:
        print("Username and password cannot be empty.")