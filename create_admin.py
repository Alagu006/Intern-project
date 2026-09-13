#!/usr/bin/env python3
"""
Create an admin user for the Secure File Sharing System.

Usage:
    python create_admin.py
    
Or with custom credentials:
    python create_admin.py --username admin --email admin@example.com --password SecurePass123!
"""

import sys
import getpass
import argparse
from app import create_app
from app.extensions import db
from app.models import User


def create_admin_user(username, email, password):
    """Create an admin user."""
    app = create_app()
    
    with app.app_context():
        # Check if user already exists
        existing = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing:
            print(f"❌ Error: User with username '{username}' or email '{email}' already exists.")
            return False
        
        # Create admin user
        admin = User(
            username=username,
            email=email,
            role="admin",
            is_active=True
        )
        admin.set_password(password)
        
        db.session.add(admin)
        db.session.commit()
        
        print(f"✅ Admin user created successfully!")
        print(f"   Username: {admin.username}")
        print(f"   Email: {admin.email}")
        print(f"   Role: {admin.role}")
        print(f"   ID: {admin.id}")
        print(f"\n🔐 You can now log in with these credentials.")
        
        return True


def main():
    parser = argparse.ArgumentParser(description="Create an admin user")
    parser.add_argument("--username", default="admin", help="Admin username")
    parser.add_argument("--email", default="admin@secure-files.local", help="Admin email")
    parser.add_argument("--password", help="Admin password (will prompt if not provided)")
    
    args = parser.parse_args()
    
    # Get password
    if args.password:
        password = args.password
    else:
        print("Creating admin user...")
        print(f"Username: {args.username}")
        print(f"Email: {args.email}")
        print()
        password = getpass.getpass("Enter password: ")
        password_confirm = getpass.getpass("Confirm password: ")
        
        if password != password_confirm:
            print("❌ Error: Passwords do not match.")
            return 1
        
        if len(password) < 8:
            print("❌ Error: Password must be at least 8 characters long.")
            return 1
    
    # Create admin
    success = create_admin_user(args.username, args.email, password)
    
    return 0 if success else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n❌ Cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)
