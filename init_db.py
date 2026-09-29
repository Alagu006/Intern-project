#!/usr/bin/env python3
"""
Initialize the database tables for Secure File Share.
Works for both SQLite and PostgreSQL.
"""
import os
from app import create_app
from app.extensions import db
import app.models

app = create_app()

with app.app_context():
    # Ensure upload directory exists
    upload_dir = app.config.get("UPLOAD_FOLDER", "uploads")
    os.makedirs(upload_dir, exist_ok=True)
    staging_dir = app.config.get("UPLOAD_STAGING_DIR", "staging")
    os.makedirs(staging_dir, exist_ok=True)

    db.create_all()
    print("Database tables created successfully!")
    print(f"Using database: {app.config['SQLALCHEMY_DATABASE_URI']}")
