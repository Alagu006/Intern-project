#!/usr/bin/env python
"""
Database management CLI.

Usage:
    python manage.py init       — initialize migrations folder
    python manage.py migrate    — generate migration from model changes
    python manage.py upgrade    — apply pending migrations
    python manage.py downgrade  — rollback one migration
"""

import sys
from flask_migrate import init, migrate, upgrade, downgrade
from app import create_app

app = create_app()

commands = {
    "init": lambda: init(),
    "migrate": lambda: migrate(message=input("Migration message: ") or "auto"),
    "upgrade": lambda: upgrade(),
    "downgrade": lambda: downgrade(),
}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in commands:
        print(__doc__)
        sys.exit(1)

    with app.app_context():
        commands[sys.argv[1]]()
