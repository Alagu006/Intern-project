#!/bin/bash
set -e

echo "=== Secure File Sharing System — Setup ==="

# Check Python version
python3 --version || { echo "Python 3.8+ required"; exit 1; }

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Check for .env file
if [ ! -f ".env" ]; then
    echo "Creating .env from example..."
    cp .env.example .env
    echo "⚠️  Edit .env and set DATABASE_URL, JWT_SECRET_KEY, and other values!"
fi

# Create upload directory
mkdir -p /var/secure_files || mkdir -p ./uploads

echo ""
echo "✓ Setup complete!"
echo ""
echo "Next steps:"
echo "  1. Edit .env with your database credentials and secrets"
echo "  2. Initialize database: python manage.py init"
echo "  3. Create migrations: python manage.py migrate"
echo "  4. Apply migrations: python manage.py upgrade"
echo "  5. Run tests: pytest tests/ -v"
echo "  6. Start server: python wsgi.py"
echo ""
