# Quick Start Guide

Get the Secure File Sharing System running in under 5 minutes.

---

## Prerequisites

- Python 3.8+
- PostgreSQL 12+ (or use SQLite for testing)
- Redis (optional, for production rate limiting)

---

## Installation

### 1. Clone & Setup
```bash
cd secure_file_share
chmod +x setup.sh
./setup.sh
source venv/bin/activate  # or `venv\Scripts\activate` on Windows
```

### 2. Configure Environment
Edit `.env`:
```bash
DATABASE_URL=postgresql://postgres:password@localhost:5432/secure_files
JWT_SECRET_KEY=your-random-secret-here
BASE_URL=https://localhost:5000
```

Generate secrets:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### 3. Initialize Database
```bash
python manage.py init      # create migrations folder
python manage.py migrate   # generate initial migration
python manage.py upgrade   # apply migration
```

Verify:
```bash
psql $DATABASE_URL -c "\dt"
# Should show: users, files, shares, access_logs
```

---

## Run the Server

### Development (with auto-reload)
```bash
FLASK_APP=wsgi FLASK_ENV=development flask run --cert=adhoc --port=5000
```

Visit: `https://localhost:5000`

---

## Test the API

### 1. Register a user
```bash
curl -k -X POST https://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "email": "alice@test.com",
    "password": "Test1234!"
  }'
```

### 2. Login
```bash
TOKEN=$(curl -k -X POST https://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@test.com",
    "password": "Test1234!"
  }' | jq -r .access_token)

echo "Token: $TOKEN"
```

### 3. Upload a file
```bash
echo "Hello, secure world!" > test.txt

FILE_ID=$(curl -k -X POST https://localhost:5000/api/files \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@test.txt" | jq -r .file.id)

echo "File ID: $FILE_ID"
```

### 4. Create a share link
```bash
SHARE=$(curl -k -X POST "https://localhost:5000/api/files/$FILE_ID/share" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "permissions": {
      "can_view": true,
      "can_download": true
    },
    "password": "secret123",
    "expires_at": "2027-12-31T23:59:59Z"
  }')

echo "$SHARE" | jq

SHARE_TOKEN=$(echo "$SHARE" | jq -r .shares[0].share_token)
echo "Share token: $SHARE_TOKEN"
```

### 5. Access the share (anonymous)
```bash
# Try without password → 401
curl -k "https://localhost:5000/api/shares/$SHARE_TOKEN/access"

# Verify password → get grant token
GRANT=$(curl -k -X POST "https://localhost:5000/api/shares/$SHARE_TOKEN/verify-password" \
  -H "Content-Type: application/json" \
  -d '{"password":"secret123"}' | jq -r .grant_token)

echo "Grant token: $GRANT"

# Access with grant → success
curl -k "https://localhost:5000/api/shares/$SHARE_TOKEN/access" \
  -H "X-Share-Grant: $GRANT" | jq
```

### 6. Download the file
```bash
curl -k "https://localhost:5000/api/shares/$SHARE_TOKEN/download" \
  -H "X-Share-Grant: $GRANT" \
  -o downloaded.txt

cat downloaded.txt
# → Hello, secure world!
```

### 7. Get QR code
```bash
curl -k "https://localhost:5000/api/shares/$SHARE_TOKEN/qrcode" \
  -H "X-Share-Grant: $GRANT" \
  -o qr.png

open qr.png  # macOS
# xdg-open qr.png  # Linux
# start qr.png     # Windows
```

---

## Run Tests
```bash
pytest tests/ -v
```

All tests should pass ✓

---

## Import Postman Collection
1. Open Postman
2. Import → `postman_collection.json`
3. Set `base_url` variable to `https://localhost:5000`
4. Run requests in order (Register → Login → Upload → Share)

---

## View OpenAPI Spec
```bash
# Install Swagger UI viewer (optional)
pip install connexion[swagger-ui]

# Or paste openapi.yaml into https://editor.swagger.io
```

---

## Next Steps

- Read [API.md](API.md) for full endpoint documentation
- Read [DEPLOYMENT.md](DEPLOYMENT.md) for production setup
- Check [README.md](README.md) for architecture overview
- Try the frontend: open `static/share.html` in a browser

---

## Troubleshooting

### "SSL: CERTIFICATE_VERIFY_FAILED"
Use `-k` flag with curl, or set up a proper cert.

### "ModuleNotFoundError"
```bash
source venv/bin/activate
pip install -r requirements.txt
```

### "relation does not exist"
```bash
python manage.py upgrade
```

### "Rate limit exceeded"
Wait 15 minutes, or disable rate limiting in config:
```python
# config.py
RATELIMIT_ENABLED = False
```

### PostgreSQL connection issues
Check that PostgreSQL is running:
```bash
psql $DATABASE_URL -c "SELECT version();"
```

---

## Support

For issues, check the full documentation:
- [README.md](README.md) — Architecture & security
- [API.md](API.md) — Complete API reference
- [DEPLOYMENT.md](DEPLOYMENT.md) — Production setup
- [schema.sql](schema.sql) — Database schema reference
