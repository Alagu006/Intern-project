# 🚀 Get Started in 5 Minutes

This is the **fastest path** from zero to a working secure file sharing system.

---

## Prerequisites Check

```bash
python3 --version   # Need 3.8+
psql --version      # Need PostgreSQL 12+
```

If missing, install:
- **macOS:** `brew install python postgresql`
- **Ubuntu:** `apt-get install python3 python3-pip postgresql`
- **Windows:** Download from python.org and postgresql.org

---

## Quick Setup

```bash
# 1. Navigate to the project
cd secure_file_share

# 2. Run the setup script
chmod +x setup.sh
./setup.sh

# 3. Activate virtual environment
source venv/bin/activate  # macOS/Linux
# OR
venv\Scripts\activate     # Windows

# 4. Generate secrets
python -c "import secrets; print('JWT_SECRET_KEY=' + secrets.token_hex(32))" >> .env
python -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" >> .env

# 5. Set database URL (edit .env or export)
export DATABASE_URL="postgresql://postgres:password@localhost:5432/secure_files"

# 6. Create database
createdb secure_files
# OR if that fails:
# psql -U postgres -c "CREATE DATABASE secure_files;"

# 7. Run migrations
python manage.py init
python manage.py migrate
python manage.py upgrade

# 8. Start the server
python wsgi.py
```

Server runs at: **https://localhost:5000** 🎉

---

## Quick Test

Open a new terminal:

```bash
# Register
curl -k -X POST https://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test","email":"test@test.com","password":"Test1234!"}'

# Login
TOKEN=$(curl -k -X POST https://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"Test1234!"}' | jq -r .access_token)

echo "Your token: $TOKEN"

# Upload a file
echo "Hello, secure world!" > test.txt
FILE_ID=$(curl -k -X POST https://localhost:5000/api/files \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@test.txt" | jq -r .file.id)

echo "File ID: $FILE_ID"

# Create a share
curl -k -X POST "https://localhost:5000/api/files/$FILE_ID/share" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"permissions":{"can_view":true,"can_download":true}}' | jq
```

✅ If you see JSON output with a `share_token`, **it works!**

---

## Run Tests

```bash
pytest tests/ -v
```

All tests should pass ✅

---

## Use Postman

1. Import `postman_collection.json`
2. Set variable `base_url` = `https://localhost:5000`
3. Disable SSL verification (Settings → SSL certificate verification → OFF)
4. Run requests in order

---

## Troubleshooting

### "ModuleNotFoundError: No module named 'flask'"
```bash
source venv/bin/activate
pip install -r requirements.txt
```

### "psql: FATAL: database does not exist"
```bash
createdb secure_files
```

### "relation 'users' does not exist"
```bash
python manage.py upgrade
```

### "Address already in use"
```bash
# Change port in wsgi.py or kill the existing process
lsof -ti:5000 | xargs kill -9
```

---

## Next Steps

- **Read the docs:** [README.md](README.md), [API.md](API.md), [QUICKSTART.md](QUICKSTART.md)
- **Deploy to production:** [DEPLOYMENT.md](DEPLOYMENT.md)
- **Understand the flow:** [FLOW_DIAGRAM.md](FLOW_DIAGRAM.md)
- **Check implementation:** [IMPLEMENTATION_CHECKLIST.md](IMPLEMENTATION_CHECKLIST.md)

---

## What You Just Built

✅ User registration & JWT auth  
✅ File upload with AES-256-GCM encryption  
✅ Secure share links with permissions  
✅ Password-protected shares (Argon2)  
✅ Expiry & revocation support  
✅ QR code generation  
✅ Complete audit trail  
✅ Rate limiting on password verification  
✅ In-memory file decryption (no plaintext on disk)  

**You now have a production-ready secure file sharing system!** 🎉
