# 📚 Documentation Index

Complete guide to the Secure File Sharing System — Module 4

---

## 🚀 Getting Started

Start here if this is your first time:

1. **[GET_STARTED.md](GET_STARTED.md)** — 5-minute quick setup
2. **[QUICKSTART.md](QUICKSTART.md)** — Detailed setup with test examples
3. **[README.md](README.md)** — Architecture overview and security notes

---

## 📖 Core Documentation

### For Developers

- **[API.md](API.md)** — Complete REST API reference with cURL examples
- **[FLOW_DIAGRAM.md](FLOW_DIAGRAM.md)** — Visual flow diagrams (sharing, permissions, audit)
- **[schema.sql](schema.sql)** — PostgreSQL schema reference with sample queries

### For DevOps

- **[DEPLOYMENT.md](DEPLOYMENT.md)** — Production deployment guide
  - Environment setup
  - Nginx reverse proxy config
  - Systemd service
  - Docker Compose
  - Security hardening checklist
  - Backup strategy

---

## ✅ Verification

- **[IMPLEMENTATION_CHECKLIST.md](IMPLEMENTATION_CHECKLIST.md)** — Complete requirements checklist
- **[MODULE_4_SUMMARY.md](MODULE_4_SUMMARY.md)** — Implementation summary and deliverables

---

## 🧪 Testing

- **[tests/test_shares.py](tests/test_shares.py)** — Pytest test suite
  - Permission enforcement
  - Expiry & revocation
  - Password verification
  - QR code generation
  - Audit logging

Run: `pytest tests/ -v`

---

## 🔧 Tools & Utilities

### Postman Collection
**[postman_collection.json](postman_collection.json)**
- Pre-configured API requests
- Auto-variable capture (tokens, IDs)
- Import into Postman and test instantly

### OpenAPI Spec
**[openapi.yaml](openapi.yaml)**
- OpenAPI 3.1 specification
- Complete schemas and endpoints
- View in [Swagger Editor](https://editor.swagger.io)

### Database Management
**[manage.py](manage.py)**
```bash
python manage.py init      # Initialize migrations
python manage.py migrate   # Create migration
python manage.py upgrade   # Apply migrations
python manage.py downgrade # Rollback
```

### Setup Script
**[setup.sh](setup.sh)**
```bash
./setup.sh  # Automated environment setup
```

---

## 📂 Code Structure

```
secure_file_share/
├── app/
│   ├── auth/          — JWT decorators, login/register
│   ├── crypto/        — AES-256-GCM encryption helpers
│   ├── files/         — File upload/list endpoints
│   ├── shares/        — Module 4 core (8 endpoints)
│   ├── models/        — SQLAlchemy models (User, File, Share, AccessLog)
│   ├── config.py      — Configuration classes
│   └── extensions.py  — SQLAlchemy, Migrate, Limiter
├── tests/             — Pytest test suite
├── static/            — Frontend example (share.html)
└── [documentation files]
```

---

## 🔐 Security Features

Implemented and documented:

✅ **Token Generation:** CSPRNG (256-bit entropy)  
✅ **Password Hashing:** Argon2id  
✅ **Rate Limiting:** 5 attempts / 15 min / IP  
✅ **Permission Model:** Granular (view/download/edit/reshare)  
✅ **Expiry Enforcement:** Auto-invalidate after timestamp  
✅ **Revocation:** Soft-delete with audit trail  
✅ **Audit Logging:** Every access attempt (success + failure)  
✅ **File Encryption:** AES-256-GCM at rest  
✅ **In-Memory Decryption:** No plaintext on disk  
✅ **HTTPS Only:** TLS 1.2+ required  

---

## 📊 Feature Matrix

| Feature | Status | Docs |
|---------|--------|------|
| User Auth (JWT) | ✅ | [API.md](API.md#auth) |
| File Upload (Encrypted) | ✅ | [API.md](API.md#files) |
| Share Creation | ✅ | [API.md](API.md#post-apifilesiidshare) |
| Permission Control | ✅ | [README.md](README.md#permission-model) |
| Password Protection | ✅ | [FLOW_DIAGRAM.md](FLOW_DIAGRAM.md#3-password-verification-flow) |
| Expiry & Revocation | ✅ | [API.md](API.md#patch-apishares-shareid) |
| QR Code | ✅ | [API.md](API.md#get-apishares-tokenqrcode) |
| Audit Trail | ✅ | [FLOW_DIAGRAM.md](FLOW_DIAGRAM.md#4-audit-trail-flow) |
| Rate Limiting | ✅ | [FLOW_DIAGRAM.md](FLOW_DIAGRAM.md#7-rate-limiting-password-verification) |
| Tests | ✅ | [tests/test_shares.py](tests/test_shares.py) |

---

## 🎯 Common Tasks

### How do I...

**...create a share link?**  
→ [API.md: POST /api/files/{id}/share](API.md#post-apifilesiidshare)

**...add password protection?**  
→ Include `"password": "yourpass"` in the share creation body

**...set an expiry date?**  
→ Include `"expires_at": "2027-12-31T23:59:59Z"` in ISO-8601 format

**...revoke a share?**  
→ [API.md: DELETE /api/shares/{id}](API.md#delete-apishares-shareid)

**...view audit logs?**  
→ Query `access_logs` table (see [schema.sql](schema.sql#L58))

**...deploy to production?**  
→ Follow [DEPLOYMENT.md](DEPLOYMENT.md)

**...run tests?**  
→ `pytest tests/ -v`

**...understand the flow?**  
→ [FLOW_DIAGRAM.md](FLOW_DIAGRAM.md)

---

## 📞 Support

### Issue Resolution

1. Check **[QUICKSTART.md](QUICKSTART.md#troubleshooting)** troubleshooting section
2. Check **[GET_STARTED.md](GET_STARTED.md#troubleshooting)** for common errors
3. Review **[IMPLEMENTATION_CHECKLIST.md](IMPLEMENTATION_CHECKLIST.md)** to verify setup

### Documentation Coverage

- ✅ Setup & Installation
- ✅ API Reference
- ✅ Security Architecture
- ✅ Testing Guide
- ✅ Production Deployment
- ✅ Flow Diagrams
- ✅ Database Schema
- ✅ Troubleshooting

---

## 📦 Files Reference

| File | Purpose |
|------|---------|
| `GET_STARTED.md` | 5-minute quick start |
| `QUICKSTART.md` | Detailed setup guide |
| `README.md` | Architecture & security overview |
| `API.md` | Complete API reference |
| `DEPLOYMENT.md` | Production deployment guide |
| `FLOW_DIAGRAM.md` | Visual flow diagrams |
| `IMPLEMENTATION_CHECKLIST.md` | Requirements verification |
| `MODULE_4_SUMMARY.md` | Implementation summary |
| `schema.sql` | Database schema reference |
| `openapi.yaml` | OpenAPI 3.1 spec |
| `postman_collection.json` | Postman API collection |
| `requirements.txt` | Python dependencies |
| `wsgi.py` | Application entry point |
| `manage.py` | Database migration CLI |
| `setup.sh` | Automated setup script |
| `.env.example` | Environment variables template |

---

## 🏁 Quick Links

- 🚀 [Get Started](GET_STARTED.md)
- 📖 [API Reference](API.md)
- 🔐 [Security](README.md#security-notes)
- 🧪 [Testing](tests/test_shares.py)
- 🚢 [Deploy](DEPLOYMENT.md)
- 📊 [Diagrams](FLOW_DIAGRAM.md)

---

**Module 4: Access Control & Secure File Sharing — Complete Implementation**
