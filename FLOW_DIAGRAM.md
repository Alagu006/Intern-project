# Secure File Sharing Flow Diagrams

## 1. Complete Sharing Flow (Happy Path)

```
┌─────────────┐                                    ┌─────────────┐
│   Owner     │                                    │  Recipient  │
│   (Alice)   │                                    │    (Bob)    │
└──────┬──────┘                                    └──────┬──────┘
       │                                                  │
       │ 1. Upload File                                  │
       ├─────────POST /api/files───────────────────────┐ │
       │         (encrypted with AES-256-GCM)           │ │
       │◄────────file_id = uuid─────────────────────────┘ │
       │                                                  │
       │ 2. Create Share                                 │
       ├─────────POST /api/files/{id}/share────────────┐ │
       │         {                                       │ │
       │           recipient_ids: [bob_id],              │ │
       │           permissions: {can_download: true},    │ │
       │           password: "secret123",                │ │
       │           expires_at: "2027-12-31"              │ │
       │         }                                       │ │
       │◄────────share_token, share_url─────────────────┘ │
       │                                                  │
       │ 3. Send Share URL to Bob ────────────────────────▶│
       │    (via email, SMS, etc.)                        │
       │                                                  │
       │                                                  │ 4. Open Share URL
       │                                                  ├────GET /api/shares/{token}/access
       │                                                  │◄───401 Password Required
       │                                                  │
       │                                                  │ 5. Enter Password
       │                                                  ├────POST /api/shares/{token}/verify-password
       │                                                  │    {password: "secret123"}
       │                                                  │◄───grant_token (15 min validity)
       │                                                  │
       │                                                  │ 6. Access with Grant Token
       │                                                  ├────GET /api/shares/{token}/access
       │                                                  │    X-Share-Grant: {grant_token}
       │                                                  │◄───file metadata + permissions
       │                                                  │
       │                                                  │ 7. Download File
       │                                                  ├────GET /api/shares/{token}/download
       │                                                  │    X-Share-Grant: {grant_token}
       │                                                  │◄───decrypted file stream
       │                                                  │
       │ 8. Revoke Share (anytime)                       │
       ├─────────DELETE /api/shares/{id}────────────────┐│
       │◄────────200 OK──────────────────────────────────┘│
       │                                                  │
       │                                                  │ 9. Try to Access Again
       │                                                  ├────GET /api/shares/{token}/access
       │                                                  │◄───410 Gone (revoked)
```

---

## 2. Permission Enforcement Flow

```
                    ┌────────────────────────────────────┐
                    │  Incoming Request                  │
                    │  GET /api/shares/{token}/download  │
                    └────────────┬───────────────────────┘
                                 │
                    ┌────────────▼───────────────────────┐
                    │  1. Lookup Share by Token          │
                    └────────────┬───────────────────────┘
                                 │
                    ┌────────────▼───────────────────────┐
                    │  2. Check: is_revoked?             │
                    │     YES → 410 Gone                 │
                    │     NO → Continue                  │
                    └────────────┬───────────────────────┘
                                 │
                    ┌────────────▼───────────────────────┐
                    │  3. Check: Expired?                │
                    │     NOW > expires_at → 410 Gone    │
                    │     NO → Continue                  │
                    └────────────┬───────────────────────┘
                                 │
                    ┌────────────▼───────────────────────┐
                    │  4. Check: Recipient Scoped?       │
                    │     recipient_id set?              │
                    │       YES → Match current_user?    │
                    │         NO → 403 Forbidden         │
                    │       NO → Continue                │
                    └────────────┬───────────────────────┘
                                 │
                    ┌────────────▼───────────────────────┐
                    │  5. Check: Password Protected?     │
                    │     password_hash set?             │
                    │       YES → X-Share-Grant valid?   │
                    │         NO → 401 Unauthorized      │
                    │       NO → Continue                │
                    └────────────┬───────────────────────┘
                                 │
                    ┌────────────▼───────────────────────┐
                    │  6. Check: can_download = true?    │
                    │     NO → 403 Forbidden             │
                    │     YES → Continue                 │
                    └────────────┬───────────────────────┘
                                 │
                    ┌────────────▼───────────────────────┐
                    │  7. Decrypt File (in-memory)       │
                    │     AES-256-GCM with file key      │
                    └────────────┬───────────────────────┘
                                 │
                    ┌────────────▼───────────────────────┐
                    │  8. Log Access (success)           │
                    │     action: download               │
                    │     success: true                  │
                    └────────────┬───────────────────────┘
                                 │
                    ┌────────────▼───────────────────────┐
                    │  9. Stream File to Client          │
                    │     200 OK + binary stream         │
                    └────────────────────────────────────┘
```

---

## 3. Password Verification Flow

```
┌────────────────────────────────────────────────────────────────┐
│  Client attempts to access password-protected share            │
└────────────┬───────────────────────────────────────────────────┘
             │
             │ GET /api/shares/{token}/access
             ▼
┌────────────────────────────────────────────────────────────────┐
│  Server: password_hash is set → 401 Unauthorized              │
│  Response: {"error": "Password required", "password_protected": true} │
└────────────┬───────────────────────────────────────────────────┘
             │
             │ Client prompts user for password
             ▼
┌────────────────────────────────────────────────────────────────┐
│  POST /api/shares/{token}/verify-password                      │
│  Body: {"password": "user_input"}                              │
└────────────┬───────────────────────────────────────────────────┘
             │
             │ Rate Limiter Check (5 attempts / 15 min / IP)
             ▼
┌────────────────────────────────────────────────────────────────┐
│  Argon2 Verify: ph.verify(stored_hash, user_input)            │
└────────────┬───────────────────┬──────────────────────────────┘
             │                   │
        Match?                Mismatch?
             │                   │
             ▼                   ▼
┌─────────────────────┐  ┌─────────────────────────────────────┐
│  Generate JWT       │  │  Log: action=password_verify        │
│  - exp: now + 15min │  │       success=false                 │
│  - sub: share_id    │  │  Response: 403 Forbidden            │
│  - type: share_grant│  │           {"error": "Incorrect password"} │
└──────────┬──────────┘  └─────────────────────────────────────┘
           │
           │ Log: action=password_verify, success=true
           ▼
┌────────────────────────────────────────────────────────────────┐
│  Response: 200 OK                                              │
│  {"grant_token": "eyJhbGciOiJIUzI1NiIs..."}                    │
└────────────┬───────────────────────────────────────────────────┘
             │
             │ Client stores grant_token
             ▼
┌────────────────────────────────────────────────────────────────┐
│  All subsequent requests include:                              │
│  Header: X-Share-Grant: {grant_token}                          │
│                                                                 │
│  Valid for 15 minutes, then must re-verify password           │
└────────────────────────────────────────────────────────────────┘
```

---

## 4. Audit Trail Flow

```
Every Access Attempt
         │
         ▼
┌─────────────────────────────────────┐
│  Extract Context:                   │
│  - share_id                         │
│  - accessed_by (user_id or null)    │
│  - ip_address (request.remote_addr) │
│  - action (view/download/password)  │
│  - timestamp (now)                  │
└─────────────┬───────────────────────┘
              │
              ▼
┌─────────────────────────────────────┐
│  Perform Authorization Checks       │
└─────────┬──────────────┬────────────┘
          │              │
      Success?        Failure?
          │              │
          ▼              ▼
┌──────────────┐  ┌──────────────────┐
│  Execute     │  │  Capture Reason: │
│  Action      │  │  - expired       │
│  (download,  │  │  - revoked       │
│   view, etc.)│  │  - wrong_password│
└──────┬───────┘  │  - no_permission │
       │          └─────────┬────────┘
       │                    │
       ▼                    ▼
┌──────────────────────────────────────┐
│  INSERT INTO access_logs             │
│  (                                   │
│    share_id,                         │
│    accessed_by,                      │
│    ip_address,                       │
│    action,                           │
│    success,      ◄── true or false   │
│    detail,       ◄── failure reason  │
│    timestamp                         │
│  )                                   │
└──────────────┬───────────────────────┘
               │
               ▼
┌──────────────────────────────────────┐
│  Return Response to Client           │
│  (200, 401, 403, 410, etc.)          │
└──────────────────────────────────────┘

Later: Query access_logs for:
- Forensics (who accessed what when)
- Compliance reports
- Anomaly detection (unusual IPs)
- Rate limit enforcement
```

---

## 5. Database Relationships

```
┌──────────────────────────────────────────────────────────────────┐
│                          USERS                                   │
│  id (UUID PK) │ username │ email │ password_hash │ mfa_enabled   │
└────┬──────────────────────────────────────────────────┬──────────┘
     │ owner_id                                          │ owner_id
     │                                                   │
     ▼                                                   │
┌──────────────────────────────────────────────────────────────────┐
│                          FILES                                   │
│  id (UUID PK) │ owner_id (FK) │ encrypted_path │ nonce_hex │...  │
└────┬─────────────────────────────────────────────────────────────┘
     │ file_id
     │
     ▼
┌──────────────────────────────────────────────────────────────────┐
│                          SHARES                                  │
│  id (UUID PK) │ file_id (FK) │ owner_id (FK) │ recipient_id (FK)│
│  share_token │ password_hash │ can_* permissions │ expires_at    │
└────┬─────────────────────────────────────────────────────────────┘
     │ share_id
     │
     ▼
┌──────────────────────────────────────────────────────────────────┐
│                        ACCESS_LOGS                               │
│  id (UUID PK) │ share_id (FK) │ accessed_by (FK) │ action │...   │
└──────────────────────────────────────────────────────────────────┘

Foreign Key Cascades:
- DELETE user   → CASCADE delete files, shares, set null in access_logs
- DELETE file   → CASCADE delete shares
- DELETE share  → CASCADE delete access_logs
```

---

## 6. Security Layers

```
┌─────────────────────────────────────────────────────────────────┐
│  Layer 1: Network                                               │
│  ✓ HTTPS/TLS 1.2+ only                                         │
│  ✓ Certificate validation                                       │
└─────────────────────────────────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  Layer 2: Authentication                                        │
│  ✓ JWT Bearer tokens (for owner operations)                    │
│  ✓ Optional MFA (TOTP)                                         │
│  ✓ Argon2 password hashing                                     │
└─────────────────────────────────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  Layer 3: Authorization                                         │
│  ✓ Ownership checks (file.owner_id == current_user.id)        │
│  ✓ Recipient scoping (share.recipient_id == current_user.id)  │
│  ✓ Permission checks (can_view, can_download, etc.)           │
└─────────────────────────────────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  Layer 4: Share Access Control                                  │
│  ✓ CSPRNG token (256-bit, unguessable)                        │
│  ✓ Optional password (Argon2, rate-limited)                   │
│  ✓ Expiry enforcement (auto-invalidate)                       │
│  ✓ Revocation support (soft-delete)                           │
└─────────────────────────────────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  Layer 5: Data Protection                                       │
│  ✓ AES-256-GCM encryption at rest                             │
│  ✓ In-memory decryption only (no plaintext on disk)           │
│  ✓ Per-file random keys                                        │
└─────────────────────────────────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  Layer 6: Audit & Monitoring                                    │
│  ✓ Complete access log (every attempt)                        │
│  ✓ IP tracking                                                 │
│  ✓ Success/failure tracking                                    │
│  ✓ Failure reason capture                                      │
└─────────────────────────────────────────────────────────────────┘
```

---

## 7. Rate Limiting (Password Verification)

```
Client IP: 192.168.1.100
Action: POST /api/shares/{token}/verify-password

┌───────────────────────────────────────────────────────────────┐
│  Flask-Limiter: Track attempts per IP per 15-minute window   │
└──────────────────┬────────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────┐
│  Attempt Count < 5?                                         │
└──────────┬──────────────────────┬───────────────────────────┘
           │ YES                  │ NO
           ▼                      ▼
┌──────────────────────┐  ┌─────────────────────────────────┐
│  Process Request     │  │  Return 429 Too Many Requests   │
│  Increment Counter   │  │  Retry-After: XXX seconds       │
└──────────────────────┘  └─────────────────────────────────┘

After 15 minutes: counter resets automatically

Storage Backend:
- Development: Memory (resets on restart)
- Production: Redis (persistent, shared across workers)
```

---

These diagrams illustrate the complete flow from file upload to secure sharing, including all security checks and audit logging.
