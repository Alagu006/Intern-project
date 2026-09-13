# API Reference — Module 4: Access Control & Secure File Sharing

Base URL: `https://localhost:5000`

---

## Authentication

All **owner-only** endpoints require a JWT Bearer token in the `Authorization` header:

```http
Authorization: Bearer <your-jwt-token>
```

Get a token via `POST /api/auth/login`.

---

## Endpoints

### Auth

#### `POST /api/auth/register`
Register a new user.

**Request:**
```json
{
  "username": "alice",
  "email": "alice@example.com",
  "password": "SecurePass123!"
}
```

**Response (201):**
```json
{
  "user": {
    "id": "uuid",
    "username": "alice",
    "email": "alice@example.com"
  }
}
```

---

#### `POST /api/auth/login`
Login and receive a JWT access token. Rate-limited to **10 attempts per 15 minutes** (per IP and per email).

**Request:**
```json
{
  "email": "alice@example.com",
  "password": "SecurePass123!",
  "totp_code": "123456"  // optional, only if MFA is enabled
}
```

**Response (200):**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "user": {
    "id": "uuid",
    "username": "alice",
    "email": "alice@example.com"
  }
}
```

**Error (401):** Invalid credentials or MFA code  
**Error (403):** Account is disabled  
**Error (429):** Rate limit exceeded  

---

#### `GET /api/auth/oauth/google/start`
Redirects the user to Google's OAuth 2.0 consent screen. Gated behind `GOOGLE_OAUTH_CLIENT_ID` and `GOOGLE_OAUTH_CLIENT_SECRET` environment variables.

**Response (302):** Redirect to `https://accounts.google.com/o/oauth2/v2/auth` with `client_id`, `redirect_uri`, and generated `state`.

**Error (404):** Google OAuth is not configured on this server.

---

#### `GET /api/auth/oauth/google/callback`
OAuth 2.0 callback endpoint. Exchanges the authorization code for tokens, verifies the Google ID token, and either logs in an existing user matching the verified email or provisions a new user with `oauth_provider: "google"`.

**Query Parameters:**
- `code` (string, required): Authorization code returned by Google.
- `error` (string, optional): Error code returned by Google if access was denied.

**Response (200):**
```json
{
  "access_token": "<jwt_access_token>",
  "user": {
    "id": "uuid",
    "username": "jane_google",
    "email": "jane@example.com",
    "storage_quota_bytes": 524288000,
    "oauth_provider": "google"
  },
  "is_new_user": true
}
```

**Error (400):** Missing code, OAuth error from Google, invalid/unverified email, or invalid ID token  
**Error (403):** Account is disabled  
**Error (404):** Google OAuth is not configured on this server  

---

#### `POST /api/auth/mfa/setup`
Initiate MFA setup. Generates a new TOTP secret in pending status (does not enable MFA yet) and returns the secret along with a QR code PNG encoding the `otpauth://` URI.

**Headers:** `Authorization: Bearer <token>` (required)

**Response (200):**
```json
{
  "secret": "JBSWY3DPEHPK3PXP...",
  "otpauth_uri": "otpauth://totp/SecureFileShare:alice@example.com?secret=...",
  "qr_code": "data:image/png;base64,iVBORw0KGgo...",
  "qr_code_base64": "iVBORw0KGgo..."
}
```

**Error (400):** MFA is already enabled  
**Error (401):** Missing or invalid token  

---

#### `POST /api/auth/mfa/enable`
Verify a TOTP code against the pending secret and enable MFA for the user.

**Headers:** `Authorization: Bearer <token>` (required)

**Request:**
```json
{
  "code": "123456"
}
```

**Response (200):**
```json
{
  "message": "MFA enabled successfully",
  "mfa_enabled": true
}
```

**Error (400):** Invalid verification code, verification code required, or MFA already enabled  
**Error (401):** Missing or invalid token  

---

#### `POST /api/auth/mfa/disable`
Disable MFA for the user. Requires the current user password, and if MFA is currently enabled, a valid TOTP code. Clears the TOTP secret.

**Headers:** `Authorization: Bearer <token>` (required)

**Request:**
```json
{
  "password": "SecurePass123!",
  "totp_code": "123456"
}
```

**Response (200):**
```json
{
  "message": "MFA disabled successfully",
  "mfa_enabled": false
}
```

**Error (400):** Password is required, TOTP code is required, or MFA is not enabled  
**Error (401):** Invalid password or invalid MFA code  

---

### WebAuthn Passkeys

#### `POST /api/auth/webauthn/register/start`
Initiate WebAuthn passkey registration for the authenticated user. Generates `PublicKeyCredentialCreationOptions` with challenge, excluding any credentials already registered for this user.

**Headers:** `Authorization: Bearer <token>` (required)

**Request (optional):**
```json
{
  "nickname": "MacBook Touch ID"
}
```

**Response (200):**
```json
{
  "options": {
    "rp": { "name": "Secure File Share", "id": "localhost" },
    "user": { "id": "...", "name": "alice", "displayName": "alice" },
    "challenge": "...",
    "pubKeyCredParams": [ ... ],
    "authenticatorSelection": { ... }
  },
  "challenge": "<base64url_challenge>"
}
```

---

#### `POST /api/auth/webauthn/register/finish`
Verify client's registration credential response and store the new passkey credential.

**Headers:** `Authorization: Bearer <token>` (required)

**Request:**
```json
{
  "credential": {
    "id": "<base64url_credential_id>",
    "rawId": "<base64url_credential_id>",
    "response": {
      "clientDataJSON": "...",
      "attestationObject": "..."
    },
    "type": "public-key"
  },
  "nickname": "MacBook Touch ID"
}
```

**Response (201):**
```json
{
  "message": "Passkey registered successfully",
  "credential": {
    "id": "uuid",
    "credential_id": "<base64url_id>",
    "nickname": "MacBook Touch ID",
    "sign_count": 0,
    "created_at": "2026-09-08T20:00:00Z"
  }
}
```

**Error (400):** Invalid challenge or verification failure  
**Error (409):** Credential already registered  

---

#### `POST /api/auth/webauthn/login/start`
Initiate passkey authentication. Supports both discoverable passkeys (empty body) and targeted authentication (specifying `email` or `username`).

**Request (optional):**
```json
{
  "email": "alice@example.com"
}
```

**Response (200):**
```json
{
  "options": {
    "challenge": "...",
    "rpId": "localhost",
    "allowCredentials": [ ... ],
    "userVerification": "preferred"
  },
  "challenge": "<base64url_challenge>"
}
```

---

#### `POST /api/auth/webauthn/login/finish`
Verify passkey assertion response and authenticate the user, returning a JWT access token.

**Request:**
```json
{
  "credential": {
    "id": "<base64url_credential_id>",
    "rawId": "<base64url_credential_id>",
    "response": {
      "clientDataJSON": "...",
      "authenticatorData": "...",
      "signature": "...",
      "userHandle": "..."
    },
    "type": "public-key"
  }
}
```

**Response (200):**
```json
{
  "access_token": "<jwt_access_token>",
  "user": {
    "id": "uuid",
    "username": "alice",
    "email": "alice@example.com"
  }
}
```

**Error (400):** Invalid challenge or verification failure  
**Error (403):** Account is disabled  
**Error (404):** Passkey not recognized  

---

#### `GET /api/auth/me`
Retrieve the authenticated user's profile, including MFA status, last login, and storage quota/usage statistics.

**Headers:** `Authorization: Bearer <token>` (required)

**Response (200):**
```json
{
  "user": {
    "id": "uuid",
    "username": "alice",
    "email": "alice@example.com",
    "mfa_enabled": false,
    "last_login": "2026-07-15T12:00:00Z",
    "storage_used_bytes": 1048576,
    "storage_quota_bytes": 524288000
  },
  "id": "uuid",
  "username": "alice",
  "email": "alice@example.com",
  "storage_used_bytes": 1048576,
  "storage_quota_bytes": 524288000
}
```

**Error (401):** Missing or invalid token  

---

#### `POST /api/auth/change-password`
Change the current user's password. Requires verification of the current password and enforces a minimum length of 8 characters.

**Headers:** `Authorization: Bearer <token>` (required)

**Request:**
```json
{
  "current_password": "CurrentPassword123!",
  "new_password": "NewSecretPassword5678!"
}
```

**Response (200):**
```json
{
  "message": "Password changed successfully"
}
```

**Error (400):** Missing fields, new password < 8 characters, or new password same as current  
**Error (401):** Invalid current password or invalid token  

---

#### `GET /api/auth/users/search?q=<query>`
Search users by username or email (for recipient picker).

**Headers:** `Authorization: Bearer <token>` (required)

**Response (200):**
```json
{
  "users": [
    {"id": "uuid", "username": "bob", "email": "bob@example.com"}
  ]
}
```

---

### Personal Access Tokens (PAT)

Personal access tokens provide long-lived authentication credentials for automated scripts, CLI tools, and external integrations without requiring the short-lived 1-hour JWT session token.

**Using a PAT:**
Include the token in the `Authorization` header prefixed with `pat_`:
```http
Authorization: Bearer pat_xxxxxx...
```

#### `POST /api/auth/tokens`
Generate a new personal access token. The `raw_token` is returned **exactly once** upon creation; only a SHA-256 hash is persisted.

**Headers:** `Authorization: Bearer <token>` (required)

**Request:**
```json
{
  "name": "CI/CD Deployment Script",
  "expires_in_days": 90
}
```

**Response (201):**
```json
{
  "message": "Personal access token created successfully",
  "token": {
    "id": "uuid",
    "user_id": "uuid",
    "name": "CI/CD Deployment Script",
    "created_at": "2026-07-15T12:00:00Z",
    "last_used_at": null,
    "expires_at": "2026-10-13T12:00:00Z",
    "is_expired": false
  },
  "raw_token": "pat_abc123..."
}
```

**Error (400):** Missing `name` or invalid expiration

---

#### `GET /api/auth/tokens`
List all personal access tokens for the authenticated user (metadata only; never exposes raw tokens or hashes).

**Headers:** `Authorization: Bearer <token>` (required)

**Response (200):**
```json
{
  "tokens": [
    {
      "id": "uuid",
      "user_id": "uuid",
      "name": "CI/CD Deployment Script",
      "created_at": "2026-07-15T12:00:00Z",
      "last_used_at": "2026-07-15T14:30:00Z",
      "expires_at": "2026-10-13T12:00:00Z",
      "is_expired": false
    }
  ]
}
```

---

#### `DELETE /api/auth/tokens/<id>`
Revoke an existing personal access token. Subsequent requests using this token will be rejected with HTTP 401.

**Headers:** `Authorization: Bearer <token>` (required)

**Response (200):**
```json
{
  "message": "Token revoked successfully"
}
```

**Error (403):** Forbidden (token belongs to another user)  
**Error (404):** Token not found

---

### Files

#### `POST /api/files`
Upload a file. The file is encrypted with AES-256-GCM before storage.

**Headers:** `Authorization: Bearer <token>` (required)  
**Body:** `multipart/form-data` with:
- `file`: `<binary>` (required)
- `folder_id`: Optional UUID of destination folder.
- `tags`: Optional comma-separated tag names (e.g. `reports,2026`).
- `auto_delete_at`: Optional ISO-8601 timestamp when the file will automatically expire and be deleted.
- `auto_delete_days`: Optional number of days after upload when the file will automatically expire.

**Response (201):**
```json
{
  "file": {
    "id": "uuid",
    "filename": "document.pdf",
    "mime_type": "application/pdf",
    "size_bytes": 102400,
    "version": 1,
    "folder_id": null,
    "tags": ["reports"],
    "auto_delete_at": "2026-10-15T12:00:00Z",
    "is_expired": false,
    "created_at": "2026-07-15T12:00:00Z"
  }
}
```

**Error (400):** No file provided, empty file, or invalid auto_delete parameter format  
**Error (413):** Request entity too large (file exceeds `MAX_CONTENT_LENGTH`) or Storage quota exceeded (`storage_used + file_size > storage_quota_bytes`)  
**Error (422):** Malware detected (file rejected if flagged as infected by ClamAV)

---

#### `POST /api/files/uploads`
Initiate a resumable chunked file upload session. Avoids holding large files in memory during single-request uploads and allows resuming failed or interrupted uploads.

**Headers:** `Authorization: Bearer <token>` (required)  
**Body:** `application/json`
```json
{
  "filename": "large_dataset.zip",
  "mime_type": "application/zip",
  "expected_chunks": 5,
  "total_size_bytes": 52428800,
  "folder_id": "optional-folder-uuid",
  "auto_delete_days": 7,
  "tags": ["archive", "datasets"]
}
```

**Response (201):**
```json
{
  "upload_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "session": {
    "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "owner_id": "user-uuid",
    "filename": "large_dataset.zip",
    "mime_type": "application/zip",
    "total_size_bytes": 52428800,
    "expected_chunks": 5,
    "received_chunks": 0,
    "status": "in_progress",
    "folder_id": null,
    "auto_delete_at": "2026-07-22T12:00:00Z",
    "tags": "archive,datasets",
    "created_at": "2026-07-15T12:00:00Z",
    "updated_at": "2026-07-15T12:00:00Z"
  }
}
```

**Error (400):** `expected_chunks` is missing or less than 1, or invalid auto-delete format  
**Error (401):** Missing or invalid token  
**Error (403):** Folder belongs to another user  
**Error (404):** Folder not found  

---

#### `PUT /api/files/uploads/<upload_id>/chunks/<chunk_index>`
Upload an individual chunk of bytes (0-indexed). Chunks are appended to temporary storage on disk outside `UPLOAD_FOLDER` in a dedicated staging directory. Chunks can arrive in any order or be retried idempotently.

**Headers:** `Authorization: Bearer <token>` (required)  
**Body:** Raw bytes (`application/octet-stream`) or multipart file (`chunk` or `file` field)

**Response (200):**
```json
{
  "message": "Chunk 0 uploaded",
  "upload_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "chunk_index": 0,
  "chunk_size_bytes": 10485760,
  "received_chunks": 1,
  "expected_chunks": 5
}
```

**Error (400):** Invalid chunk index (out of bounds 0 to expected_chunks-1), empty chunk data, or upload session already completed  
**Error (401):** Missing or invalid token  
**Error (403):** Not the upload session owner  
**Error (404):** Upload session not found  

---

#### `POST /api/files/uploads/<upload_id>/complete`
Verify that all expected chunks (`0..expected_chunks-1`) are present, reassemble them in sequential index order, and reuse the existing encryption (`encrypt_file()`), malware scanning (ClamAV), quota enforcement, and `FileVersion` flow to finalize exactly like a single-shot upload. Cleans up temporary staging files on disk.

**Headers:** `Authorization: Bearer <token>` (required)  
**Body (optional):** `application/json` (optional metadata overrides such as `filename`, `folder_id`, `tags`)

**Response (201):**
```json
{
  "file": {
    "id": "uuid",
    "filename": "large_dataset.zip",
    "mime_type": "application/zip",
    "size_bytes": 52428800,
    "version": 1,
    "folder_id": null,
    "tags": ["archive", "datasets"],
    "created_at": "2026-07-15T12:00:00Z"
  }
}
```

**Error (400):** Missing chunks (returns `missing_chunks` array), empty file, or session already completed  
**Error (401):** Missing or invalid token  
**Error (403):** Not the upload session owner  
**Error (404):** Upload session not found  
**Error (413):** Storage quota exceeded  
**Error (422):** Malware detected  

---

#### `GET /api/files/uploads/<upload_id>`
Inspect upload session progress, including total expected chunks, count of received chunks, list of received chunk indices, and list of missing chunk indices for resumption.

**Headers:** `Authorization: Bearer <token>` (required)

**Response (200):**
```json
{
  "session": {
    "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "owner_id": "user-uuid",
    "filename": "large_dataset.zip",
    "mime_type": "application/zip",
    "total_size_bytes": 52428800,
    "expected_chunks": 5,
    "received_chunks": 3,
    "status": "in_progress",
    "received_chunk_indices": [0, 1, 3],
    "missing_chunk_indices": [2, 4],
    "created_at": "2026-07-15T12:00:00Z",
    "updated_at": "2026-07-15T12:02:00Z"
  }
}
```

**Error (401):** Missing or invalid token  
**Error (403):** Not the upload session owner  
**Error (404):** Upload session not found  

---

#### `POST /api/files/uploads/cleanup`
Administrative maintenance endpoint to purge orphaned in-progress upload sessions older than `max_age_hours` (default: 24) and delete their temporary staging directories from disk.

**Headers:** `Authorization: Bearer <token>` (admin required)  
**Query Parameters:**
- `max_age_hours` (int, default `24`): Max session age in hours before considering it orphaned.

**Response (200):**
```json
{
  "cleaned_sessions": 2,
  "max_age_hours": 24
}
```

**Error (401):** Missing or invalid token  
**Error (403):** Admin role required  

---

#### `GET /api/files`
List all files owned by the authenticated user with pagination, sorting, search, and storage usage tracking.

**Headers:** `Authorization: Bearer <token>` (required)

**Response Headers:**
- `X-Storage-Used-Bytes`: Total bytes consumed by the user's files.
- `X-Storage-Quota-Bytes`: Configured user quota in bytes or `"unlimited"`.

**Query Parameters:**
- `page` (integer, default `1`): Page number (min 1).
- `per_page` (integer, default `20`, max `100`): Items per page.
- `search` (string, optional): Search by filename substring (case-insensitive, alias `q`).
- `sort` (string, default `date`): Sort field (`name` | `size` | `date`).
- `order` (string, optional): Sort direction (`asc` | `desc`). Defaults to `asc` for `name` and `desc` for `size` and `date`.
- `folder_id` (string, optional): Filter files by folder UUID, or `"root"`/`"null"` for files outside any folder.
- `tag` (string, optional): Filter files tagged with the specified tag name.
- `include_deleted` (boolean, default `false`): When `true`, includes soft-deleted files in results.

**Response (200):**
```json
{
  "files": [
    {
      "id": "uuid",
      "filename": "document.pdf",
      "mime_type": "application/pdf",
      "size_bytes": 102400,
      "folder_id": "optional-uuid or null",
      "tags": ["finance", "2026"],
      "created_at": "2026-07-15T12:00:00Z"
    }
  ],
  "items": [
    {
      "id": "uuid",
      "filename": "document.pdf",
      "mime_type": "application/pdf",
      "size_bytes": 102400,
      "folder_id": null,
      "tags": [],
      "created_at": "2026-07-15T12:00:00Z"
    }
  ],
  "total": 1,
  "page": 1,
  "per_page": 20,
  "pages": 1,
  "storage_used_bytes": 102400,
  "storage_quota_bytes": 524288000
}
```

---

#### `GET /api/files/search?q=<query>`
Search files owned by the authenticated user matching filename or attached tag names (case-insensitive substring match).

**Headers:** `Authorization: Bearer <token>` (required)

**Query Parameters:**
- `q` (string, optional): Search query matching filename or attached tag names (case-insensitive substring). If empty or omitted, returns an empty result set.
- `page` (integer, default `1`): Page number (min 1).
- `per_page` (integer, default `20`, max `100`): Items per page.
- `sort` (string, default `date`): Sort field (`name` | `size` | `date`).
- `order` (string, optional): Sort direction (`asc` | `desc`).

> [!NOTE]
> Initial version searches filename and tags only. Extracted text and OCR indexing for common document types are planned for a subsequent release.

**Response (200):**
```json
{
  "files": [
    {
      "id": "uuid",
      "filename": "alpha_budget.pdf",
      "mime_type": "application/pdf",
      "size_bytes": 102400,
      "version": 1,
      "folder_id": null,
      "tags": ["finance", "annual"],
      "created_at": "2026-07-15T12:00:00Z"
    }
  ],
  "items": [
    {
      "id": "uuid",
      "filename": "alpha_budget.pdf",
      "mime_type": "application/pdf",
      "size_bytes": 102400,
      "version": 1,
      "folder_id": null,
      "tags": ["finance", "annual"],
      "created_at": "2026-07-15T12:00:00Z"
    }
  ],
  "total": 1,
  "page": 1,
  "per_page": 20,
  "pages": 1,
  "query": "budget"
}
```

**Error (401):** Missing or invalid token

---

#### `PATCH /api/files/<file_id>`
Update file metadata (owner only). Supports renaming (`filename`), moving into or out of folders (`folder_id`), updating tags (`tags`), and configuring auto-deletion (`auto_delete_at` or `auto_delete_days`). Pass `null` for `auto_delete_at` to clear expiration. Immutable properties `mime_type` and `size_bytes` cannot be modified.

**Headers:** `Authorization: Bearer <token>` (required)

**Request:**
```json
{
  "filename": "updated_document.pdf",
  "folder_id": "uuid-or-null",
  "tags": ["invoices", "q3"],
  "auto_delete_at": "2026-12-31T23:59:59Z"
}
```

**Response (200):**
```json
{
  "file": {
    "id": "uuid",
    "filename": "updated_document.pdf",
    "mime_type": "application/pdf",
    "size_bytes": 102400,
    "version": 1,
    "folder_id": "uuid-or-null",
    "tags": ["invoices", "q3"],
    "auto_delete_at": "2026-12-31T23:59:59Z",
    "is_expired": false,
    "created_at": "2026-07-15T12:00:00Z"
  }
}
```

**Error (400):** Filename is required, invalid filename, invalid auto-delete format, or attempt to modify `mime_type`/`size_bytes`  
**Error (403):** Forbidden (not the file owner)  
**Error (404):** File or target folder not found  

---

#### `POST /api/files/<file_id>/tags`
Attach one or more tags to a file (owner only).

**Headers:** `Authorization: Bearer <token>` (required)  
**Request:** `{"name": "finance"}` or `{"tags": ["tax", "audit"]}`

**Response (200):**
```json
{
  "file": {
    "id": "uuid",
    "tags": ["finance", "tax", "audit"]
  }
}
```

---

#### `DELETE /api/files/<file_id>/tags/<tag_id_or_name>`
Remove a tag association from a file (owner only).

**Headers:** `Authorization: Bearer <token>` (required)

**Response (200):**
```json
{
  "file": {
    "id": "uuid",
    "tags": ["tax", "audit"]
  }
}
```

---

#### `DELETE /api/files/<file_id>`
Delete a file (owner only). By default, performs a **soft-delete** by setting `deleted_at = now()` and revoking active shares, while retaining the encrypted blobs on disk and the database record. Pass `?permanent=true` to permanently purge the file immediately.

**Headers:** `Authorization: Bearer <token>` (required)

**Query Parameters:**
- `permanent` (boolean, optional): If `true`, permanently removes disk blobs and the database row.

**Response (200):**
```json
{
  "message": "File deleted successfully",
  "deleted_at": "2026-09-08T15:30:00Z"
}
```

---

#### `GET /api/files/trash`
List soft-deleted files in the user's trash.

**Headers:** `Authorization: Bearer <token>` (required)

**Query Parameters:**
- `page` (integer, default `1`): Page number (min 1).
- `per_page` (integer, default `20`, max `100`): Items per page.

**Response (200):**
```json
{
  "files": [
    {
      "id": "uuid",
      "filename": "draft.txt",
      "mime_type": "text/plain",
      "size_bytes": 1024,
      "deleted_at": "2026-09-08T15:30:00Z",
      "is_deleted": true
    }
  ],
  "items": [ ... ],
  "total": 1,
  "page": 1,
  "per_page": 20,
  "pages": 1
}
```

---

#### `POST /api/files/<file_id>/restore`
Restore a soft-deleted file from trash (owner only). Clears `deleted_at` and restores file visibility. Does NOT un-revoke previously revoked shares (the owner must create a new share link explicitly).

**Headers:** `Authorization: Bearer <token>` (required)

**Response (200):**
```json
{
  "message": "File restored successfully",
  "file": {
    "id": "uuid",
    "filename": "draft.txt",
    "deleted_at": null,
    "is_deleted": false
  }
}
```

**Error (400):** File is not in trash  
**Error (403):** Forbidden  
**Error (404):** File not found  

---

#### `GET /api/files/<file_id>/thumbnail`
Generate and return an on-demand resized JPEG thumbnail (max 400x400) for raster image files (`image/png`, `image/jpeg`, `image/webp`).
Decryption occurs strictly in-memory without saving plaintext to disk. Uses an in-process, thread-safe LRU cache with a 5-minute TTL to accelerate repeated requests.
Returns HTTP 415 (Unsupported Media Type) for non-image file types (e.g. PDF, text documents).

**Authentication / Access:**
- Owner JWT: `Authorization: Bearer <token>`
- Share Token: Query param `?share_token=<token_or_slug>` or `?token=<token_or_slug>`, or header `X-Share-Token: <token_or_slug>`
- Password-protected shares require `X-Share-Grant: <grant_token>` header.

**Response (200):**
Binary JPEG image stream (`Content-Type: image/jpeg`, `Cache-Control: private, max-age=300`).

**Error (401):** Missing authentication or share token, or password required  
**Error (403):** Forbidden (not file owner and not an authorized recipient)  
**Error (404):** File or share not found  
**Error (410):** Share is expired or revoked  
**Error (415):** Unsupported media type (thumbnail preview only supported for image types)  

---

#### `GET /api/files/<file_id>/analytics`
Retrieve aggregated access analytics across all shares of a file (owner only). Computes total views, total downloads, unique accessors (distinct user IDs for authenticated users; distinct IP addresses for anonymous shares), and a 30-day continuous daily time-series with daily counts, views, and downloads.

**Headers:** `Authorization: Bearer <token>` (required)

**Response (200):**
```json
{
  "file_id": "uuid",
  "filename": "report.pdf",
  "total_shares": 2,
  "total_views": 15,
  "total_downloads": 8,
  "views": 15,
  "downloads": 8,
  "total_accesses": 23,
  "unique_accessors": 7,
  "time_series": [
    {
      "date": "2026-08-10",
      "count": 2,
      "views": 1,
      "downloads": 1
    },
    ...
  ],
  "analytics": {
    "total_views": 15,
    "total_downloads": 8,
    "views": 15,
    "downloads": 8,
    "total_accesses": 23,
    "unique_accessors": 7,
    "time_series": [ ... ]
  }
}
```

**Error (401):** Missing or invalid token  
**Error (403):** Forbidden (not the file owner)  
**Error (404):** File not found  

---

### Bulk File Operations

#### `POST /api/files/bulk/delete`
Bulk delete multiple files owned by the authenticated user. Silently skips IDs that do not belong to the user (reported as `"File not found"`) to prevent existence probing of other tenants' files.

**Headers:** `Authorization: Bearer <token>` (required)

**Request:**
```json
{
  "file_ids": ["uuid-1", "uuid-2"]
}
```

**Response (200):**
```json
{
  "succeeded": ["uuid-1", "uuid-2"],
  "failed": [
    {
      "id": "uuid-3",
      "error": "File not found"
    }
  ],
  "total": 3,
  "success_count": 2,
  "failure_count": 1
}
```

---

#### `POST /api/files/bulk/move`
Bulk move multiple files into a target folder or to root (`null`). Silently skips files not owned by the user.

**Headers:** `Authorization: Bearer <token>` (required)

**Request:**
```json
{
  "file_ids": ["uuid-1", "uuid-2"],
  "folder_id": "target-folder-uuid"
}
```
*(Pass `"folder_id": null` to move files to root).*

**Response (200):**
```json
{
  "succeeded": ["uuid-1", "uuid-2"],
  "failed": [],
  "total": 2,
  "success_count": 2,
  "failure_count": 0,
  "folder_id": "target-folder-uuid"
}
```

---

#### `POST /api/files/bulk/tag`
Bulk add, replace, or remove tags across multiple files owned by the user.

**Headers:** `Authorization: Bearer <token>` (required)

**Request:**
```json
{
  "file_ids": ["uuid-1", "uuid-2"],
  "tags": ["finance", "reports"],
  "action": "add"
}
```
*(Actions supported: `"add"` (default), `"replace"`, `"remove"`).*

**Response (200):**
```json
{
  "succeeded": ["uuid-1", "uuid-2"],
  "failed": [],
  "total": 2,
  "success_count": 2,
  "failure_count": 0
}
```

---

### Folders

#### `POST /api/folders`
Create a new folder scoped to the authenticated owner, with optional nesting under a `parent_id`.

**Headers:** `Authorization: Bearer <token>` (required)  
**Request:**
```json
{
  "name": "Project Documents",
  "parent_id": "optional-uuid or null"
}
```

**Response (201):**
```json
{
  "folder": {
    "id": "uuid",
    "owner_id": "uuid",
    "parent_id": null,
    "name": "Project Documents",
    "created_at": "2026-07-15T12:00:00Z",
    "updated_at": "2026-07-15T12:00:00Z"
  }
}
```

---

#### `GET /api/folders`
List all folders owned by the authenticated user.

**Headers:** `Authorization: Bearer <token>` (required)  
**Query Parameters:**
- `parent_id` (string, optional): Filter by parent folder UUID, or `"root"`/`"null"` for top-level folders.

**Response (200):**
```json
{
  "folders": [
    {
      "id": "uuid",
      "parent_id": null,
      "name": "Project Documents",
      "created_at": "2026-07-15T12:00:00Z"
    }
  ],
  "total": 1
}
```

---

#### `GET /api/folders/<folder_id>`
Get details for a folder, including direct subfolders and contained files.

**Headers:** `Authorization: Bearer <token>` (required)

**Response (200):**
```json
{
  "folder": {
    "id": "uuid",
    "name": "Project Documents"
  },
  "subfolders": [],
  "files": []
}
```

---

#### `DELETE /api/folders/<folder_id>`
Delete a folder. Files contained in this folder have their `folder_id` set to `NULL` (moved to root) so files are preserved. Subfolders are cascade-deleted.

**Headers:** `Authorization: Bearer <token>` (required)

**Response (200):**
```json
{
  "message": "Folder deleted successfully"
}
```

---

### Tags

#### `POST /api/tags`
Create a new tag for the authenticated owner. Idempotent: returns existing tag if already created.

**Headers:** `Authorization: Bearer <token>` (required)  
**Request:**
```json
{
  "name": "invoice"
}
```

**Response (201 or 200):**
```json
{
  "tag": {
    "id": "uuid",
    "name": "invoice",
    "created_at": "2026-07-15T12:00:00Z"
  }
}
```

---

#### `GET /api/tags`
List all tags owned by the authenticated user.

**Headers:** `Authorization: Bearer <token>` (required)

**Response (200):**
```json
{
  "tags": [
    {
      "id": "uuid",
      "name": "invoice",
      "created_at": "2026-07-15T12:00:00Z"
    }
  ],
  "total": 1
}
```

---

#### `DELETE /api/tags/<tag_id>`
Delete a tag. Removes associations in `file_tags`; files are preserved.

**Headers:** `Authorization: Bearer <token>` (required)

**Response (200):**
```json
{
  "message": "Tag deleted successfully"
}
```  

---

#### `DELETE /api/files/<file_id>`
Delete a file owned by the authenticated user. Revokes all active shares, removes all version encrypted blobs from disk, and cascade-deletes the file, file versions, and related share/access log records.

**Headers:** `Authorization: Bearer <token>` (required)

**Response (200):**
```json
{
  "message": "File deleted successfully"
}
```

**Error (403):** Forbidden (not the file owner)  
**Error (404):** File not found  

---

#### `GET /api/files/<file_id>/download`
Directly download the current decrypted version of a file owned by the authenticated user.

**Headers:** `Authorization: Bearer <token>` (required)

**Response (200):**
Raw binary file stream with `Content-Disposition: attachment; filename="..."; filename*=UTF-8''...` headers.

**Error (403):** Forbidden (not the file owner)  
**Error (404):** File not found  

---

#### `POST /api/files/<file_id>/versions`
Upload a new version of an existing file under the same logical file identity. The new encrypted blob is persisted with an incremented version number, and the parent file row is updated to point to this latest version. Existing shares without an explicit pin will dynamically serve this new version.

**Headers:** `Authorization: Bearer <token>` (required)  
**Body:** `multipart/form-data` with `file=<binary>`

**Response (201):**
```json
{
  "message": "Version 2 uploaded successfully",
  "version": {
    "id": "uuid",
    "file_id": "uuid",
    "version_number": 2,
    "filename": "document_v2.pdf",
    "mime_type": "application/pdf",
    "size_bytes": 105200,
    "created_at": "2026-07-16T10:00:00Z"
  },
  "file": {
    "id": "uuid",
    "filename": "document_v2.pdf",
    "mime_type": "application/pdf",
    "size_bytes": 105200,
    "version": 2,
    "created_at": "2026-07-15T12:00:00Z"
  }
}
```

**Error (400):** No file provided or empty file  
**Error (403):** Forbidden (not the file owner)  
**Error (404):** File not found  
**Error (422):** Malware detected (file rejected if flagged as infected by ClamAV)

---

#### `GET /api/files/<file_id>/versions`
List all past and current versions for a file in descending version order.

**Headers:** `Authorization: Bearer <token>` (required)

**Response (200):**
```json
{
  "versions": [
    {
      "id": "uuid",
      "file_id": "uuid",
      "version_number": 2,
      "filename": "document_v2.pdf",
      "mime_type": "application/pdf",
      "size_bytes": 105200,
      "created_at": "2026-07-16T10:00:00Z"
    },
    {
      "id": "uuid",
      "file_id": "uuid",
      "version_number": 1,
      "filename": "document.pdf",
      "mime_type": "application/pdf",
      "size_bytes": 102400,
      "created_at": "2026-07-15T12:00:00Z"
    }
  ],
  "total": 2,
  "current_version": 2
}
```

**Error (403):** Forbidden (not the file owner)  
**Error (404):** File not found  

---

#### `GET /api/files/<file_id>/versions/<version_number>` & `GET /api/files/<file_id>/versions/<version_number>/download`
Retrieve metadata for a specific version (`GET .../<version_number>`) or download the decrypted version blob (`GET .../<version_number>/download` or `?download=true`).

**Headers:** `Authorization: Bearer <token>` (required)

**Response (200 for download):**
Decrypted binary stream with RFC 5987 `Content-Disposition: attachment; filename="..."; filename*=UTF-8''...` headers.

**Response (200 for metadata):**
```json
{
  "version": {
    "id": "uuid",
    "file_id": "uuid",
    "version_number": 1,
    "filename": "document.pdf",
    "mime_type": "application/pdf",
    "size_bytes": 102400,
    "created_at": "2026-07-15T12:00:00Z"
  }
}
```

**Error (403):** Forbidden (not the file owner)  
**Error (404):** File or version not found  

---

### Shares

#### `POST /api/files/<file_id>/share`
Create a share link for a file. Supports pinning to an immutable historical version or leaving unpinned (default) to dynamically track the latest version.

**Headers:** `Authorization: Bearer <token>` (required)

**Request:**
```json
{
  "recipient_ids": ["uuid1", "uuid2"],  // optional; omit for open link
  "custom_slug": "team-wiki",           // optional string; 3-64 chars, alphanumeric + hyphens only
  "permissions": {
    "can_view": true,
    "can_download": true,
    "can_edit": false,
    "can_reshare": false
  },
  "pinned_version": 1,                  // optional integer; null/omitted = dynamic tracking of latest version
  "password": "optional-plaintext",     // optional
  "expires_at": "2027-12-31T23:59:59Z"  // optional ISO-8601
}
```

**Response (201):**
```json
{
  "shares": [
    {
      "id": "uuid",
      "file_id": "uuid",
      "recipient_id": "uuid or null",
      "permissions": {
        "can_view": true,
        "can_download": true,
        "can_edit": false,
        "can_reshare": false
      },
      "share_token": "abcd1234...",
      "custom_slug": "team-wiki",
      "share_url": "https://localhost:5000/api/shares/team-wiki/access",
      "expires_at": "2027-12-31T23:59:59Z",
      "is_revoked": false,
      "created_at": "2026-07-15T12:00:00Z",
      "updated_at": "2026-07-15T12:00:00Z"
    }
  ]
}
```

**Error (400):** Invalid custom_slug format (must be 3-64 chars, alphanumeric and hyphens only) or slug used with multiple recipients  
**Error (409):** Custom slug is already in use (collision)

---

#### `GET /api/files/<file_id>/shares`
List all active shares for a file (owner only). Includes recipient read/download receipt timestamps (`first_viewed_at`, `first_downloaded_at`) and `custom_slug`.

**Headers:** `Authorization: Bearer <token>` (required)

**Response (200):**
```json
{
  "shares": [
    {
      "id": "uuid",
      "recipient_id": "uuid or null",
      "share_token": "abcd1234...",
      "custom_slug": "team-wiki",
      "share_url": "https://localhost:5000/api/shares/team-wiki/access",
      "is_expired": false,
      "first_viewed_at": "2026-07-15T13:00:00Z",
      "first_downloaded_at": "2026-07-15T13:05:00Z"
    }
  ]
}
```

---

#### `GET /api/shares/<token_or_slug>/access`
Validate a share token or custom human-readable slug and return file metadata.

**Headers:**
- `Authorization: Bearer <token>` (optional — for recipient-scoped shares)
- `X-Share-Grant: <grant-token>` (required for password-protected shares)

**Response (200):**
```json
{
  "share": { ... },
  "file": {
    "id": "uuid",
    "filename": "document.pdf",
    "mime_type": "application/pdf",
    "size_bytes": 102400,
    "created_at": "2026-07-15T12:00:00Z"
  },
  "permissions": {
    "can_view": true,
    "can_download": true,
    "can_edit": false,
    "can_reshare": false
  }
}
```

**Error (401):** Password required
```json
{
  "error": "Password required",
  "password_protected": true
}
```

**Error (410):** Expired or revoked
```json
{
  "error": "Share is expired"
}
```

---

#### `POST /api/shares/<token_or_slug>/verify-password`
Verify the share-link password (looked up by share token or custom slug). Rate-limited to **5 attempts per 15 minutes per IP**.

**Request:**
```json
{
  "password": "secret123"
}
```

**Response (200):**
```json
{
  "grant_token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}
```

Use this `grant_token` as the `X-Share-Grant` header on subsequent requests (valid for 15 minutes).

**Error (403):** Incorrect password
**Error (429):** Rate limit exceeded

---

#### `GET /api/shares/<token_or_slug>/download`
Stream the decrypted file (looked up by share token or custom slug). Requires `can_download` permission.

**Headers:**
- `X-Share-Grant: <grant-token>` (required for password-protected shares)

**Response (200):** Binary file stream  
**Content-Disposition:** `attachment; filename="document.pdf"`

**Error (403):** Download not permitted
**Error (410):** Expired or revoked

---

#### `GET /api/shares/<token_or_slug>/preview`
Stream the decrypted file inline for in-browser preview (looked up by share token or custom slug). Only permitted when `can_view=true` and `can_download=false`.

**Headers:**
- `X-Share-Grant: <grant-token>` (required for password-protected shares)

**Response (200):** Binary/text file stream  
**Content-Disposition:** `inline; filename="document.png"`

**Error (401):** Password required  
**Error (403):** View not permitted, or download is enabled (use `/download` instead)  
**Error (404):** Share not found  
**Error (410):** Expired or revoked  

---

#### `PATCH /api/shares/<share_id>`
Update permissions, custom slug, expiry, or revoke a share (owner only).

**Headers:** `Authorization: Bearer <token>` (required)

**Request (all fields optional):**
```json
{
  "custom_slug": "new-team-wiki",        // or null to remove custom slug
  "permissions": {
    "can_view": true,
    "can_download": false
  },
  "expires_at": "2028-01-01T00:00:00Z",  // or null to remove expiry
  "is_revoked": true
}
```

**Response (200):**
```json
{
  "share": { ... }
}
```

**Error (400):** Invalid custom slug format  
**Error (409):** Custom slug already in use by another share  

---

#### `DELETE /api/shares/<share_id>`
Revoke a share (owner only).

**Headers:** `Authorization: Bearer <token>` (required)

**Response (200):**
```json
{
  "message": "Share revoked"
}
```

---

#### `GET /api/shares/<share_id>/receipts`
Get read and download receipts for a share with a recipient (owner only). Returns whether and when the recipient first viewed and first downloaded the share, derived from access audit logs.

**Headers:** `Authorization: Bearer <token>` (required)

**Response (200):**
```json
{
  "share_id": "uuid",
  "recipient_id": "uuid or null",
  "viewed": true,
  "downloaded": true,
  "first_viewed_at": "2026-07-15T13:00:00Z",
  "first_downloaded_at": "2026-07-15T13:05:00Z"
}
```

**Error (403):** Forbidden (caller is not the share owner)  
**Error (404):** Share not found

---

#### `GET /api/shares/<token_or_slug>/qrcode`
Return a QR code PNG image encoding the share URL (looked up by share token or custom slug).

**Headers:**
- `X-Share-Grant: <grant-token>` (required for password-protected shares)

**Response (200):** `image/png`

---

## Notifications

In-app alerts notifying owners whenever someone views or downloads their shared files.

#### `GET /api/notifications`
List notifications for the current authenticated user (newest first) with pagination.

**Headers:** `Authorization: Bearer <token>` (required)

**Query Parameters:**
- `page` (integer, default `1`): Page number.
- `per_page` (integer, default `20`, max `100`): Notifications per page.
- `unread` (boolean, optional): Set to `true` to return only unread notifications.

**Response (200):**
```json
{
  "notifications": [
    {
      "id": "uuid",
      "user_id": "uuid",
      "type": "share_download",
      "message": "Your shared file 'report.pdf' was downloaded.",
      "read_at": null,
      "is_read": false,
      "created_at": "2026-07-15T12:00:00Z",
      "related_share_id": "uuid"
    }
  ],
  "items": [ ... ],
  "total": 1,
  "page": 1,
  "per_page": 20,
  "pages": 1,
  "unread_count": 1
}
```

---

#### `PATCH /api/notifications/<id>/read`
Mark a specific notification as read.

**Headers:** `Authorization: Bearer <token>` (required)

**Response (200):**
```json
{
  "message": "Notification marked as read",
  "notification": {
    "id": "uuid",
    "user_id": "uuid",
    "type": "share_download",
    "message": "Your shared file 'report.pdf' was downloaded.",
    "read_at": "2026-07-15T12:05:00Z",
    "is_read": true,
    "created_at": "2026-07-15T12:00:00Z",
    "related_share_id": "uuid"
  }
}
```

**Error (403):** Forbidden (notification belongs to another user)  
**Error (404):** Notification not found

---

### Webhooks

Outbound webhooks notify external systems (e.g., Slack, Zapier, internal tooling) in real-time when sharing events occur without polling audit logs.

#### Signature Verification (HMAC-SHA256)
Every outbound HTTP POST request is signed using the webhook's `secret` with HMAC-SHA256:
- **Headers Sent**:
  - `X-Signature`: Hex-encoded HMAC-SHA256 digest of the raw request payload bytes.
  - `X-Hub-Signature-256`: `sha256=<hex-digest>` (GitHub-compatible).
  - `X-Event-Type`: Name of the event (e.g., `share.downloaded`, `share.revoked`).
  - `Content-Type`: `application/json`.
- **Supported Events**:
  - `share.downloaded`: Dispatched whenever a file share is successfully downloaded.
  - `share.revoked`: Dispatched whenever a file share is revoked.
- **SSRF & DNS-Rebinding Protection**:
  - Webhook URLs must resolve to publicly routable, global IP addresses.
  - Direct IP literals or hostnames resolving to private (RFC 1918), loopback (`127.0.0.1`, `::1`), link-local metadata (`169.254.169.254`, `fe80::/10`), multicast, or reserved ranges are rejected with 400 Bad Request.
  - URLs specifying internal service or database ports (e.g. 22, 3306, 5432, 6379, 3310) are rejected.
  - Resolved IPs are re-validated at actual dispatch time to protect against DNS-rebinding attacks.
  - Outbound requests enforce `allow_redirects=False` to prevent open-redirect SSRF bypasses.

#### `POST /api/webhooks`
Register a new webhook subscription.

**Headers:** `Authorization: Bearer <token>` (required)

**Request:**
```json
{
  "url": "https://example.com/webhooks/listener",
  "secret": "optional-custom-secret",
  "event_types": ["share.downloaded", "share.revoked"],
  "is_active": true
}
```
*(If `secret` is omitted, a random 64-char hex string is generated automatically).*

**Response (201):**
```json
{
  "webhook": {
    "id": "uuid",
    "user_id": "uuid",
    "url": "https://example.com/webhooks/listener",
    "secret": "my-secret-or-generated-hex",
    "event_types": ["share.downloaded", "share.revoked"],
    "is_active": true,
    "created_at": "2026-09-08T14:30:00Z",
    "updated_at": "2026-09-08T14:30:00Z"
  }
}
```

#### `GET /api/webhooks`
List all webhooks registered by the authenticated user.

**Headers:** `Authorization: Bearer <token>` (required)

**Response (200):**
```json
{
  "webhooks": [
    {
      "id": "uuid",
      "user_id": "uuid",
      "url": "https://example.com/webhooks/listener",
      "secret": "...",
      "event_types": ["share.downloaded", "share.revoked"],
      "is_active": true,
      "created_at": "2026-09-08T14:30:00Z",
      "updated_at": "2026-09-08T14:30:00Z"
    }
  ]
}
```

#### `GET /api/webhooks/<webhook_id>`
Retrieve details of a single webhook owned by the user.

**Headers:** `Authorization: Bearer <token>` (required)

**Response (200):**
```json
{
  "webhook": {
    "id": "uuid",
    "user_id": "uuid",
    "url": "https://example.com/webhooks/listener",
    "secret": "...",
    "event_types": ["share.downloaded", "share.revoked"],
    "is_active": true,
    "created_at": "2026-09-08T14:30:00Z",
    "updated_at": "2026-09-08T14:30:00Z"
  }
}
```

#### `PATCH /api/webhooks/<webhook_id>`
Update webhook configuration.

**Headers:** `Authorization: Bearer <token>` (required)

**Request:**
```json
{
  "url": "https://new-url.example.com/hook",
  "secret": "new-secret",
  "event_types": ["share.downloaded"],
  "is_active": false
}
```

**Response (200):**
```json
{
  "webhook": {
    "id": "uuid",
    "user_id": "uuid",
    "url": "https://new-url.example.com/hook",
    "secret": "new-secret",
    "event_types": ["share.downloaded"],
    "is_active": false,
    "created_at": "2026-09-08T14:30:00Z",
    "updated_at": "2026-09-08T14:35:00Z"
  }
}
```

#### `DELETE /api/webhooks/<webhook_id>`
Delete a webhook subscription.

**Headers:** `Authorization: Bearer <token>` (required)

**Response (200):**
```json
{
  "message": "Webhook deleted"
}
```

---

## Security Features

### Share Token Generation
- 256-bit entropy via `secrets.token_urlsafe(32)`
- Never sequential or guessable

### Password Protection
- Argon2id hashing (never stored in plaintext)
- Rate-limited verification (5 attempts / 15 min / IP)
- Grant tokens valid for 15 minutes only

### Permission Enforcement
- Server-side checks on every request
- Permissions: `can_view`, `can_download`, `can_edit`, `can_reshare`

### Expiry & Revocation
- Automatic rejection after `expires_at`
- Soft-delete via `is_revoked` flag
- HTTP 410 (Gone) for expired/revoked shares

### Audit Trail
- Every access logged to `access_logs` table
- Tracks: user, IP, action, success/failure, timestamp

### File Encryption
- AES-256-GCM for files at rest
- Decryption in-memory only (no plaintext on disk)
- Per-file random keys

---

## Health Checks

#### `GET /health` / `GET /healthz`
Readiness and liveness probe for orchestrators, load balancers, and uptime monitors. Verifies database connectivity. No authentication required.

**Response (200 - Healthy):**
```json
{
  "status": "ok",
  "database": "ok"
}
```

**Response (503 - Service Unavailable):**
```json
{
  "status": "error",
  "database": "unavailable",
  "message": "connection refused"
}
```

---

## Error Codes

| Code | Meaning                          |
|------|----------------------------------|
| 200  | Success                          |
| 201  | Created                          |
| 400  | Bad Request (validation error)   |
| 401  | Unauthorized (missing/invalid JWT or password) |
| 403  | Forbidden (permission denied)    |
| 404  | Not Found                        |
| 409  | Conflict (duplicate username/email) |
| 410  | Gone (expired or revoked share)  |
| 429  | Too Many Requests (rate limited) |
| 500  | Internal Server Error            |
| 503  | Service Unavailable (DB down)    |

---

## Testing the API

### Using cURL

**1. Register:**
```bash
curl -X POST https://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@test.com","password":"Test1234!"}'
```

**2. Login:**
```bash
TOKEN=$(curl -X POST https://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@test.com","password":"Test1234!"}' \
  | jq -r .access_token)
```

**3. Upload file:**
```bash
FILE_ID=$(curl -X POST https://localhost:5000/api/files \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@document.pdf" \
  | jq -r .file.id)
```

**4. Create share:**
```bash
curl -X POST https://localhost:5000/api/files/$FILE_ID/share \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"permissions":{"can_view":true,"can_download":true},"password":"secret"}'
```

### Using Postman
Import `postman_collection.json` and follow the pre-configured requests.
