# Module 6: Admin Dashboard & User Management

## Overview

Module 6 adds comprehensive admin capabilities to the Secure File Sharing System, enabling administrators to manage users, monitor storage, view audit logs, and access system-wide statistics.

---

## Features

### 1. User Management
- List all users with pagination
- Search by username or email
- Filter by role (admin/user) and status (active/disabled)
- View detailed user information
- Disable/enable user accounts
- Track last login and MFA status

### 2. File Management
- View all files across all users
- Sort by size or upload date
- Filter by owner
- See share count per file

### 3. Storage Monitoring
- Total storage used system-wide
- Top consumers (users using most storage)
- Storage breakdown by file type
- Historical storage growth

### 4. Audit Logs
- View all access logs with pagination
- Filter by user, action, date range, success/failure
- Export logs as CSV (sanitized against formula injection)
- Track admin actions separately

### 5. System Statistics
- Total users and files
- Today's uploads and downloads
- Active shared files count
- Failed login attempts
- Time-series charts (uploads, downloads, storage, activity)

---

## API Endpoints

All endpoints require JWT authentication + admin role.

### User Management

**List Users**
```http
GET /api/admin/users?page=1&per_page=20&search=alice&role=user&active=true
Authorization: Bearer {admin_token}
```

**Get User Detail**
```http
GET /api/admin/users/{user_id}
Authorization: Bearer {admin_token}
```

**Disable User**
```http
PATCH /api/admin/users/{user_id}/disable
Authorization: Bearer {admin_token}
```

**Enable User**
```http
PATCH /api/admin/users/{user_id}/enable
Authorization: Bearer {admin_token}
```

**Update User Storage Quota**
```http
PATCH /api/admin/users/{user_id}/quota
Authorization: Bearer {admin_token}
Content-Type: application/json

{
  "storage_quota_bytes": 104857600
}
```
*(Accepts `storage_quota_bytes` (integer or `null` for unlimited) or `storage_quota_mb` (float/int or `null`).)*


### File Management

**List All Files**
```http
GET /api/admin/files?page=1&per_page=20&sort=size
Authorization: Bearer {admin_token}
```

### Storage Monitoring

**Get Storage Usage**
```http
GET /api/admin/storage
Authorization: Bearer {admin_token}
```

Response:
```json
{
  "total_storage_bytes": 1073741824,
  "top_users": [
    {
      "user_id": "uuid",
      "username": "alice",
      "email": "alice@example.com",
      "storage_used_bytes": 536870912
    }
  ],
  "storage_by_type": [
    {
      "mime_type": "application/pdf",
      "file_count": 150,
      "total_size_bytes": 429496729
    }
  ]
}
```

### Audit Logs

**View Audit Logs**
```http
GET /api/admin/audit-logs?page=1&user_id={uuid}&action=download&start_date=2026-01-01&success=true
Authorization: Bearer {admin_token}
```

**Export Audit Logs (CSV)**
```http
GET /api/admin/audit-logs/export?start_date=2026-01-01&end_date=2026-12-31
Authorization: Bearer {admin_token}
```

### System Statistics

**Get Summary Statistics**
```http
GET /api/admin/stats/summary
Authorization: Bearer {admin_token}
```

Response:
```json
{
  "total_users": 1543,
  "total_files": 8921,
  "uploads_today": 127,
  "downloads_today": 456,
  "shared_files_count": 324,
  "failed_login_attempts_today": 12
}
```

**Get Chart Data**
```http
GET /api/admin/stats/charts?metric=uploads&range=7d
Authorization: Bearer {admin_token}
```

Metrics: `uploads`, `downloads`, `storage`, `activity`  
Ranges: `7d`, `30d`, `90d`

Response:
```json
{
  "metric": "uploads",
  "range": "7d",
  "data": [
    {"date": "2026-07-09", "value": 45},
    {"date": "2026-07-10", "value": 52},
    {"date": "2026-07-11", "value": 38},
    {"date": "2026-07-12", "value": 61},
    {"date": "2026-07-13", "value": 47},
    {"date": "2026-07-14", "value": 55},
    {"date": "2026-07-15", "value": 127}
  ]
}
```

---

## Database Changes

### New User Fields

```sql
ALTER TABLE users ADD COLUMN role VARCHAR(20) DEFAULT 'user' NOT NULL;
ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT true NOT NULL;
ALTER TABLE users ADD COLUMN disabled_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN last_login TIMESTAMPTZ;

CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_is_active ON users(is_active);
```

### New Indexes for Performance

```sql
CREATE INDEX idx_access_logs_timestamp ON access_logs(timestamp);
CREATE INDEX idx_files_created_at ON files(created_at);
```

---

## Security

### Role-Based Access Control

- Every `/api/admin/*` endpoint checks `user.role == 'admin'`
- Non-admin users receive HTTP 403 Forbidden
- Disabled accounts cannot authenticate

### Account Disabling

When an admin disables a user:
1. `is_active` set to `false`
2. `disabled_at` timestamp recorded
3. User's existing JWT will be rejected on next request
4. User cannot log in until re-enabled
5. Action is logged to audit trail

### Admin Action Logging

All admin actions are logged to `access_logs`:
- `admin_disable_user`
- `admin_enable_user`
- `admin_export_logs`

Each log includes:
- Admin user ID (accessed_by)
- IP address
- Timestamp
- Action detail

### CSV Export Security

CSV exports are sanitized against formula injection:
- Fields starting with `=`, `+`, `-`, `@` are prefixed with `'`
- Prevents malicious formulas in Excel/LibreOffice
- Export is limited to 10,000 rows maximum

---

## Creating the First Admin

### Method 1: Python Script

```python
from app import create_app
from app.extensions import db
from app.models import User

app = create_app()
with app.app_context():
    admin = User(
        username='admin',
        email='admin@yourdomain.com',
        role='admin'
    )
    admin.set_password('SecurePassword123!')
    db.session.add(admin)
    db.session.commit()
    print(f"Admin created: {admin.username}")
```

### Method 2: SQL (after hashing password separately)

```sql
INSERT INTO users (id, username, email, password_hash, role, is_active, created_at)
VALUES (
    gen_random_uuid(),
    'admin',
    'admin@yourdomain.com',
    '{argon2_hash_here}',
    'admin',
    true,
    NOW()
);
```

---

## Performance Considerations

### Query Optimization

- **Date range queries** use indexed `timestamp` and `created_at` columns
- **User lookups** use indexed `role` and `is_active` columns
- **Pagination** prevents loading entire tables into memory

### Caching (Optional)

For high-traffic dashboards, consider caching:

```python
from flask_caching import Cache

cache = Cache(config={'CACHE_TYPE': 'simple', 'CACHE_DEFAULT_TIMEOUT': 60})

@cache.cached(timeout=60)
def get_summary_stats():
    # ... expensive queries ...
```

### Export Limits

- CSV exports limited to 10,000 rows
- Recommend date range filters for large datasets
- Consider background job for very large exports

---

## Testing

Run admin tests:

```bash
pytest tests/test_admin.py -v
```

Tests cover:
- ✅ Role enforcement (403 for non-admin)
- ✅ User disable/enable workflow
- ✅ Disabled user cannot login
- ✅ User listing with filters
- ✅ Storage statistics accuracy
- ✅ Audit log viewing and filtering
- ✅ CSV export with formula injection prevention
- ✅ System statistics calculation
- ✅ Chart data generation
- ✅ Admin action logging

---

## Usage Examples

### Disable a malicious user

```bash
curl -X PATCH https://api.example.com/api/admin/users/{user_id}/disable \
  -H "Authorization: Bearer {admin_token}"
```

### Export audit logs for compliance

```bash
curl https://api.example.com/api/admin/audit-logs/export \
  ?start_date=2026-01-01 \
  ?end_date=2026-12-31 \
  -H "Authorization: Bearer {admin_token}" \
  -o audit_logs_2026.csv
```

### Monitor today's activity

```bash
curl https://api.example.com/api/admin/stats/summary \
  -H "Authorization: Bearer {admin_token}"
```

### View top storage consumers

```bash
curl https://api.example.com/api/admin/storage \
  -H "Authorization: Bearer {admin_token}"
```

---

## Troubleshooting

### "Admin access required" error

- Verify your user has `role='admin'` in the database
- Check JWT token is valid and not expired
- Ensure `is_active=true` for your admin account

### Empty statistics

- Run the database migration to create indexes
- Ensure there is data in the system (users, files, logs)
- Check date range parameters are correct

### CSV export fails

- Check that you have access_logs data
- Verify date range isn't too large (>10,000 rows)
- Ensure proper permissions on the export endpoint

---

## Frontend Integration

For building an admin dashboard UI, use these endpoints:

### Dashboard Page

```javascript
// Fetch summary stats
const stats = await fetch('/api/admin/stats/summary', {
  headers: { 'Authorization': `Bearer ${token}` }
}).then(r => r.json());

// Display in cards: Total Users, Total Files, Uploads Today, etc.
```

### Charts

```javascript
// Fetch uploads chart data
const uploadsData = await fetch(
  '/api/admin/stats/charts?metric=uploads&range=7d',
  { headers: { 'Authorization': `Bearer ${token}` }}
).then(r => r.json());

// Use with Chart.js, D3, or similar
new Chart(ctx, {
  type: 'line',
  data: {
    labels: uploadsData.data.map(d => d.date),
    datasets: [{
      label: 'Uploads',
      data: uploadsData.data.map(d => d.value)
    }]
  }
});
```

### Users Table

```javascript
// Fetch users with search and filters
const users = await fetch(
  '/api/admin/users?page=1&search=alice&role=user',
  { headers: { 'Authorization': `Bearer ${token}` }}
).then(r => r.json());

// Display in table with Disable/Enable buttons
```

---

## Production Checklist

- [ ] Create initial admin user with strong password
- [ ] Enable rate limiting on admin endpoints
- [ ] Set up monitoring for admin actions
- [ ] Configure log retention policy
- [ ] Test account disable/enable workflow
- [ ] Verify CSV export sanitization
- [ ] Set up alerts for failed login spikes
- [ ] Document admin procedures
- [ ] Train admin staff on dashboard usage
- [ ] Regular audit log reviews

---

**Module 6 Status: Complete ✅**

All admin functionality implemented and tested.
