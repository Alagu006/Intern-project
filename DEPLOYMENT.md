# Deployment Guide

## Production Checklist

### 1. Environment Variables
```bash
export DATABASE_URL=postgresql://user:pass@db-host:5432/secure_files
export JWT_SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
export UPLOAD_FOLDER=/var/secure_files
export BASE_URL=https://files.yourdomain.com
export RATELIMIT_STORAGE_URI=redis://localhost:6379/0  # use Redis in production
```

### 2. Database Setup
```bash
# Run migrations
python manage.py init
python manage.py migrate
python manage.py upgrade

# Verify tables
psql $DATABASE_URL -c "\dt"
# Should show: users, files, shares, access_logs, alembic_version
```

### 3. File Storage
```bash
# Create upload directory with restricted permissions
sudo mkdir -p /var/secure_files
sudo chown appuser:appuser /var/secure_files
sudo chmod 700 /var/secure_files
```

### 4. Application Server (Gunicorn)
```bash
pip install gunicorn

# Run with TLS (use your cert paths)
gunicorn \
    --bind 0.0.0.0:5000 \
    --workers 4 \
    --timeout 120 \
    --certfile=/etc/ssl/certs/server.crt \
    --keyfile=/etc/ssl/private/server.key \
    wsgi:app
```

### 5. Reverse Proxy (Nginx)
```nginx
server {
    listen 443 ssl http2;
    server_name files.yourdomain.com;

    ssl_certificate /etc/ssl/certs/server.crt;
    ssl_certificate_key /etc/ssl/private/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    client_max_body_size 100M;  # max file upload size

    location / {
        proxy_pass https://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Long timeout for large file uploads/downloads
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }
}
```

### 6. Rate Limiting (Redis)
> **CRITICAL**: In any multi-process deployment (such as Gunicorn with multiple workers), rate limiting **must** use a shared storage backend like Redis. By default, `RATELIMIT_STORAGE_URI` falls back to `memory://`, which creates an isolated in-memory counter per worker process. This allows attackers to bypass rate limits by distributing requests across different workers. Setting `RATELIMIT_STORAGE_URI=redis://...` ensures shared, centralized rate limit state across all workers.

```bash
# Install Redis
sudo apt-get install redis-server
sudo systemctl enable redis-server
sudo systemctl start redis-server

# Update environment to use Redis for rate limiting (e.g. redis://host:port/db)
export RATELIMIT_STORAGE_URI=redis://localhost:6379/0
```

### 7. ClamAV Antivirus Daemon (Malware Protection)
Production environments should always enable pre-encryption malware scanning:
```bash
# Install ClamAV daemon
sudo apt-get install clamav clamav-daemon
sudo freshclam  # update virus signatures
sudo systemctl enable clamav-daemon
sudo systemctl start clamav-daemon

# Configure application environment
export SCAN_UPLOADS=true
export CLAMD_HOST=127.0.0.1
export CLAMD_PORT=3310
```

### 8. Systemd Service
Create `/etc/systemd/system/secure-files.service`:
```ini
[Unit]
Description=Secure File Sharing API
After=network.target postgresql.service redis.service clamav-daemon.service

[Service]
Type=notify
User=appuser
Group=appuser
WorkingDirectory=/opt/secure_file_share
Environment="DATABASE_URL=postgresql://..."
Environment="JWT_SECRET_KEY=..."
Environment="SECRET_KEY=..."
Environment="UPLOAD_FOLDER=/var/secure_files"
Environment="BASE_URL=https://files.yourdomain.com"
Environment="RATELIMIT_STORAGE_URI=redis://localhost:6379/0"
Environment="SCAN_UPLOADS=true"
Environment="CLAMD_HOST=127.0.0.1"
Environment="CLAMD_PORT=3310"

ExecStart=/opt/secure_file_share/venv/bin/gunicorn \
    --bind 127.0.0.1:5000 \
    --workers 4 \
    --timeout 120 \
    --certfile=/etc/ssl/certs/server.crt \
    --keyfile=/etc/ssl/private/server.key \
    wsgi:app

Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable secure-files
sudo systemctl start secure-files
sudo systemctl status secure-files
```

### 8. Monitoring & Logs
```bash
# Application logs
journalctl -u secure-files -f

# Access logs (install in shares/routes.py)
# Log every access to a centralized system like ELK or CloudWatch
```

### 9. Backup Strategy
```bash
# Database backups (daily cron)
pg_dump $DATABASE_URL | gzip > /backups/secure_files_$(date +%Y%m%d).sql.gz

# Encrypted file backups
rsync -avz /var/secure_files/ /backups/encrypted_files/
```

### 10. Security Hardening
- [ ] Use a proper TLS certificate (Let's Encrypt or commercial)
- [ ] Set `HSTS` headers in Nginx
- [ ] Enable CORS only for trusted origins
- [ ] Use a WAF (Web Application Firewall) in front of the app
- [ ] Rotate `JWT_SECRET_KEY` periodically (invalidates all tokens)
- [ ] Enable PostgreSQL SSL connections
- [ ] Run the app as a non-root user
- [ ] Set up intrusion detection (fail2ban for repeated password failures)
- [ ] Regular security audits of `access_logs` table

### 11. Expired File Auto-Deletion (Cron Job)
Files configured with an `auto_delete_at` timestamp are automatically purged by `scripts/cleanup_expired_files.py`. The cleanup script revokes any active shares, securely deletes encrypted file and version blobs from disk, and cascade-removes database records.

Schedule the cleanup job to run periodically (e.g. hourly or every 15 minutes) using `crontab -e`:
```bash
# Run file cleanup script every hour at minute 0
0 * * * * cd /opt/secure_file_share && /opt/secure_file_share/venv/bin/python scripts/cleanup_expired_files.py >> /var/log/secure_files_cleanup.log 2>&1

# Alternatively, run every 15 minutes:
# */15 * * * * cd /opt/secure_file_share && /opt/secure_file_share/venv/bin/python scripts/cleanup_expired_files.py >> /var/log/secure_files_cleanup.log 2>&1
```

Or configure via a systemd timer (`/etc/systemd/system/secure-files-cleanup.timer`):
```ini
[Unit]
Description=Run Secure File Share Expired Files Cleanup Hourly

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
```

---

## Docker (Optional)

```dockerfile
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /var/secure_files && chmod 700 /var/secure_files

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "wsgi:app"]
```

`docker-compose.yml`:
```yaml
version: "3.9"

services:
  db:
    image: postgres:15
    environment:
      POSTGRES_DB: secure_files
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: changeme
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  app:
    build: .
    ports:
      - "5000:5000"
    environment:
      DATABASE_URL: postgresql://postgres:changeme@db:5432/secure_files
      JWT_SECRET_KEY: change-me-in-production
      SECRET_KEY: change-me-in-production
      BASE_URL: https://localhost:5000
      RATELIMIT_STORAGE_URI: redis://redis:6379/0
    depends_on:
      - db
      - redis
    volumes:
      - file_storage:/var/secure_files

volumes:
  postgres_data:
  file_storage:
```

Run:
```bash
docker-compose up -d
docker-compose exec app python manage.py upgrade
```
