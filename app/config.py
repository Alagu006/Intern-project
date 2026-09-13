import os
import tempfile
from datetime import timedelta


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-in-production")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "postgresql://postgres:password@localhost:5432/secure_files"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # JWT
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "jwt-secret-change-me")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)

    # File storage (encrypted blobs stored here)
    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "/var/secure_files")

    # Staging directory for chunked uploads (outside UPLOAD_FOLDER)
    UPLOAD_STAGING_DIR = os.environ.get(
        "UPLOAD_STAGING_DIR", os.path.join(tempfile.gettempdir(), "secure_file_staging")
    )

    # File upload limits (default: 100MB)
    MAX_UPLOAD_SIZE_MB = int(os.environ.get("MAX_UPLOAD_SIZE_MB", 100))
    MAX_CONTENT_LENGTH = int(
        os.environ.get("MAX_CONTENT_LENGTH", MAX_UPLOAD_SIZE_MB * 1024 * 1024)
    )

    # Per-user storage quota (default: 500MB; None or <= 0 means unlimited)
    _quota_mb_env = os.environ.get("DEFAULT_USER_QUOTA_MB")
    DEFAULT_USER_QUOTA_MB = int(_quota_mb_env) if _quota_mb_env is not None else 500
    DEFAULT_USER_QUOTA_BYTES = (
        DEFAULT_USER_QUOTA_MB * 1024 * 1024
        if DEFAULT_USER_QUOTA_MB is not None and DEFAULT_USER_QUOTA_MB > 0
        else None
    )

    # Rate limiting
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_HEADERS_ENABLED = True

    # Master Key Encryption Key (KEK) for envelope encryption (32 random bytes, Base64-encoded)
    MASTER_KEK = os.environ.get("MASTER_KEK")

    # Share link base URL (used when building share URLs and QR codes)
    BASE_URL = os.environ.get("BASE_URL", "https://localhost:5000")

    # CORS: Allowed origins (comma-separated list, e.g. "http://localhost:3000,http://localhost:5173")
    # Never default to "*" because the API uses Authorization headers
    _raw_origins = os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000")
    if isinstance(_raw_origins, str):
        ALLOWED_ORIGINS = [
            origin.strip()
            for origin in _raw_origins.split(",")
            if origin.strip()
        ]
    else:
        ALLOWED_ORIGINS = list(_raw_origins)


    # API Documentation (Swagger UI & OpenAPI specification)
    # Disabled by default in production; enabled if DEBUG is True or ENABLE_API_DOCS is True
    DEBUG = os.environ.get("DEBUG", "false").lower() in ("true", "1", "yes")
    ENABLE_API_DOCS = os.environ.get("ENABLE_API_DOCS", "false").lower() in (
        "true",
        "1",
        "yes",
    ) or DEBUG

    # ClamAV Malware Scanning
    # Disabled by default (fail gracefully) so environments without ClamAV daemon installed don't break;
    # Should be enabled in production environments.
    SCAN_UPLOADS = os.environ.get("SCAN_UPLOADS", "false").lower() in ("true", "1", "yes")
    CLAMD_HOST = os.environ.get("CLAMD_HOST", "127.0.0.1")
    CLAMD_PORT = int(os.environ.get("CLAMD_PORT", 3310))
    CLAMD_TIMEOUT = float(os.environ.get("CLAMD_TIMEOUT", 10.0))


    # Trash retention in days (soft-deleted files older than this are permanently purged)
    TRASH_RETENTION_DAYS = int(os.environ.get("TRASH_RETENTION_DAYS", 30))

    # Google OAuth
    GOOGLE_OAUTH_CLIENT_ID = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
    GOOGLE_OAUTH_CLIENT_SECRET = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")
    GOOGLE_OAUTH_REDIRECT_URI = os.environ.get("GOOGLE_OAUTH_REDIRECT_URI")

    # WebAuthn / Passkeys
    WEBAUTHN_RP_ID = os.environ.get("WEBAUTHN_RP_ID", "localhost")
    WEBAUTHN_RP_NAME = os.environ.get("WEBAUTHN_RP_NAME", "Secure File Share")
    WEBAUTHN_ORIGIN = os.environ.get("WEBAUTHN_ORIGIN", "http://localhost:5000")


class TestingConfig(Config):
    TESTING = True
    ENABLE_API_DOCS = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    RATELIMIT_ENABLED = False
    RATELIMIT_STORAGE_URI = "memory://"
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=5)
    # Fixed 32-byte Base64 KEK for testing ("test-master-kek-32-bytes-length!")
    MASTER_KEK = "dGVzdC1tYXN0ZXIta2VrLTMyLWJ5dGVzLWxlbmd0aCE="
    SCAN_UPLOADS = False
    CLAMD_HOST = "127.0.0.1"
    CLAMD_PORT = 3310
    CLAMD_TIMEOUT = 5.0
    UPLOAD_FOLDER = os.environ.get(
        "UPLOAD_FOLDER", os.path.join(tempfile.gettempdir(), "secure_file_test_uploads")
    )
    UPLOAD_STAGING_DIR = os.path.join(tempfile.gettempdir(), "secure_file_test_staging")
    TRASH_RETENTION_DAYS = 30
    GOOGLE_OAUTH_CLIENT_ID = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
    GOOGLE_OAUTH_CLIENT_SECRET = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")
    GOOGLE_OAUTH_REDIRECT_URI = os.environ.get("GOOGLE_OAUTH_REDIRECT_URI")
    WEBAUTHN_RP_ID = "localhost"
    WEBAUTHN_RP_NAME = "Secure File Share"
    WEBAUTHN_ORIGIN = "http://localhost:5000"


