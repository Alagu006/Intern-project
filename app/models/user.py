import uuid
from datetime import datetime, timezone
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from app.extensions import db

ph = PasswordHasher()


def get_default_user_quota_bytes():
    """Retrieve default storage quota in bytes from application config or Config class."""
    try:
        from flask import current_app
        if current_app:
            if "DEFAULT_USER_QUOTA_BYTES" in current_app.config:
                return current_app.config.get("DEFAULT_USER_QUOTA_BYTES")
            if "DEFAULT_USER_QUOTA_MB" in current_app.config:
                mb = current_app.config.get("DEFAULT_USER_QUOTA_MB")
                return int(mb) * 1024 * 1024 if mb and mb > 0 else None
    except (RuntimeError, TypeError, ValueError):
        pass
    from app.config import Config
    mb = getattr(Config, "DEFAULT_USER_QUOTA_MB", 500)
    return int(mb) * 1024 * 1024 if mb and mb > 0 else None


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.Text, nullable=True)

    # OAuth
    oauth_provider = db.Column(db.String(32), nullable=True, index=True)  # 'google'

    # TOTP MFA
    totp_secret = db.Column(db.String(64), nullable=True)
    mfa_enabled = db.Column(db.Boolean, default=False, nullable=False)

    # Role-Based Access Control (Module 6)
    role = db.Column(db.String(20), default="user", nullable=False, index=True)  # 'admin' or 'user'
    
    # Account status (Module 6)
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    disabled_at = db.Column(db.DateTime(timezone=True), nullable=True)
    last_login = db.Column(db.DateTime(timezone=True), nullable=True)

    # Storage quota in bytes (nullable = unlimited)
    storage_quota_bytes = db.Column(db.BigInteger, nullable=True)

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    files = db.relationship("File", back_populates="owner", lazy="dynamic")
    shares_created = db.relationship(
        "Share", foreign_keys="Share.owner_id", back_populates="owner", lazy="dynamic"
    )
    shares_received = db.relationship(
        "Share",
        foreign_keys="Share.recipient_id",
        back_populates="recipient",
        lazy="dynamic",
    )
    tokens = db.relationship(
        "PersonalAccessToken",
        back_populates="user",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )
    upload_sessions = db.relationship(
        "UploadSession",
        back_populates="owner",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )
    webhooks = db.relationship(
        "Webhook",
        back_populates="user",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )
    webauthn_credentials = db.relationship(
        "WebAuthnCredential",
        back_populates="user",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )

    def __init__(self, **kwargs):
        if "storage_quota_bytes" not in kwargs:
            kwargs["storage_quota_bytes"] = get_default_user_quota_bytes()
        super().__init__(**kwargs)

    def set_password(self, plaintext: str) -> None:
        self.password_hash = ph.hash(plaintext)

    def verify_password(self, plaintext: str) -> bool:
        if not self.password_hash:
            return False
        try:
            return ph.verify(self.password_hash, plaintext)
        except VerifyMismatchError:
            return False

    def to_public_dict(self) -> dict:
        return {
            "id": str(self.id),
            "username": self.username,
            "email": self.email,
            "storage_quota_bytes": self.storage_quota_bytes,
            "oauth_provider": self.oauth_provider,
        }

    def to_admin_dict(self) -> dict:
        """Extended info for admin dashboard (no sensitive fields)."""
        return {
            "id": str(self.id),
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "is_active": self.is_active,
            "oauth_provider": self.oauth_provider,
            "mfa_enabled": self.mfa_enabled,
            "storage_quota_bytes": self.storage_quota_bytes,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "disabled_at": self.disabled_at.isoformat() if self.disabled_at else None,
        }

    def is_admin(self) -> bool:
        """Check if user has admin role."""
        return self.role == "admin"

