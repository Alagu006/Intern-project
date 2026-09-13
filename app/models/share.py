import uuid
import secrets
from datetime import datetime, timezone
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from app.extensions import db

ph = PasswordHasher()


class Share(db.Model):
    __tablename__ = "shares"

    id = db.Column(db.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    file_id = db.Column(
        db.UUID(as_uuid=True),
        db.ForeignKey("files.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    owner_id = db.Column(
        db.UUID(as_uuid=True),
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Nullable → "anyone with the link" mode
    recipient_id = db.Column(
        db.UUID(as_uuid=True),
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    # Granular permissions
    can_view = db.Column(db.Boolean, default=True, nullable=False)
    can_download = db.Column(db.Boolean, default=False, nullable=False)
    can_edit = db.Column(db.Boolean, default=False, nullable=False)
    can_reshare = db.Column(db.Boolean, default=False, nullable=False)

    # Cryptographically random token (URL-safe base64, 32 bytes → 43 chars)
    share_token = db.Column(db.String(64), unique=True, nullable=False, index=True)

    # Optional human-readable custom slug (3-64 chars, alphanumeric + hyphens)
    custom_slug = db.Column(db.String(64), unique=True, nullable=True, index=True)

    # Optional Argon2-hashed password — never stored in plaintext
    password_hash = db.Column(db.Text, nullable=True)

    # Optional expiry
    expires_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # Optional pinned version (None = dynamic, always points to current/latest version)
    pinned_version = db.Column(db.Integer, nullable=True)

    is_revoked = db.Column(db.Boolean, default=False, nullable=False)

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    file = db.relationship("File", back_populates="shares")
    owner = db.relationship("User", foreign_keys=[owner_id], back_populates="shares_created")
    recipient = db.relationship(
        "User", foreign_keys=[recipient_id], back_populates="shares_received"
    )
    access_logs = db.relationship(
        "AccessLog", back_populates="share", lazy="dynamic", cascade="all, delete-orphan"
    )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def generate_token() -> str:
        """CSPRNG token — secrets.token_urlsafe uses os.urandom internally."""
        return secrets.token_urlsafe(32)

    def set_password(self, plaintext: str) -> None:
        """Hash and store the share-link password."""
        self.password_hash = ph.hash(plaintext)

    def verify_password(self, plaintext: str) -> bool:
        if not self.password_hash:
            return True  # no password set → open link
        try:
            return ph.verify(self.password_hash, plaintext)
        except VerifyMismatchError:
            return False

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        expires_at = self.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > expires_at

    def is_valid(self) -> bool:
        if self.is_revoked or self.is_expired():
            return False
        if self.owner is not None and not self.owner.is_active:
            return False
        return True

    def permissions_dict(self) -> dict:
        return {
            "can_view": self.can_view,
            "can_download": self.can_download,
            "can_edit": self.can_edit,
            "can_reshare": self.can_reshare,
        }

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "file_id": str(self.file_id),
            "recipient_id": str(self.recipient_id) if self.recipient_id else None,
            "permissions": self.permissions_dict(),
            "can_view": self.can_view,
            "can_download": self.can_download,
            "can_edit": self.can_edit,
            "can_reshare": self.can_reshare,
            "share_token": self.share_token,
            "custom_slug": self.custom_slug,
            "pinned_version": self.pinned_version,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_revoked": self.is_revoked,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
