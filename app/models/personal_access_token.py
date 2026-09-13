import uuid
import hashlib
from datetime import datetime, timezone
from app.extensions import db


class PersonalAccessToken(db.Model):
    __tablename__ = "personal_access_tokens"

    id = db.Column(db.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(
        db.UUID(as_uuid=True),
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name = db.Column(db.String(128), nullable=False)
    token_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    last_used_at = db.Column(db.DateTime(timezone=True), nullable=True)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # Relationships
    user = db.relationship("User", back_populates="tokens")

    @staticmethod
    def hash_token(raw_token: str) -> str:
        """Compute SHA-256 hex digest of a raw token."""
        return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    def is_expired(self) -> bool:
        """Check if token has passed its expiration time."""
        if self.expires_at is None:
            return False
        exp = self.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > exp

    def to_dict(self) -> dict:
        """Safe representation excluding raw secret and token hash."""
        return {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "name": self.name,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_expired": self.is_expired(),
        }
