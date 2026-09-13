import uuid
import base64
from datetime import datetime, timezone
from app.extensions import db


class WebAuthnCredential(db.Model):
    __tablename__ = "webauthn_credentials"

    id = db.Column(db.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(
        db.UUID(as_uuid=True),
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    credential_id = db.Column(db.LargeBinary, unique=True, nullable=False, index=True)
    public_key = db.Column(db.LargeBinary, nullable=False)
    sign_count = db.Column(db.BigInteger, default=0, nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    nickname = db.Column(db.String(64), nullable=True)

    # Relationships
    user = db.relationship("User", back_populates="webauthn_credentials")

    def to_dict(self) -> dict:
        b64_cred_id = base64.urlsafe_b64encode(self.credential_id).decode("utf-8").rstrip("=")
        return {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "credential_id": b64_cred_id,
            "sign_count": self.sign_count,
            "nickname": self.nickname,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
