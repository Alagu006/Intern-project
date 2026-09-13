import uuid
from datetime import datetime, timezone
from app.extensions import db


class AccessLog(db.Model):
    __tablename__ = "access_logs"

    id = db.Column(db.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    share_id = db.Column(
        db.UUID(as_uuid=True),
        db.ForeignKey("shares.id", ondelete="CASCADE"),
        nullable=True,  # Nullable for admin actions
        index=True,
    )
    # Nullable — anonymous access is possible on public links
    accessed_by = db.Column(
        db.UUID(as_uuid=True),
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    ip_address = db.Column(db.String(45), nullable=True)  # IPv4 or IPv6

    # action: "view" | "download" | "edit" | "reshare" | "password_verify"
    action = db.Column(db.String(32), nullable=False)
    success = db.Column(db.Boolean, nullable=False)
    detail = db.Column(db.Text, nullable=True)  # optional failure reason

    timestamp = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    # Relationships
    share = db.relationship("Share", back_populates="access_logs")

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "share_id": str(self.share_id) if self.share_id else None,
            "accessed_by": str(self.accessed_by) if self.accessed_by else None,
            "ip_address": self.ip_address,
            "action": self.action,
            "success": self.success,
            "detail": self.detail,
            "timestamp": self.timestamp.isoformat(),
        }
