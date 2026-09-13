import uuid
from datetime import datetime, timezone
from app.extensions import db


class Notification(db.Model):
    __tablename__ = "notifications"

    id = db.Column(db.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(
        db.UUID(as_uuid=True),
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    type = db.Column(db.String(64), nullable=False)  # e.g. "share_download", "share_view"
    message = db.Column(db.Text, nullable=False)
    read_at = db.Column(db.DateTime(timezone=True), nullable=True, index=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    related_share_id = db.Column(
        db.UUID(as_uuid=True),
        db.ForeignKey("shares.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Relationships
    user = db.relationship("User", backref=db.backref("notifications", lazy="dynamic", cascade="all, delete-orphan"))
    share = db.relationship("Share", backref=db.backref("notifications", lazy="dynamic"))

    def mark_as_read(self) -> None:
        self.read_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "type": self.type,
            "message": self.message,
            "read_at": self.read_at.isoformat() if self.read_at else None,
            "is_read": self.read_at is not None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "related_share_id": str(self.related_share_id) if self.related_share_id else None,
        }
