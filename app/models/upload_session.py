import uuid
from datetime import datetime, timezone
from app.extensions import db


class UploadSession(db.Model):
    __tablename__ = "upload_sessions"

    id = db.Column(db.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id = db.Column(
        db.UUID(as_uuid=True), db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    filename = db.Column(db.String(512), nullable=False, default="upload")
    mime_type = db.Column(db.String(128), nullable=False, default="application/octet-stream")
    total_size_bytes = db.Column(db.BigInteger, nullable=True)
    expected_chunks = db.Column(db.Integer, nullable=False)
    received_chunks = db.Column(db.Integer, nullable=False, default=0)
    status = db.Column(db.String(32), nullable=False, default="in_progress", index=True)

    folder_id = db.Column(
        db.UUID(as_uuid=True), db.ForeignKey("folders.id", ondelete="SET NULL"), nullable=True
    )
    auto_delete_at = db.Column(db.DateTime(timezone=True), nullable=True)
    tags = db.Column(db.Text, nullable=True)

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    owner = db.relationship("User", back_populates="upload_sessions")

    def to_dict(self):
        return {
            "id": str(self.id),
            "upload_id": str(self.id),
            "owner_id": str(self.owner_id),
            "filename": self.filename,
            "mime_type": self.mime_type,
            "total_size_bytes": self.total_size_bytes,
            "expected_chunks": self.expected_chunks,
            "received_chunks": self.received_chunks,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
