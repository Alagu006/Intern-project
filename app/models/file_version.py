import uuid
from datetime import datetime, timezone
from app.extensions import db


class FileVersion(db.Model):
    __tablename__ = "file_versions"

    id = db.Column(db.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    file_id = db.Column(
        db.UUID(as_uuid=True),
        db.ForeignKey("files.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    version_number = db.Column(db.Integer, nullable=False)

    filename = db.Column(db.String(512), nullable=False)
    mime_type = db.Column(db.String(128), nullable=False, default="application/octet-stream")
    size_bytes = db.Column(db.BigInteger, nullable=False, default=0)

    # Path to the AES-256-GCM encrypted blob on disk
    encrypted_path = db.Column(db.Text, nullable=False)

    # 96-bit nonce stored as hex (12 bytes -> 24 hex chars)
    nonce_hex = db.Column(db.String(24), nullable=False)

    # Per-version DEK wrapped with server-side KEK using AES-256-GCM, stored as hex
    wrapped_key_hex = db.Column(db.Text, nullable=False)

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    file = db.relationship("File", back_populates="versions")

    __table_args__ = (
        db.UniqueConstraint("file_id", "version_number", name="uq_file_version_number"),
    )

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "file_id": str(self.file_id),
            "version_number": self.version_number,
            "filename": self.filename,
            "mime_type": self.mime_type,
            "size_bytes": self.size_bytes,
            "created_at": self.created_at.isoformat(),
        }
