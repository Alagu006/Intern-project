import uuid
from datetime import datetime, timezone
from app.extensions import db


class File(db.Model):
    __tablename__ = "files"

    id = db.Column(db.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id = db.Column(
        db.UUID(as_uuid=True), db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    # Original filename (for Content-Disposition on download)
    filename = db.Column(db.String(512), nullable=False)
    mime_type = db.Column(db.String(128), nullable=False, default="application/octet-stream")
    size_bytes = db.Column(db.BigInteger, nullable=False, default=0)

    # Path to the AES-256-GCM encrypted blob on disk
    encrypted_path = db.Column(db.Text, nullable=False)

    # 96-bit nonce stored as hex (12 bytes → 24 hex chars)
    nonce_hex = db.Column(db.String(24), nullable=False)

    # Per-file DEK wrapped with server-side KEK using AES-256-GCM, stored as hex
    wrapped_key_hex = db.Column(db.Text, nullable=False)

    def __init__(self, **kwargs):
        # Backwards compatibility: allow callers to pass encrypted_key_hex
        if "encrypted_key_hex" in kwargs and "wrapped_key_hex" not in kwargs:
            kwargs["wrapped_key_hex"] = kwargs.pop("encrypted_key_hex")
        super().__init__(**kwargs)

    @property
    def encrypted_key_hex(self) -> str:
        """Alias for wrapped_key_hex for backward compatibility."""
        return self.wrapped_key_hex

    @encrypted_key_hex.setter
    def encrypted_key_hex(self, value: str):
        self.wrapped_key_hex = value

    # Optional folder organization
    folder_id = db.Column(
        db.UUID(as_uuid=True),
        db.ForeignKey("folders.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Optional auto-deletion expiration timestamp
    auto_delete_at = db.Column(
        db.DateTime(timezone=True),
        nullable=True,
        index=True,
    )

    # Soft-delete timestamp (null = active, timestamp = in trash)
    deleted_at = db.Column(
        db.DateTime(timezone=True),
        nullable=True,
        index=True,
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    owner = db.relationship("User", back_populates="files")
    folder = db.relationship("Folder", back_populates="files")
    tags = db.relationship("Tag", secondary="file_tags", back_populates="files")
    shares = db.relationship(
        "Share", back_populates="file", lazy="dynamic", cascade="all, delete-orphan"
    )
    versions = db.relationship(
        "FileVersion",
        back_populates="file",
        cascade="all, delete-orphan",
        order_by="FileVersion.version_number.desc()",
    )

    @property
    def is_expired(self) -> bool:
        if self.auto_delete_at is None:
            return False
        exp = self.auto_delete_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return exp <= datetime.now(timezone.utc)

    @property
    def is_deleted(self) -> bool:
        return self.deleted_at is not None

    @property
    def current_version_number(self) -> int:
        if self.versions:
            return self.versions[0].version_number
        return 1

    def to_dict(self) -> dict:
        auto_delete_iso = None
        if self.auto_delete_at:
            exp = self.auto_delete_at
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            auto_delete_iso = exp.isoformat()

        deleted_iso = None
        if self.deleted_at:
            dt = self.deleted_at
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            deleted_iso = dt.isoformat()

        return {
            "id": str(self.id),
            "filename": self.filename,
            "mime_type": self.mime_type,
            "size_bytes": self.size_bytes,
            "version": self.current_version_number,
            "folder_id": str(self.folder_id) if self.folder_id else None,
            "tags": [t.name for t in self.tags],
            "tag_objects": [t.to_dict() for t in self.tags],
            "auto_delete_at": auto_delete_iso,
            "is_expired": self.is_expired,
            "deleted_at": deleted_iso,
            "is_deleted": self.is_deleted,
            "created_at": self.created_at.isoformat(),
        }

