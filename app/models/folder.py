import uuid
from datetime import datetime, timezone
from app.extensions import db


class Folder(db.Model):
    __tablename__ = "folders"

    id = db.Column(db.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id = db.Column(
        db.UUID(as_uuid=True),
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    parent_id = db.Column(
        db.UUID(as_uuid=True),
        db.ForeignKey("folders.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    name = db.Column(db.String(255), nullable=False)

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
    owner = db.relationship("User", backref=db.backref("folders", cascade="all, delete-orphan"))
    parent = db.relationship(
        "Folder",
        remote_side=[id],
        backref=db.backref("subfolders", cascade="all, delete-orphan"),
    )
    files = db.relationship("File", back_populates="folder")

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "owner_id": str(self.owner_id),
            "parent_id": str(self.parent_id) if self.parent_id else None,
            "name": self.name,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
