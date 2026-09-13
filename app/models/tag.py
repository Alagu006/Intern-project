import uuid
from datetime import datetime, timezone
from app.extensions import db

# Many-to-many join table between files and tags
file_tags = db.Table(
    "file_tags",
    db.Column(
        "file_id",
        db.UUID(as_uuid=True),
        db.ForeignKey("files.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    db.Column(
        "tag_id",
        db.UUID(as_uuid=True),
        db.ForeignKey("tags.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class Tag(db.Model):
    __tablename__ = "tags"

    id = db.Column(db.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id = db.Column(
        db.UUID(as_uuid=True),
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name = db.Column(db.String(64), nullable=False, index=True)

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    owner = db.relationship("User", backref=db.backref("tags", cascade="all, delete-orphan"))
    files = db.relationship("File", secondary=file_tags, back_populates="tags")

    __table_args__ = (
        db.UniqueConstraint("owner_id", "name", name="uq_tag_owner_name"),
    )

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "name": self.name,
            "created_at": self.created_at.isoformat(),
        }
