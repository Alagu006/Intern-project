"""
Tag management endpoints.
Blueprint: /api/tags
"""

import uuid
from flask import Blueprint, request, jsonify
from app.extensions import db
from app.models import Tag
from app.auth.decorators import jwt_required

bp = Blueprint("tags", __name__, url_prefix="/api/tags")


@bp.route("", methods=["POST"])
@jwt_required
def create_tag(current_user):
    """
    Create a new tag for the current user.
    Body (JSON):
      - name: string (required)
    """
    data = request.get_json(silent=True) or {}
    name = str(data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Tag name is required"}), 400

    # Idempotent: return existing tag if already created by this owner
    existing = Tag.query.filter_by(owner_id=current_user.id, name=name).first()
    if existing:
        return jsonify({"tag": existing.to_dict(), "message": "Tag already exists"}), 200

    tag = Tag(owner_id=current_user.id, name=name)
    db.session.add(tag)
    db.session.commit()

    return jsonify({"tag": tag.to_dict()}), 201


@bp.route("", methods=["GET"])
@jwt_required
def list_tags(current_user):
    """
    List all tags owned by the current user.
    """
    tags = Tag.query.filter_by(owner_id=current_user.id).order_by(Tag.name.asc()).all()
    tag_items = [t.to_dict() for t in tags]

    return jsonify({
        "tags": tag_items,
        "items": tag_items,
        "total": len(tag_items),
    }), 200


@bp.route("/<uuid:tag_id>", methods=["DELETE"])
@jwt_required
def delete_tag(current_user, tag_id: uuid.UUID):
    """
    Delete a tag. File associations in file_tags are removed; files themselves are untouched.
    """
    tag = db.session.get(Tag, tag_id)
    if tag is None:
        return jsonify({"error": "Tag not found"}), 404

    if tag.owner_id != current_user.id:
        return jsonify({"error": "Forbidden"}), 403

    db.session.delete(tag)
    db.session.commit()

    return jsonify({"message": "Tag deleted successfully"}), 200
