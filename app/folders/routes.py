"""
Folder management endpoints.
Blueprint: /api/folders
"""

import uuid
from flask import Blueprint, request, jsonify
from app.extensions import db
from app.models import Folder, File
from app.auth.decorators import jwt_required

bp = Blueprint("folders", __name__, url_prefix="/api/folders")


@bp.route("", methods=["POST"])
@jwt_required
def create_folder(current_user):
    """
    Create a new folder for the current user.
    Body (JSON):
      - name: string (required)
      - parent_id: UUID string or null (optional)
    """
    data = request.get_json(silent=True) or {}
    name = str(data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Folder name is required"}), 400

    parent_id = data.get("parent_id")
    parent_uuid = None
    if parent_id:
        try:
            parent_uuid = uuid.UUID(str(parent_id))
        except ValueError:
            return jsonify({"error": "Invalid parent_id format"}), 400

        parent_folder = db.session.get(Folder, parent_uuid)
        if parent_folder is None:
            return jsonify({"error": "Parent folder not found"}), 404
        if parent_folder.owner_id != current_user.id:
            return jsonify({"error": "Forbidden: parent folder belongs to another user"}), 403

    folder = Folder(
        owner_id=current_user.id,
        parent_id=parent_uuid,
        name=name,
    )
    db.session.add(folder)
    db.session.commit()

    return jsonify({"folder": folder.to_dict()}), 201


@bp.route("", methods=["GET"])
@jwt_required
def list_folders(current_user):
    """
    List folders owned by the current user.
    Query params:
      - parent_id: filter by parent folder ("root" or "none" for top-level folders, or a UUID)
    """
    query = Folder.query.filter_by(owner_id=current_user.id)

    parent_param = request.args.get("parent_id")
    if parent_param:
        parent_param = parent_param.strip()
        if parent_param.lower() in ("null", "none", "root"):
            query = query.filter(Folder.parent_id.is_(None))
        else:
            try:
                p_uuid = uuid.UUID(parent_param)
                query = query.filter(Folder.parent_id == p_uuid)
            except ValueError:
                return jsonify({"error": "Invalid parent_id format"}), 400

    folders = query.order_by(Folder.name.asc(), Folder.created_at.asc()).all()
    folder_items = [f.to_dict() for f in folders]

    return jsonify({
        "folders": folder_items,
        "items": folder_items,
        "total": len(folder_items),
    }), 200


@bp.route("/<uuid:folder_id>", methods=["GET"])
@jwt_required
def get_folder(current_user, folder_id: uuid.UUID):
    """
    Retrieve details of a folder, including direct subfolders and contained files.
    """
    folder = db.session.get(Folder, folder_id)
    if folder is None:
        return jsonify({"error": "Folder not found"}), 404

    if folder.owner_id != current_user.id:
        return jsonify({"error": "Forbidden"}), 403

    subfolders = [sf.to_dict() for sf in folder.subfolders]
    files = [f.to_dict() for f in folder.files]

    return jsonify({
        "folder": folder.to_dict(),
        "subfolders": subfolders,
        "files": files,
    }), 200


@bp.route("/<uuid:folder_id>", methods=["DELETE"])
@jwt_required
def delete_folder(current_user, folder_id: uuid.UUID):
    """
    Delete a folder. Files residing in this folder have their folder_id set to NULL
    (moved to root) so no user files are lost. Subfolders are cascade deleted.
    """
    folder = db.session.get(Folder, folder_id)
    if folder is None:
        return jsonify({"error": "Folder not found"}), 404

    if folder.owner_id != current_user.id:
        return jsonify({"error": "Forbidden"}), 403

    # Safely detach files so they are preserved
    def _detach_files(fld):
        for f in fld.files:
            f.folder_id = None
        for sf in fld.subfolders:
            _detach_files(sf)

    _detach_files(folder)
    db.session.flush()

    db.session.delete(folder)
    db.session.commit()

    return jsonify({"message": "Folder deleted successfully"}), 200
