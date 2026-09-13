"""
File upload and listing endpoints.
Encryption happens here before anything touches disk.
"""

import os
import shutil
import tempfile
import uuid
import urllib.parse
import jwt as pyjwt
from datetime import datetime, timedelta, timezone
from flask import Blueprint, request, jsonify, current_app, Response
from sqlalchemy import desc, func, or_
from werkzeug.utils import secure_filename
from app.extensions import db
from app.models import File, FileVersion, Share, Folder, Tag, UploadSession, AccessLog
from app.auth.decorators import jwt_required, jwt_optional
from app.crypto.file_crypto import encrypt_file, decrypt_file, decrypt_file_bytes
from app.files.scanner import scan_file_for_malware
from app.files.thumbnail import (
    ALLOWED_IMAGE_MIMETYPES,
    generate_thumbnail_bytes,
    thumbnail_cache,
    is_supported_image,
)
from app.utils import _get_pagination_params, _paginate_query

bp = Blueprint("files", __name__, url_prefix="/api/files")


def _find_share_by_token_or_slug(token_or_slug: str) -> Share | None:
    return Share.query.filter(
        or_(Share.custom_slug == token_or_slug, Share.share_token == token_or_slug)
    ).first()


def _verify_grant_token(token: str, share_id: uuid.UUID) -> bool:
    try:
        payload = pyjwt.decode(
            token,
            current_app.config["JWT_SECRET_KEY"],
            algorithms=["HS256"],
        )
        return payload.get("type") == "share_grant" and payload.get("sub") == str(share_id)
    except pyjwt.InvalidTokenError:
        return False


def _finalize_file_upload(
    current_user,
    plaintext: bytes,
    raw_filename: str,
    mime_type: str,
    folder_uuid: uuid.UUID = None,
    auto_delete_at: datetime = None,
    raw_tags = None,
):
    """
    Common encryption and persistence logic for uploaded files.
    Performs malware scanning, storage quota enforcement, AES-256-GCM
    envelope encryption, saves the ciphertext to UPLOAD_FOLDER, and persists
    File and FileVersion records.

    Returns:
        tuple (file_record, None) on success, or (None, (response, status_code)) on failure.
    """
    if not plaintext:
        return None, (jsonify({"error": "Empty file"}), 400)

    # Malware scanning before encryption
    is_clean, virus_name = scan_file_for_malware(plaintext)
    if not is_clean:
        return None, (
            jsonify({
                "error": "Malware detected",
                "message": f"File rejected: infected with {virus_name}",
                "virus": virus_name,
            }),
            422,
        )

    # Storage quota enforcement before writing encrypted blob
    if current_user.storage_quota_bytes is not None:
        storage_used = (
            db.session.query(func.sum(File.size_bytes))
            .filter(File.owner_id == current_user.id)
            .scalar()
            or 0
        )
        if storage_used + len(plaintext) > current_user.storage_quota_bytes:
            return None, (
                jsonify({
                    "error": "Storage quota exceeded",
                    "message": (
                        f"Upload of {len(plaintext)} bytes exceeds storage quota "
                        f"({storage_used}/{current_user.storage_quota_bytes} bytes used)"
                    ),
                    "storage_used_bytes": storage_used,
                    "storage_quota_bytes": current_user.storage_quota_bytes,
                    "file_size_bytes": len(plaintext),
                }),
                413,
            )

    ciphertext, nonce_hex, wrapped_key_hex = encrypt_file(plaintext)

    upload_dir = current_app.config["UPLOAD_FOLDER"]
    os.makedirs(upload_dir, exist_ok=True)

    file_id = uuid.uuid4()
    encrypted_path = os.path.join(upload_dir, str(file_id) + ".enc")

    with open(encrypted_path, "wb") as fh:
        fh.write(ciphertext)

    sanitized_filename = secure_filename(raw_filename) or "upload"
    mime = mime_type or "application/octet-stream"

    file_record = File(
        id=file_id,
        owner_id=current_user.id,
        folder_id=folder_uuid,
        filename=sanitized_filename,
        mime_type=mime,
        size_bytes=len(plaintext),
        encrypted_path=encrypted_path,
        nonce_hex=nonce_hex,
        wrapped_key_hex=wrapped_key_hex,
        auto_delete_at=auto_delete_at,
    )

    db.session.add(file_record)

    if raw_tags:
        if isinstance(raw_tags, str):
            tag_list = [t.strip() for t in raw_tags.split(",") if t.strip()]
        elif isinstance(raw_tags, (list, tuple)):
            tag_list = [str(t).strip() for t in raw_tags if str(t).strip()]
        else:
            tag_list = []
        for tname in tag_list:
            t_obj = Tag.query.filter_by(owner_id=current_user.id, name=tname).first()
            if not t_obj:
                t_obj = Tag(owner_id=current_user.id, name=tname)
                db.session.add(t_obj)
            file_record.tags.append(t_obj)

    db.session.flush()

    v1 = FileVersion(
        file_id=file_record.id,
        version_number=1,
        filename=sanitized_filename,
        mime_type=mime,
        size_bytes=len(plaintext),
        encrypted_path=encrypted_path,
        nonce_hex=nonce_hex,
        wrapped_key_hex=wrapped_key_hex,
        created_at=file_record.created_at,
    )
    db.session.add(v1)
    db.session.commit()

    return file_record, None


@bp.route("", methods=["POST"])
@jwt_required
def upload_file(current_user):
    """
    Upload a file.  The file is encrypted with AES-256-GCM before being
    written to disk.  The plaintext is never persisted.

    Form-data: file=<binary>
    """
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    upload = request.files["file"]
    plaintext = upload.read()
    if not plaintext:
        return jsonify({"error": "Empty file"}), 400

    # Optional folder placement
    folder_uuid = None
    folder_id_val = request.form.get("folder_id")
    if folder_id_val and folder_id_val.strip():
        try:
            folder_uuid = uuid.UUID(folder_id_val.strip())
            folder = db.session.get(Folder, folder_uuid)
            if not folder:
                return jsonify({"error": "Folder not found"}), 404
            if folder.owner_id != current_user.id:
                return jsonify({"error": "Forbidden: Folder belongs to another user"}), 403
        except ValueError:
            return jsonify({"error": "Invalid folder_id format"}), 400

    # Optional auto-deletion setting
    auto_delete_at = None
    if request.form.get("auto_delete_days"):
        try:
            days = float(request.form.get("auto_delete_days"))
            if days <= 0:
                return jsonify({"error": "auto_delete_days must be greater than 0"}), 400
            auto_delete_at = datetime.now(timezone.utc) + timedelta(days=days)
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid auto_delete_days format"}), 400
    elif request.form.get("auto_delete_at"):
        raw_auto_delete = request.form.get("auto_delete_at").strip()
        if raw_auto_delete and raw_auto_delete.lower() not in ("null", "none", ""):
            try:
                auto_delete_at = datetime.fromisoformat(raw_auto_delete.replace("Z", "+00:00"))
                if auto_delete_at.tzinfo is None:
                    auto_delete_at = auto_delete_at.replace(tzinfo=timezone.utc)
            except Exception:
                return jsonify({"error": "Invalid auto_delete_at format, expected ISO-8601"}), 400

    raw_tags = request.form.get("tags")
    mime = upload.mimetype or "application/octet-stream"
    raw_filename = upload.filename or "upload"

    file_record, err = _finalize_file_upload(
        current_user=current_user,
        plaintext=plaintext,
        raw_filename=raw_filename,
        mime_type=mime,
        folder_uuid=folder_uuid,
        auto_delete_at=auto_delete_at,
        raw_tags=raw_tags,
    )
    if err:
        return err[0], err[1]

    return jsonify({"file": file_record.to_dict()}), 201


# ---------------------------------------------------------------------------
# Chunked Upload Staging Helpers & Endpoints
# ---------------------------------------------------------------------------

def _get_staging_base_dir() -> str:
    staging_dir = current_app.config.get("UPLOAD_STAGING_DIR")
    if not staging_dir:
        staging_dir = os.path.join(tempfile.gettempdir(), "secure_file_staging")
    os.makedirs(staging_dir, exist_ok=True)
    return staging_dir


def _get_upload_staging_dir(upload_id: uuid.UUID) -> str:
    base = _get_staging_base_dir()
    staging_dir = os.path.join(base, str(upload_id))
    os.makedirs(staging_dir, exist_ok=True)
    return staging_dir


def _get_chunk_file_path(staging_dir: str, chunk_index: int) -> str:
    return os.path.join(staging_dir, f"chunk_{chunk_index}.part")


def cleanup_orphaned_upload_sessions(max_age_hours: int = 24) -> int:
    """
    Remove orphaned upload sessions older than max_age_hours and clean up
    their staging directories on disk.
    Returns the count of cleaned up sessions.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
    orphans = (
        UploadSession.query.filter(
            UploadSession.status == "in_progress",
            UploadSession.created_at < cutoff,
        ).all()
    )
    count = len(orphans)
    staging_base = _get_staging_base_dir()
    for orphan in orphans:
        staging_dir = os.path.join(staging_base, str(orphan.id))
        if os.path.exists(staging_dir):
            shutil.rmtree(staging_dir, ignore_errors=True)
        db.session.delete(orphan)
    db.session.commit()
    return count


@bp.route("/uploads", methods=["POST"])
@jwt_required
def start_upload_session(current_user):
    """
    Start a chunked file upload session.
    JSON body:
    - expected_chunks (int, required): total number of chunks (>= 1)
    - filename (str, optional): original filename
    - mime_type (str, optional): file mime type
    - total_size_bytes (int, optional): expected total file size in bytes
    - folder_id (uuid, optional): folder placement
    - auto_delete_days / auto_delete_at (optional)
    - tags (optional)
    """
    data = request.get_json(silent=True) or {}

    expected_chunks_raw = data.get("expected_chunks")
    if expected_chunks_raw is None:
        expected_chunks_raw = data.get("total_chunks")

    if expected_chunks_raw is None:
        return jsonify({"error": "expected_chunks is required"}), 400

    try:
        expected_chunks = int(expected_chunks_raw)
        if expected_chunks < 1:
            return jsonify({"error": "expected_chunks must be at least 1"}), 400
    except (ValueError, TypeError):
        return jsonify({"error": "expected_chunks must be an integer"}), 400

    filename = (data.get("filename") or "upload").strip()
    mime_type = (data.get("mime_type") or "application/octet-stream").strip()

    total_size_bytes = data.get("total_size_bytes")
    if total_size_bytes is not None:
        try:
            total_size_bytes = int(total_size_bytes)
            if total_size_bytes < 0:
                return jsonify({"error": "total_size_bytes cannot be negative"}), 400
        except (ValueError, TypeError):
            return jsonify({"error": "total_size_bytes must be an integer"}), 400

    # Optional folder placement
    folder_uuid = None
    folder_id_val = data.get("folder_id")
    if folder_id_val:
        try:
            folder_uuid = uuid.UUID(str(folder_id_val).strip())
            folder = db.session.get(Folder, folder_uuid)
            if not folder:
                return jsonify({"error": "Folder not found"}), 404
            if folder.owner_id != current_user.id:
                return jsonify({"error": "Forbidden: Folder belongs to another user"}), 403
        except ValueError:
            return jsonify({"error": "Invalid folder_id format"}), 400

    # Optional auto-deletion setting
    auto_delete_at = None
    if data.get("auto_delete_days"):
        try:
            days = float(data.get("auto_delete_days"))
            if days <= 0:
                return jsonify({"error": "auto_delete_days must be greater than 0"}), 400
            auto_delete_at = datetime.now(timezone.utc) + timedelta(days=days)
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid auto_delete_days format"}), 400
    elif data.get("auto_delete_at"):
        raw_auto_delete = str(data.get("auto_delete_at")).strip()
        if raw_auto_delete and raw_auto_delete.lower() not in ("null", "none", ""):
            try:
                auto_delete_at = datetime.fromisoformat(raw_auto_delete.replace("Z", "+00:00"))
                if auto_delete_at.tzinfo is None:
                    auto_delete_at = auto_delete_at.replace(tzinfo=timezone.utc)
            except Exception:
                return jsonify({"error": "Invalid auto_delete_at format, expected ISO-8601"}), 400

    tags_val = data.get("tags")
    tags_str = None
    if tags_val:
        if isinstance(tags_val, list):
            tags_str = ",".join(str(t).strip() for t in tags_val if str(t).strip())
        else:
            tags_str = str(tags_val).strip()

    upload_id = uuid.uuid4()
    _get_upload_staging_dir(upload_id)

    session = UploadSession(
        id=upload_id,
        owner_id=current_user.id,
        filename=filename,
        mime_type=mime_type,
        total_size_bytes=total_size_bytes,
        expected_chunks=expected_chunks,
        received_chunks=0,
        status="in_progress",
        folder_id=folder_uuid,
        auto_delete_at=auto_delete_at,
        tags=tags_str,
    )
    db.session.add(session)
    db.session.commit()

    return jsonify({
        "upload_id": str(upload_id),
        "session": session.to_dict(),
    }), 201


@bp.route("/uploads/<uuid:upload_id>/chunks/<int:chunk_index>", methods=["PUT"])
@jwt_required
def upload_chunk(current_user, upload_id: uuid.UUID, chunk_index: int):
    """
    Accept a chunk of raw bytes and append/write it to a temp file on disk
    outside UPLOAD_FOLDER in the staging directory.
    """
    session = db.session.get(UploadSession, upload_id)
    if not session:
        return jsonify({"error": "Upload session not found"}), 404

    if session.owner_id != current_user.id:
        return jsonify({"error": "Forbidden: You do not own this upload session"}), 403

    if session.status == "completed":
        return jsonify({"error": "Upload session already completed"}), 400

    if chunk_index < 0 or chunk_index >= session.expected_chunks:
        return jsonify({
            "error": "Invalid chunk index",
            "message": f"chunk_index must be between 0 and {session.expected_chunks - 1}",
        }), 400

    # Extract chunk bytes: request.get_data() or request.files
    if "chunk" in request.files:
        chunk_data = request.files["chunk"].read()
    elif "file" in request.files:
        chunk_data = request.files["file"].read()
    else:
        chunk_data = request.get_data()

    if not chunk_data:
        return jsonify({"error": "Empty chunk"}), 400

    staging_dir = _get_upload_staging_dir(upload_id)
    chunk_path = _get_chunk_file_path(staging_dir, chunk_index)

    with open(chunk_path, "wb") as f:
        f.write(chunk_data)

    # Count distinct received chunks in staging directory
    received = sum(
        1 for i in range(session.expected_chunks)
        if os.path.exists(_get_chunk_file_path(staging_dir, i))
    )
    session.received_chunks = received
    db.session.commit()

    return jsonify({
        "message": f"Chunk {chunk_index} uploaded",
        "upload_id": str(upload_id),
        "chunk_index": chunk_index,
        "chunk_size_bytes": len(chunk_data),
        "received_chunks": session.received_chunks,
        "expected_chunks": session.expected_chunks,
    }), 200


@bp.route("/uploads/<uuid:upload_id>/complete", methods=["POST"])
@jwt_required
def complete_upload_session(current_user, upload_id: uuid.UUID):
    """
    Verify all expected chunks are present, reassemble them, then reuse the
    existing encrypt_file() path to finish exactly like single-shot upload.
    """
    session = db.session.get(UploadSession, upload_id)
    if not session:
        return jsonify({"error": "Upload session not found"}), 404

    if session.owner_id != current_user.id:
        return jsonify({"error": "Forbidden: You do not own this upload session"}), 403

    if session.status == "completed":
        return jsonify({"error": "Upload session already completed"}), 400

    staging_dir = _get_upload_staging_dir(upload_id)

    # Verify all expected chunks are present
    missing_chunks = [
        i for i in range(session.expected_chunks)
        if not os.path.exists(_get_chunk_file_path(staging_dir, i))
    ]
    if missing_chunks:
        return jsonify({
            "error": "Missing chunks",
            "message": f"Cannot complete upload: missing chunks {missing_chunks}",
            "missing_chunks": missing_chunks,
            "received_chunks": session.received_chunks,
            "expected_chunks": session.expected_chunks,
        }), 400

    # Reassemble all chunks in sequential order
    chunk_buffers = []
    for i in range(session.expected_chunks):
        with open(_get_chunk_file_path(staging_dir, i), "rb") as f:
            chunk_buffers.append(f.read())
    plaintext = b"".join(chunk_buffers)

    if not plaintext:
        shutil.rmtree(staging_dir, ignore_errors=True)
        return jsonify({"error": "Empty file"}), 400

    # Optional overrides from complete body
    req_data = request.get_json(silent=True) or {}
    filename = req_data.get("filename") or session.filename
    mime_type = req_data.get("mime_type") or session.mime_type
    folder_uuid = session.folder_id
    if req_data.get("folder_id"):
        try:
            folder_uuid = uuid.UUID(str(req_data.get("folder_id")).strip())
        except ValueError:
            return jsonify({"error": "Invalid folder_id format"}), 400

    auto_delete_at = session.auto_delete_at
    if req_data.get("auto_delete_days"):
        try:
            days = float(req_data.get("auto_delete_days"))
            auto_delete_at = datetime.now(timezone.utc) + timedelta(days=days)
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid auto_delete_days format"}), 400

    tags_val = req_data.get("tags") if "tags" in req_data else session.tags

    # Finalize upload: malware scanning, quota check, encrypt, persist
    file_record, err = _finalize_file_upload(
        current_user=current_user,
        plaintext=plaintext,
        raw_filename=filename,
        mime_type=mime_type,
        folder_uuid=folder_uuid,
        auto_delete_at=auto_delete_at,
        raw_tags=tags_val,
    )

    if err:
        shutil.rmtree(staging_dir, ignore_errors=True)
        return err[0], err[1]

    # Success: mark completed and clean up staging directory
    session.status = "completed"
    db.session.commit()
    shutil.rmtree(staging_dir, ignore_errors=True)

    return jsonify({"file": file_record.to_dict()}), 201


@bp.route("/uploads/<uuid:upload_id>", methods=["GET"])
@jwt_required
def get_upload_session(current_user, upload_id: uuid.UUID):
    """
    Get the status of an upload session, including received and missing chunk indices.
    """
    session = db.session.get(UploadSession, upload_id)
    if not session:
        return jsonify({"error": "Upload session not found"}), 404
    if session.owner_id != current_user.id:
        return jsonify({"error": "Forbidden: You do not own this upload session"}), 403

    staging_dir = _get_upload_staging_dir(upload_id)
    received_list = [
        i for i in range(session.expected_chunks)
        if os.path.exists(_get_chunk_file_path(staging_dir, i))
    ]
    missing_list = [
        i for i in range(session.expected_chunks)
        if not os.path.exists(_get_chunk_file_path(staging_dir, i))
    ]
    data = session.to_dict()
    data["received_chunk_indices"] = received_list
    data["missing_chunk_indices"] = missing_list
    return jsonify({"session": data}), 200


@bp.route("/uploads/cleanup", methods=["POST"])
@jwt_required
def cleanup_uploads_route(current_user):
    """
    Administrative endpoint to purge orphaned upload sessions.
    """
    if current_user.role != "admin":
        return jsonify({"error": "Forbidden: Admin only"}), 403
    max_age_hours = request.args.get("max_age_hours", default=24, type=int)
    count = cleanup_orphaned_upload_sessions(max_age_hours=max_age_hours)
    return jsonify({"cleaned_sessions": count, "max_age_hours": max_age_hours}), 200


@bp.route("", methods=["GET"])
@jwt_required
def list_files(current_user):
    """
    List files owned by the current user with pagination, sorting, and filename search.

    Query params:
    - page (int): page number (default 1)
    - per_page (int): items per page (default 20, max 100)
    - search (str): filter by filename substring (case-insensitive)
    - sort (str): sort field - 'name' | 'size' | 'date' (default: date desc)
    - order (str): sort direction - 'asc' | 'desc' (optional)
    """
    page, per_page = _get_pagination_params()

    query = File.query.filter_by(owner_id=current_user.id)

    # Exclude soft-deleted files by default
    include_deleted = request.args.get("include_deleted", "").lower() in ("true", "1", "yes")
    if not include_deleted:
        query = query.filter(File.deleted_at.is_(None))

    # Search by filename substring (case-insensitive)
    search = (request.args.get("search") or request.args.get("q") or "").strip()
    if search:
        query = query.filter(File.filename.ilike(f"%{search}%"))

    # Filter by folder_id
    folder_id_param = request.args.get("folder_id")
    if folder_id_param is not None:
        folder_id_param = folder_id_param.strip()
        if folder_id_param.lower() in ("null", "none", "root"):
            query = query.filter(File.folder_id.is_(None))
        elif folder_id_param:
            try:
                fid = uuid.UUID(folder_id_param)
                query = query.filter(File.folder_id == fid)
            except ValueError:
                return jsonify({"error": "Invalid folder_id format"}), 400

    # Filter by tag
    tag_param = (request.args.get("tag") or "").strip()
    if tag_param:
        query = query.join(File.tags).filter(Tag.name.ilike(tag_param))

    # Sorting: name | size | date (default: date desc)
    sort = (request.args.get("sort") or "date").strip().lower()
    order = (request.args.get("order") or "").strip().lower()

    if sort == "name":
        col = File.filename.desc() if order == "desc" else File.filename.asc()
    elif sort == "size":
        col = File.size_bytes.asc() if order == "asc" else desc(File.size_bytes)
    else:  # "date" or fallback
        col = File.created_at.asc() if order == "asc" else desc(File.created_at)

    query = query.order_by(col, desc(File.id))

    # Paginate query
    result = _paginate_query(query, page, per_page)
    file_items = [file.to_dict() for file in result["items"]]

    storage_used = db.session.query(func.sum(File.size_bytes)).filter(
        File.owner_id == current_user.id
    ).scalar() or 0

    response_payload = {
        "files": file_items,
        "items": file_items,
        "total": result["total"],
        "page": result["page"],
        "per_page": result["per_page"],
        "pages": result["pages"],
        "storage_used_bytes": storage_used,
        "storage_quota_bytes": current_user.storage_quota_bytes,
    }
    resp = jsonify(response_payload)
    resp.headers["X-Storage-Used-Bytes"] = str(storage_used)
    resp.headers["X-Storage-Quota-Bytes"] = (
        str(current_user.storage_quota_bytes)
        if current_user.storage_quota_bytes is not None
        else "unlimited"
    )
    return resp, 200


@bp.route("/search", methods=["GET"])
@jwt_required
def search_files(current_user):
    """
    Search files owned by the current user by filename and tags.

    Query params:
    - q (str): Search query matching filename or attached tag names (case-insensitive substring)
    - page (int): page number (default 1)
    - per_page (int): items per page (default 20, max 100)
    - sort (str): sort field - 'name' | 'size' | 'date' (default: date desc)
    - order (str): sort direction - 'asc' | 'desc' (optional)
    """
    page, per_page = _get_pagination_params()
    q = (request.args.get("q") or "").strip()

    if not q:
        return jsonify({
            "files": [],
            "items": [],
            "total": 0,
            "page": page,
            "per_page": per_page,
            "pages": 0,
            "query": "",
        }), 200

    pattern = f"%{q}%"

    # NOTE / FOLLOW-UP:
    # Initial version searches filename and tags only.
    # Content extraction and OCR (e.g. Tesseract OCR for scanned images/PDFs,
    # pdfminer/pypdf for text-based PDFs, python-docx for DOCX files) should be
    # added in a future pass to populate an extracted_text column or full-text
    # index (e.g. SQLite FTS5 / PostgreSQL tsvector) to enable deep content search.
    include_deleted = request.args.get("include_deleted", "").lower() in ("true", "1", "yes")
    filters = [
        File.owner_id == current_user.id,
        or_(
            File.filename.ilike(pattern),
            File.tags.any(Tag.name.ilike(pattern)),
        ),
    ]
    if not include_deleted:
        filters.append(File.deleted_at.is_(None))

    query = File.query.filter(*filters)

    # Sorting: name | size | date (default: date desc)
    sort = (request.args.get("sort") or "date").strip().lower()
    order = (request.args.get("order") or "").strip().lower()

    if sort == "name":
        col = File.filename.desc() if order == "desc" else File.filename.asc()
    elif sort == "size":
        col = File.size_bytes.asc() if order == "asc" else desc(File.size_bytes)
    else:  # "date" or fallback
        col = File.created_at.asc() if order == "asc" else desc(File.created_at)

    query = query.order_by(col, desc(File.id))

    result = _paginate_query(query, page, per_page)
    file_items = [file.to_dict() for file in result["items"]]

    return jsonify({
        "files": file_items,
        "items": file_items,
        "total": result["total"],
        "page": result["page"],
        "per_page": result["per_page"],
        "pages": result["pages"],
        "query": q,
    }), 200


@bp.route("/trash", methods=["GET"])
@jwt_required
def list_trash_files(current_user):
    """
    List soft-deleted files in the authenticated user's trash.
    Supports pagination and sorting (default: deleted_at desc).
    """
    page, per_page = _get_pagination_params()

    query = File.query.filter(
        File.owner_id == current_user.id,
        File.deleted_at.isnot(None),
    ).order_by(desc(File.deleted_at), desc(File.id))

    result = _paginate_query(query, page, per_page)
    file_items = [f.to_dict() for f in result["items"]]

    return jsonify({
        "files": file_items,
        "items": file_items,
        "total": result["total"],
        "page": result["page"],
        "per_page": result["per_page"],
        "pages": result["pages"],
    }), 200


def _perform_file_deletion(file: File) -> None:
    """
    Internal helper to revoke all active shares for a file, remove its encrypted
    blobs from disk (base file + all historical versions), and delete the File row.
    Caller is responsible for db.session.commit().
    """
    # Revoke all active shares before deletion
    active_shares = Share.query.filter_by(file_id=file.id, is_revoked=False).all()
    for s in active_shares:
        s.is_revoked = True
    db.session.flush()

    # Remove the encrypted blob(s) from disk
    blobs_to_remove = set()
    if file.encrypted_path:
        blobs_to_remove.add(file.encrypted_path)
    for v in file.versions:
        if v.encrypted_path:
            blobs_to_remove.add(v.encrypted_path)

    for path in blobs_to_remove:
        if os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass

    # Delete File row (cascades to file_versions, shares, and access logs)
    db.session.delete(file)


@bp.route("/bulk/delete", methods=["POST"])
@jwt_required
def bulk_delete_files(current_user):
    """
    Bulk delete files owned by the current user.
    Body (JSON): {"file_ids": ["<uuid>", ...]}
    Silently skips IDs that don't belong to the user (returns "File not found")
    to prevent leaking existence of other users' files.
    Returns: {"succeeded": [...], "failed": [...]}
    """
    data = request.get_json(silent=True) or {}
    file_ids = data.get("file_ids")
    if file_ids is None or not isinstance(file_ids, list):
        return jsonify({"error": "file_ids must be a list"}), 400

    succeeded = []
    failed = []

    for raw_id in file_ids:
        str_id = str(raw_id).strip()
        try:
            fid = uuid.UUID(str_id)
        except (ValueError, TypeError):
            failed.append({"id": str_id, "error": "Invalid file ID format"})
            continue

        file = db.session.get(File, fid)
        # Silently skip files that don't belong to current user (no ownership leakage)
        if file is None or file.owner_id != current_user.id:
            failed.append({"id": str_id, "error": "File not found"})
            continue

        try:
            _perform_file_deletion(file)
            succeeded.append(str_id)
        except Exception as exc:
            failed.append({"id": str_id, "error": str(exc)})

    db.session.commit()

    return jsonify({
        "succeeded": succeeded,
        "failed": failed,
        "total": len(file_ids),
        "success_count": len(succeeded),
        "failure_count": len(failed),
    }), 200


@bp.route("/bulk/move", methods=["POST"])
@jwt_required
def bulk_move_files(current_user):
    """
    Bulk move files owned by the current user into a folder (or root).
    Body (JSON): {"file_ids": ["<uuid>", ...], "folder_id": "<folder_uuid>" | null}
    Silently skips IDs that don't belong to the user.
    Returns: {"succeeded": [...], "failed": [...]}
    """
    data = request.get_json(silent=True) or {}
    file_ids = data.get("file_ids")
    if file_ids is None or not isinstance(file_ids, list):
        return jsonify({"error": "file_ids must be a list"}), 400

    if "folder_id" not in data:
        return jsonify({"error": "folder_id is required"}), 400

    raw_folder_id = data.get("folder_id")
    target_folder = None
    if raw_folder_id is not None and str(raw_folder_id).strip().lower() not in ("null", "none", "root", ""):
        try:
            folder_uuid = uuid.UUID(str(raw_folder_id).strip())
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid folder_id format"}), 400

        target_folder = db.session.get(Folder, folder_uuid)
        if target_folder is None:
            return jsonify({"error": "Folder not found"}), 404
        if target_folder.owner_id != current_user.id:
            return jsonify({"error": "Forbidden: Folder belongs to another user"}), 403

    target_folder_id = target_folder.id if target_folder else None

    succeeded = []
    failed = []

    for raw_id in file_ids:
        str_id = str(raw_id).strip()
        try:
            fid = uuid.UUID(str_id)
        except (ValueError, TypeError):
            failed.append({"id": str_id, "error": "Invalid file ID format"})
            continue

        file = db.session.get(File, fid)
        if file is None or file.owner_id != current_user.id:
            failed.append({"id": str_id, "error": "File not found"})
            continue

        file.folder_id = target_folder_id
        succeeded.append(str_id)

    db.session.commit()

    return jsonify({
        "succeeded": succeeded,
        "failed": failed,
        "total": len(file_ids),
        "success_count": len(succeeded),
        "failure_count": len(failed),
        "folder_id": str(target_folder_id) if target_folder_id else None,
    }), 200


@bp.route("/bulk/tag", methods=["POST"])
@jwt_required
def bulk_tag_files(current_user):
    """
    Bulk tag files owned by the current user.
    Body (JSON):
      - file_ids: list[str] (required)
      - tags: list[str] | string (required)
      - action: "add" (default) | "replace" | "remove" (optional)
    Silently skips IDs that don't belong to the user.
    Returns: {"succeeded": [...], "failed": [...]}
    """
    data = request.get_json(silent=True) or {}
    file_ids = data.get("file_ids")
    if file_ids is None or not isinstance(file_ids, list):
        return jsonify({"error": "file_ids must be a list"}), 400

    tag_items = data.get("tags")
    if tag_items is None:
        return jsonify({"error": "tags is required"}), 400

    if isinstance(tag_items, str):
        tag_names = [t.strip() for t in tag_items.split(",") if t.strip()]
    elif isinstance(tag_items, (list, tuple)):
        tag_names = [str(t).strip() for t in tag_items if str(t).strip()]
    else:
        return jsonify({"error": "tags must be a list or string"}), 400

    action = (data.get("action") or "add").strip().lower()
    if action not in ("add", "replace", "remove"):
        return jsonify({"error": "action must be 'add', 'replace', or 'remove'"}), 400

    # Pre-resolve Tag records for this user
    resolved_tags = []
    for tname in tag_names:
        t_rec = Tag.query.filter_by(owner_id=current_user.id, name=tname).first()
        if not t_rec and action != "remove":
            t_rec = Tag(owner_id=current_user.id, name=tname)
            db.session.add(t_rec)
        if t_rec:
            resolved_tags.append(t_rec)

    succeeded = []
    failed = []

    for raw_id in file_ids:
        str_id = str(raw_id).strip()
        try:
            fid = uuid.UUID(str_id)
        except (ValueError, TypeError):
            failed.append({"id": str_id, "error": "Invalid file ID format"})
            continue

        file = db.session.get(File, fid)
        if file is None or file.owner_id != current_user.id:
            failed.append({"id": str_id, "error": "File not found"})
            continue

        if action == "replace":
            file.tags = list(resolved_tags)
        elif action == "remove":
            file.tags = [t for t in file.tags if t.name not in set(tag_names)]
        else:  # "add"
            current_names = {t.name for t in file.tags}
            for tag in resolved_tags:
                if tag.name not in current_names:
                    file.tags.append(tag)

        succeeded.append(str_id)

    db.session.commit()

    return jsonify({
        "succeeded": succeeded,
        "failed": failed,
        "total": len(file_ids),
        "success_count": len(succeeded),
        "failure_count": len(failed),
    }), 200


@bp.route("/<uuid:file_id>", methods=["DELETE"])
@jwt_required
def delete_file(current_user, file_id: uuid.UUID):
    """
    Delete a file (owner only).
    Soft-deletes the file by setting deleted_at and revoking active shares (retains disk blobs and DB row).
    If permanent=true query parameter is supplied, permanently purges the file and its disk blobs.
    """
    file = db.session.get(File, file_id)
    if file is None:
        return jsonify({"error": "File not found"}), 404

    if file.owner_id != current_user.id:
        return jsonify({"error": "Forbidden"}), 403

    permanent = request.args.get("permanent", "").lower() in ("true", "1", "yes")
    if permanent:
        _perform_file_deletion(file)
        db.session.commit()
        return jsonify({"message": "File deleted permanently"}), 200

    # Soft-delete: set deleted_at and revoke active shares
    file.deleted_at = datetime.now(timezone.utc)
    active_shares = Share.query.filter_by(file_id=file.id, is_revoked=False).all()
    for s in active_shares:
        s.is_revoked = True
    db.session.commit()

    return jsonify({
        "message": "File deleted successfully",
        "file": file.to_dict(),
        "deleted_at": file.deleted_at.isoformat(),
    }), 200


@bp.route("/<uuid:file_id>/restore", methods=["POST"])
@jwt_required
def restore_file(current_user, file_id: uuid.UUID):
    """
    Restore a soft-deleted file from trash (owner only).
    Clears deleted_at and restores file visibility.
    Does NOT auto-restore previously revoked shares.
    """
    file = db.session.get(File, file_id)
    if file is None:
        return jsonify({"error": "File not found"}), 404

    if file.owner_id != current_user.id:
        return jsonify({"error": "Forbidden"}), 403

    if file.deleted_at is None:
        return jsonify({"error": "File is not in trash"}), 400

    file.deleted_at = None
    db.session.commit()

    return jsonify({
        "message": "File restored successfully",
        "file": file.to_dict(),
    }), 200


@bp.route("/<uuid:file_id>/analytics", methods=["GET"])
@jwt_required
def get_file_analytics(current_user, file_id: uuid.UUID):
    """
    Aggregate access analytics across all shares of a file (owner only).
    Returns total views, total downloads, unique accessors, and 30-day daily time-series.
    """
    file = db.session.get(File, file_id)
    if file is None:
        return jsonify({"error": "File not found"}), 404

    if file.owner_id != current_user.id:
        return jsonify({"error": "Forbidden"}), 403

    # Find all shares associated with this file
    share_ids = [s[0] for s in db.session.query(Share.id).filter(Share.file_id == file.id).all()]

    total_views = 0
    total_downloads = 0
    unique_accessors = 0
    now_utc = datetime.now(timezone.utc)
    today = now_utc.date()
    start_date = today - timedelta(days=29)

    # Pre-build daily time-series dictionary for the last 30 days
    daily_map = {}
    for i in range(30):
        d_str = (start_date + timedelta(days=i)).isoformat()
        daily_map[d_str] = {
            "date": d_str,
            "count": 0,
            "views": 0,
            "downloads": 0,
        }

    if share_ids:
        logs = AccessLog.query.filter(AccessLog.share_id.in_(share_ids)).all()

        accessors = set()
        for log in logs:
            if not log.success:
                continue

            if log.action == "view":
                total_views += 1
            elif log.action == "download":
                total_downloads += 1

            # Distinct accessed_by / IP for anonymous shares
            if log.accessed_by is not None:
                accessors.add(f"user:{log.accessed_by}")
            elif log.ip_address:
                accessors.add(f"ip:{log.ip_address}")
            else:
                accessors.add(f"log:{log.id}")

            # Time series bucket
            ts = log.timestamp
            if ts is not None:
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                else:
                    ts = ts.astimezone(timezone.utc)
                log_date_str = ts.date().isoformat()
                if log_date_str in daily_map:
                    daily_map[log_date_str]["count"] += 1
                    if log.action == "view":
                        daily_map[log_date_str]["views"] += 1
                    elif log.action == "download":
                        daily_map[log_date_str]["downloads"] += 1

        unique_accessors = len(accessors)

    time_series = [daily_map[d_str] for d_str in sorted(daily_map.keys())]

    analytics_data = {
        "total_views": total_views,
        "total_downloads": total_downloads,
        "views": total_views,
        "downloads": total_downloads,
        "total_accesses": total_views + total_downloads,
        "unique_accessors": unique_accessors,
        "time_series": time_series,
    }

    return jsonify({
        "file_id": str(file.id),
        "filename": file.filename,
        "total_shares": len(share_ids),
        "total_views": total_views,
        "total_downloads": total_downloads,
        "views": total_views,
        "downloads": total_downloads,
        "total_accesses": total_views + total_downloads,
        "unique_accessors": unique_accessors,
        "time_series": time_series,
        "analytics": analytics_data,
    }), 200


@bp.route("/<uuid:file_id>", methods=["PATCH"])
@jwt_required
def rename_file(current_user, file_id: uuid.UUID):
    """
    Update a file (owner only).
    Supports renaming (filename), moving to a folder (folder_id), and setting tags.
    Does not allow changing mime_type or size_bytes.
    """
    file = db.session.get(File, file_id)
    if file is None:
        return jsonify({"error": "File not found"}), 404

    if file.owner_id != current_user.id:
        return jsonify({"error": "Forbidden"}), 403

    if file.deleted_at is not None:
        return jsonify({"error": "Cannot modify file in trash"}), 400

    data = request.get_json(silent=True) or {}
    if "mime_type" in data or "size_bytes" in data:
        return jsonify({"error": "mime_type and size_bytes cannot be modified"}), 400

    if (
        "filename" not in data
        and "folder_id" not in data
        and "tags" not in data
        and "auto_delete_at" not in data
        and "auto_delete_days" not in data
    ):
        return jsonify({"error": "Filename is required"}), 400


    if "filename" in data:
        raw_filename = str(data.get("filename") or "").strip()
        if not raw_filename:
            return jsonify({"error": "Filename cannot be empty"}), 400

        sanitized_filename = secure_filename(raw_filename)
        if not sanitized_filename:
            return jsonify({"error": "Invalid filename"}), 400

        file.filename = sanitized_filename

    if "folder_id" in data:
        fid_val = data["folder_id"]
        if fid_val is None or str(fid_val).strip().lower() in ("null", "none", "root", ""):
            file.folder_id = None
        else:
            try:
                folder_uuid = uuid.UUID(str(fid_val).strip())
                target_folder = db.session.get(Folder, folder_uuid)
                if target_folder is None:
                    return jsonify({"error": "Folder not found"}), 404
                if target_folder.owner_id != current_user.id:
                    return jsonify({"error": "Forbidden: Folder belongs to another user"}), 403
                file.folder_id = target_folder.id
            except ValueError:
                return jsonify({"error": "Invalid folder_id format"}), 400

    if "tags" in data:
        tag_items = data["tags"]
        if isinstance(tag_items, str):
            tag_names = [t.strip() for t in tag_items.split(",") if t.strip()]
        elif isinstance(tag_items, (list, tuple)):
            tag_names = [str(t).strip() for t in tag_items if str(t).strip()]
        else:
            return jsonify({"error": "tags must be a list or string"}), 400

        resolved_tags = []
        for tname in tag_names:
            t_rec = Tag.query.filter_by(owner_id=current_user.id, name=tname).first()
            if not t_rec:
                t_rec = Tag(owner_id=current_user.id, name=tname)
                db.session.add(t_rec)
            resolved_tags.append(t_rec)
        file.tags = resolved_tags

    if "auto_delete_days" in data:
        raw_days = data["auto_delete_days"]
        if raw_days is None or str(raw_days).strip().lower() in ("null", "none", ""):
            file.auto_delete_at = None
        else:
            try:
                days = float(str(raw_days).strip())
                if days <= 0:
                    return jsonify({"error": "auto_delete_days must be greater than 0"}), 400
                file.auto_delete_at = datetime.now(timezone.utc) + timedelta(days=days)
            except (ValueError, TypeError):
                return jsonify({"error": "Invalid auto_delete_days format"}), 400

    elif "auto_delete_at" in data:
        raw_exp = data["auto_delete_at"]
        if raw_exp is None or str(raw_exp).strip().lower() in ("null", "none", ""):
            file.auto_delete_at = None
        else:
            try:
                exp_dt = datetime.fromisoformat(str(raw_exp).strip().replace("Z", "+00:00"))
                if exp_dt.tzinfo is None:
                    exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                file.auto_delete_at = exp_dt
            except Exception:
                return jsonify({"error": "Invalid auto_delete_at format, expected ISO-8601"}), 400

    db.session.commit()

    return jsonify({"file": file.to_dict()}), 200


@bp.route("/<uuid:file_id>/tags", methods=["POST"])
@jwt_required
def add_file_tags(current_user, file_id: uuid.UUID):
    """
    Attach one or more tags to a file (owner only).
    Body: {"name": "..."} or {"tags": ["...", "..."]}
    """
    file = db.session.get(File, file_id)
    if file is None:
        return jsonify({"error": "File not found"}), 404
    if file.owner_id != current_user.id:
        return jsonify({"error": "Forbidden"}), 403

    data = request.get_json(silent=True) or {}
    raw_name = data.get("name")
    raw_tags = data.get("tags")

    tag_names = []
    if raw_name:
        tag_names.append(str(raw_name).strip())
    if raw_tags:
        if isinstance(raw_tags, str):
            tag_names.extend([t.strip() for t in raw_tags.split(",") if t.strip()])
        elif isinstance(raw_tags, (list, tuple)):
            tag_names.extend([str(t).strip() for t in raw_tags if str(t).strip()])

    if not tag_names:
        return jsonify({"error": "Tag name is required"}), 400

    for tname in tag_names:
        tag = Tag.query.filter_by(owner_id=current_user.id, name=tname).first()
        if not tag:
            tag = Tag(owner_id=current_user.id, name=tname)
            db.session.add(tag)
        if tag not in file.tags:
            file.tags.append(tag)

    db.session.commit()
    return jsonify({"file": file.to_dict()}), 200


@bp.route("/<uuid:file_id>/tags/<string:tag_id_or_name>", methods=["DELETE"])
@jwt_required
def remove_file_tag(current_user, file_id: uuid.UUID, tag_id_or_name: str):
    """
    Remove a tag association from a file (owner only).
    """
    file = db.session.get(File, file_id)
    if file is None:
        return jsonify({"error": "File not found"}), 404
    if file.owner_id != current_user.id:
        return jsonify({"error": "Forbidden"}), 403

    tag = None
    try:
        t_uuid = uuid.UUID(tag_id_or_name)
        tag = db.session.get(Tag, t_uuid)
    except ValueError:
        pass

    if not tag:
        tag = Tag.query.filter_by(owner_id=current_user.id, name=tag_id_or_name).first()

    if not tag or tag not in file.tags:
        return jsonify({"error": "Tag not associated with this file"}), 404

    file.tags.remove(tag)
    db.session.commit()
    return jsonify({"file": file.to_dict()}), 200


@bp.route("/<uuid:file_id>/download", methods=["GET"])
@jwt_required
def download_file(current_user, file_id: uuid.UUID):
    """
    Download the current version of a file directly (owner only).
    """
    file = db.session.get(File, file_id)
    if file is None:
        return jsonify({"error": "File not found"}), 404

    if file.owner_id != current_user.id:
        return jsonify({"error": "Forbidden"}), 403

    if file.deleted_at is not None:
        return jsonify({"error": "File is in trash"}), 410

    try:
        plaintext = decrypt_file(
            file.encrypted_path,
            file.nonce_hex,
            file.wrapped_key_hex,
        )
    except Exception as exc:
        return jsonify({"error": "File decryption failed"}), 500

    safe_ascii = secure_filename(file.filename) or "download"
    raw_name = file.filename or "download"
    encoded_filename = urllib.parse.quote(raw_name, safe="!#$&+-.^_`|~")
    content_disposition = f'attachment; filename="{safe_ascii}"; filename*=UTF-8\'\'{encoded_filename}'

    return Response(
        plaintext,
        status=200,
        mimetype=file.mime_type,
        headers={
            "Content-Disposition": content_disposition,
            "Content-Length": str(len(plaintext)),
        },
    )


@bp.route("/<uuid:file_id>/thumbnail", methods=["GET"])
@jwt_optional
def get_file_thumbnail(current_user, file_id: uuid.UUID):
    """
    On-demand thumbnail generation for image files (owner or valid-share-token access).
    Decrypts the file in-memory and returns a resized JPEG thumbnail (max 400x400).
    For non-image mime types, returns 415.
    """
    share_token = (
        request.args.get("share_token")
        or request.args.get("token")
        or request.headers.get("X-Share-Token")
    )
    if share_token:
        share_token = share_token.strip()

    # Reject if unauthenticated and no share token provided
    if current_user is None and not share_token:
        return jsonify({"error": "Authentication or share token required"}), 401

    file = db.session.get(File, file_id)
    if file is None:
        return jsonify({"error": "File not found"}), 404

    if file.deleted_at is not None:
        return jsonify({"error": "File is in trash"}), 410

    target_encrypted_path = file.encrypted_path
    target_nonce_hex = file.nonce_hex
    target_wrapped_key_hex = file.wrapped_key_hex
    is_authorized = False

    # 1. File owner access
    if current_user and current_user.id == file.owner_id:
        is_authorized = True

    # 2. Share token access (by share token or custom slug)
    elif share_token:
        share = _find_share_by_token_or_slug(share_token)
        if share is None or share.file_id != file.id:
            return jsonify({"error": "Share not found"}), 404

        if not share.is_valid():
            if share.is_revoked:
                reason = "revoked"
            elif share.owner and not share.owner.is_active:
                reason = "disabled"
            else:
                reason = "expired"
            return jsonify({"error": f"Share is {reason}"}), 410

        if not share.can_view:
            return jsonify({"error": "View not permitted for this share"}), 403

        if share.recipient_id and (current_user is None or current_user.id != share.recipient_id):
            return jsonify({"error": "Access denied"}), 403

        if share.password_hash:
            grant = request.headers.get("X-Share-Grant")
            if not grant or not _verify_grant_token(grant, share.id):
                return jsonify({"error": "Password required", "password_protected": True}), 401

        # Use pinned version blob if configured on the share
        if share.pinned_version is not None:
            target_version = FileVersion.query.filter_by(
                file_id=file.id, version_number=share.pinned_version
            ).first()
            if target_version:
                target_encrypted_path = target_version.encrypted_path
                target_nonce_hex = target_version.nonce_hex
                target_wrapped_key_hex = target_version.wrapped_key_hex

        is_authorized = True

    # 3. Direct recipient access if caller is authenticated and has an active share
    elif current_user:
        active_share = Share.query.filter_by(
            file_id=file.id,
            recipient_id=current_user.id,
            is_revoked=False,
        ).first()
        if active_share and active_share.is_valid() and active_share.can_view:
            if not active_share.password_hash or _verify_grant_token(
                request.headers.get("X-Share-Grant"), active_share.id
            ):
                is_authorized = True
                if active_share.pinned_version is not None:
                    target_version = FileVersion.query.filter_by(
                        file_id=file.id, version_number=active_share.pinned_version
                    ).first()
                    if target_version:
                        target_encrypted_path = target_version.encrypted_path
                        target_nonce_hex = target_version.nonce_hex
                        target_wrapped_key_hex = target_version.wrapped_key_hex

    if not is_authorized:
        return jsonify({"error": "Forbidden"}), 403

    # Check mime type before decrypting
    if not is_supported_image(file.mime_type, file.filename):
        return jsonify({
            "error": "Unsupported media type",
            "message": (
                f"Thumbnail generation only supported for image types "
                f"(image/png, image/jpeg, image/webp). Got '{file.mime_type}'."
            ),
        }), 415

    # Check in-memory LRU cache
    cache_key = f"{file.id}:{target_nonce_hex}"
    cached_thumb = thumbnail_cache.get(cache_key)
    if cached_thumb is not None:
        return Response(
            cached_thumb,
            status=200,
            mimetype="image/jpeg",
            headers={
                "Content-Type": "image/jpeg",
                "Content-Length": str(len(cached_thumb)),
                "Cache-Control": "private, max-age=300",
                "X-Thumbnail-Cache": "HIT",
            },
        )

    # Read ciphertext from disk and decrypt in-memory
    if not target_encrypted_path or not os.path.exists(target_encrypted_path):
        return jsonify({"error": "Encrypted file not found on disk"}), 404

    try:
        with open(target_encrypted_path, "rb") as fh:
            ciphertext = fh.read()
    except OSError:
        return jsonify({"error": "Failed to read encrypted file"}), 500

    try:
        plaintext = decrypt_file_bytes(
            ciphertext=ciphertext,
            nonce_hex=target_nonce_hex,
            wrapped_key_hex=target_wrapped_key_hex,
        )
    except Exception:
        return jsonify({"error": "File decryption failed"}), 500

    try:
        thumb_bytes = generate_thumbnail_bytes(plaintext, max_size=(400, 400))
    except Exception as exc:
        return jsonify({"error": f"Failed to generate thumbnail: {exc}"}), 400

    # Store in memory cache
    thumbnail_cache.set(cache_key, thumb_bytes)

    return Response(
        thumb_bytes,
        status=200,
        mimetype="image/jpeg",
        headers={
            "Content-Type": "image/jpeg",
            "Content-Length": str(len(thumb_bytes)),
            "Cache-Control": "private, max-age=300",
            "X-Thumbnail-Cache": "MISS",
        },
    )


@bp.route("/<uuid:file_id>/versions", methods=["POST"])
@jwt_required
def upload_file_version(current_user, file_id: uuid.UUID):
    """
    Upload a new version of an existing file (owner only).
    The new blob is encrypted with AES-256-GCM and stored with a new FileVersion record.
    The parent File row is updated with the latest metadata.
    """
    file = db.session.get(File, file_id)
    if file is None:
        return jsonify({"error": "File not found"}), 404

    if file.owner_id != current_user.id:
        return jsonify({"error": "Forbidden"}), 403

    if file.deleted_at is not None:
        return jsonify({"error": "Cannot add version to file in trash"}), 400

    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    upload = request.files["file"]
    plaintext = upload.read()
    if not plaintext:
        return jsonify({"error": "Empty file"}), 400

    # Malware scanning before encryption
    is_clean, virus_name = scan_file_for_malware(plaintext)
    if not is_clean:
        return jsonify({
            "error": "Malware detected",
            "message": f"File rejected: infected with {virus_name}",
            "virus": virus_name,
        }), 422

    # Storage quota enforcement before writing new version blob
    if current_user.storage_quota_bytes is not None:
        storage_used = db.session.query(func.sum(File.size_bytes)).filter(
            File.owner_id == current_user.id
        ).scalar() or 0
        projected_used = storage_used - (file.size_bytes or 0) + len(plaintext)
        if projected_used > current_user.storage_quota_bytes:
            return jsonify({
                "error": "Storage quota exceeded",
                "message": (
                    f"Upload of version ({len(plaintext)} bytes) exceeds storage quota "
                    f"({storage_used}/{current_user.storage_quota_bytes} bytes used)"
                ),
                "storage_used_bytes": storage_used,
                "storage_quota_bytes": current_user.storage_quota_bytes,
                "file_size_bytes": len(plaintext),
            }), 413

    # Ensure v1 exists for legacy files created before versions
    if not file.versions:
        v1 = FileVersion(
            file_id=file.id,
            version_number=1,
            filename=file.filename,
            mime_type=file.mime_type,
            size_bytes=file.size_bytes,
            encrypted_path=file.encrypted_path,
            nonce_hex=file.nonce_hex,
            wrapped_key_hex=file.wrapped_key_hex,
            created_at=file.created_at,
        )
        db.session.add(v1)
        db.session.flush()
        new_version_number = 2
    else:
        new_version_number = max(v.version_number for v in file.versions) + 1

    ciphertext, nonce_hex, wrapped_key_hex = encrypt_file(plaintext)

    upload_dir = current_app.config["UPLOAD_FOLDER"]
    os.makedirs(upload_dir, exist_ok=True)

    version_blob_name = f"{file.id}_v{new_version_number}.enc"
    encrypted_path = os.path.join(upload_dir, version_blob_name)

    with open(encrypted_path, "wb") as fh:
        fh.write(ciphertext)

    mime = upload.mimetype or "application/octet-stream"
    raw_filename = upload.filename or file.filename
    sanitized_filename = secure_filename(raw_filename) or file.filename

    new_version = FileVersion(
        file_id=file.id,
        version_number=new_version_number,
        filename=sanitized_filename,
        mime_type=mime,
        size_bytes=len(plaintext),
        encrypted_path=encrypted_path,
        nonce_hex=nonce_hex,
        wrapped_key_hex=wrapped_key_hex,
    )
    db.session.add(new_version)

    # Update base File row to reflect the current latest version
    file.filename = sanitized_filename
    file.mime_type = mime
    file.size_bytes = len(plaintext)
    file.encrypted_path = encrypted_path
    file.nonce_hex = nonce_hex
    file.wrapped_key_hex = wrapped_key_hex
    db.session.commit()

    return jsonify({
        "message": f"Version {new_version_number} uploaded successfully",
        "version": new_version.to_dict(),
        "file": file.to_dict(),
    }), 201


@bp.route("/<uuid:file_id>/versions", methods=["GET"])
@jwt_required
def list_file_versions(current_user, file_id: uuid.UUID):
    """
    List all versions of a file (owner only).
    """
    file = db.session.get(File, file_id)
    if file is None:
        return jsonify({"error": "File not found"}), 404

    if file.owner_id != current_user.id:
        return jsonify({"error": "Forbidden"}), 403

    # Backfill v1 if this file was created before version tracking
    if not file.versions:
        v1 = FileVersion(
            file_id=file.id,
            version_number=1,
            filename=file.filename,
            mime_type=file.mime_type,
            size_bytes=file.size_bytes,
            encrypted_path=file.encrypted_path,
            nonce_hex=file.nonce_hex,
            wrapped_key_hex=file.wrapped_key_hex,
            created_at=file.created_at,
        )
        db.session.add(v1)
        db.session.commit()

    sorted_versions = sorted(file.versions, key=lambda v: v.version_number, reverse=True)
    return jsonify({
        "versions": [v.to_dict() for v in sorted_versions],
        "total": len(sorted_versions),
        "current_version": file.current_version_number,
    }), 200


@bp.route("/<uuid:file_id>/versions/<int:version_number>", methods=["GET"])
@bp.route("/<uuid:file_id>/versions/<int:version_number>/download", methods=["GET"])
@jwt_required
def get_or_download_file_version(current_user, file_id: uuid.UUID, version_number: int):
    """
    Get metadata for a specific file version, or download the decrypted version blob (owner only).
    If the endpoint called is .../download or query param download=true or Accept is application/octet-stream,
    the decrypted blob is streamed. Otherwise, version metadata JSON is returned.
    """
    file = db.session.get(File, file_id)
    if file is None:
        return jsonify({"error": "File not found"}), 404

    if file.owner_id != current_user.id:
        return jsonify({"error": "Forbidden"}), 403

    if not file.versions:
        v1 = FileVersion(
            file_id=file.id,
            version_number=1,
            filename=file.filename,
            mime_type=file.mime_type,
            size_bytes=file.size_bytes,
            encrypted_path=file.encrypted_path,
            nonce_hex=file.nonce_hex,
            wrapped_key_hex=file.wrapped_key_hex,
            created_at=file.created_at,
        )
        db.session.add(v1)
        db.session.commit()

    version = next((v for v in file.versions if v.version_number == version_number), None)
    if version is None:
        return jsonify({"error": f"Version {version_number} not found"}), 404

    # Determine whether to download or return JSON metadata
    is_download_request = (
        request.path.rstrip("/").endswith("/download")
        or request.args.get("download", "").lower() in ("true", "1", "yes")
        or "application/octet-stream" in request.headers.get("Accept", "")
    )

    if not is_download_request:
        return jsonify({"version": version.to_dict()}), 200

    # Decrypt and stream version blob
    try:
        plaintext = decrypt_file(
            version.encrypted_path,
            version.nonce_hex,
            version.wrapped_key_hex,
        )
    except Exception as exc:
        return jsonify({"error": "File decryption failed"}), 500

    safe_ascii = secure_filename(version.filename) or "download"
    raw_name = version.filename or "download"
    encoded_filename = urllib.parse.quote(raw_name, safe="!#$&+-.^_`|~")
    content_disposition = f'attachment; filename="{safe_ascii}"; filename*=UTF-8\'\'{encoded_filename}'

    return Response(
        plaintext,
        status=200,
        mimetype=version.mime_type,
        headers={
            "Content-Disposition": content_disposition,
            "Content-Length": str(len(plaintext)),
        },
    )

