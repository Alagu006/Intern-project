"""
Module 4 — Access Control & Secure File Sharing
Blueprint: /api

Endpoints
---------
POST   /api/files/<file_id>/share          — create share(s)
GET    /api/files/<file_id>/shares         — list shares for a file (owner only)
GET    /api/shares/<token>/access          — validate token, return metadata
POST   /api/shares/<token>/verify-password — verify share password
GET    /api/shares/<token>/download        — stream decrypted file
GET    /api/shares/<share_id>/receipts     — read/download receipts (owner only)
PATCH  /api/shares/<share_id>              — update permissions / expiry / revoke
DELETE /api/shares/<share_id>              — revoke share
GET    /api/shares/<token>/qrcode          — return QR code PNG
"""

import io
import re
import uuid
import urllib.parse
import jwt as pyjwt
import datetime
import qrcode
from werkzeug.utils import secure_filename
from sqlalchemy import or_

from flask import (
    Blueprint,
    request,
    jsonify,
    current_app,
    Response,
    stream_with_context,
)
from app.extensions import db, limiter
from app.models import User, File, FileVersion, Share, AccessLog, Notification
from app.auth.decorators import jwt_required, jwt_optional
from app.crypto.file_crypto import decrypt_file
from app.webhooks import dispatch_webhook_event

bp = Blueprint("shares", __name__, url_prefix="/api")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

SLUG_REGEX = re.compile(r"^[a-zA-Z0-9-]{3,64}$")


def _validate_custom_slug(slug: any) -> tuple[str | None, str | None]:
    """
    Validate custom slug format (3-64 chars, alphanumeric + hyphens only).
    Returns (cleaned_slug, error_message). If valid, error_message is None.
    """
    if not isinstance(slug, str) or not SLUG_REGEX.match(slug):
        return (
            None,
            "custom_slug must be 3-64 characters long and contain only alphanumeric characters and hyphens",
        )
    return slug, None


def _find_share_by_token_or_slug(token_or_slug: str) -> Share | None:
    """Find a share by either its custom_slug or its share_token."""
    return Share.query.filter(
        or_(Share.custom_slug == token_or_slug, Share.share_token == token_or_slug)
    ).first()

def _log(share_id, accessed_by_id, action: str, success: bool, detail: str = None):
    """Append an audit record to access_logs and notify owner on download/view."""
    log = AccessLog(
        share_id=share_id,
        accessed_by=accessed_by_id,
        ip_address=request.remote_addr,
        action=action,
        success=success,
        detail=detail,
    )
    db.session.add(log)

    # In-app notification creation for share owner on successful download or view
    if success and action in ("download", "view") and share_id:
        share = db.session.get(Share, share_id)
        if share and share.owner_id:
            filename = share.file.filename if share.file else "your shared file"
            verb = "downloaded" if action == "download" else "viewed"
            notification = Notification(
                user_id=share.owner_id,
                type=f"share_{action}",
                message=f"Your shared file '{filename}' was {verb}.",
                related_share_id=share.id,
            )
            db.session.add(notification)

            # Outbound webhook notification for share download
            if action == "download":
                try:
                    dispatch_webhook_event(
                        user_id=share.owner_id,
                        event_type="share.downloaded",
                        data={
                            "share_id": str(share.id),
                            "file_id": str(share.file_id),
                            "filename": filename,
                            "downloaded_by": str(accessed_by_id) if accessed_by_id else None,
                            "ip_address": request.remote_addr,
                            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        },
                    )
                except Exception as wh_exc:
                    current_app.logger.warning(f"Failed to trigger share.downloaded webhook: {wh_exc}")

    db.session.commit()


def _require_ownership(share: Share, current_user: User):
    """Return 403 JSON if current_user is not the share owner, else None."""
    if share.owner_id != current_user.id:
        return jsonify({"error": "Forbidden"}), 403
    return None


def _get_share_receipts(share: Share) -> dict:
    """
    Derive whether/when the recipient first viewed and first downloaded the share.
    Queries AccessLog for share_id + action + accessed_by == recipient_id, success=True,
    ordered by timestamp ascending (taking the earliest of each action type).
    """
    if not share.recipient_id:
        return {
            "first_viewed_at": None,
            "first_downloaded_at": None,
        }

    first_view = (
        AccessLog.query.filter_by(
            share_id=share.id,
            action="view",
            accessed_by=share.recipient_id,
            success=True,
        )
        .order_by(AccessLog.timestamp.asc())
        .first()
    )

    first_download = (
        AccessLog.query.filter_by(
            share_id=share.id,
            action="download",
            accessed_by=share.recipient_id,
            success=True,
        )
        .order_by(AccessLog.timestamp.asc())
        .first()
    )

    return {
        "first_viewed_at": first_view.timestamp.isoformat() if first_view else None,
        "first_downloaded_at": first_download.timestamp.isoformat() if first_download else None,
    }


def _parse_permissions(data: dict) -> dict:
    perms = data.get("permissions", {})
    return {
        "can_view": bool(perms.get("can_view", True)),
        "can_download": bool(perms.get("can_download", False)),
        "can_edit": bool(perms.get("can_edit", False)),
        "can_reshare": bool(perms.get("can_reshare", False)),
    }


def _issue_grant_token(share: Share) -> str:
    """
    Issue a short-lived (15 min) signed JWT granting access to a share.
    Used after successful password verification.
    """
    payload = {
        "sub": str(share.id),
        "type": "share_grant",
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=15),
    }
    return pyjwt.encode(payload, current_app.config["JWT_SECRET_KEY"], algorithm="HS256")


def _verify_grant_token(token: str, share_id: uuid.UUID) -> bool:
    """Validate a grant token and confirm it matches the share."""
    try:
        payload = pyjwt.decode(
            token,
            current_app.config["JWT_SECRET_KEY"],
            algorithms=["HS256"],
        )
        return payload.get("type") == "share_grant" and payload.get("sub") == str(share_id)
    except pyjwt.InvalidTokenError:
        return False


# ---------------------------------------------------------------------------
# POST /api/files/<file_id>/share
# ---------------------------------------------------------------------------

@bp.route("/files/<uuid:file_id>/share", methods=["POST"])
@jwt_required
def create_share(current_user: User, file_id: uuid.UUID):
    """
    Create one share per recipient, or a single open link (no recipient).

    Body (JSON)
    -----------
    {
        "recipient_ids": ["<uuid>", ...],   # optional; omit for open link
        "permissions": {
            "can_view": true,
            "can_download": false,
            "can_edit": false,
            "can_reshare": false
        },
        "password": "optional-plaintext",
        "expires_at": "2026-12-31T23:59:59Z"  # optional ISO-8601
    }
    """
    file = db.session.get(File, file_id)
    if file is None or file.owner_id != current_user.id or file.deleted_at is not None:
        return jsonify({"error": "File not found or access denied"}), 404

    data = request.get_json(silent=True) or {}
    perms = _parse_permissions(data)

    # Parse optional expiry
    expires_at = None
    if data.get("expires_at"):
        try:
            expires_at = datetime.datetime.fromisoformat(data["expires_at"])
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            return jsonify({"error": "Invalid expires_at format, use ISO-8601"}), 400

    recipient_ids = data.get("recipient_ids", [])
    created_shares = []

    # Parse optional custom_slug
    custom_slug = data.get("custom_slug")
    if custom_slug is not None:
        slug, err_msg = _validate_custom_slug(custom_slug)
        if err_msg:
            return jsonify({"error": err_msg}), 400
        if len(recipient_ids) > 1:
            return jsonify({"error": "custom_slug cannot be set when creating multiple shares"}), 400
        existing = _find_share_by_token_or_slug(slug)
        if existing is not None:
            return jsonify({"error": "custom_slug is already in use"}), 409
        custom_slug = slug

    # Parse optional pinned version
    pinned_version = None
    if "pinned_version" in data and data["pinned_version"] is not None:
        try:
            pinned_version = int(data["pinned_version"])
            if pinned_version < 1:
                return jsonify({"error": "pinned_version must be a positive integer"}), 400
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid pinned_version"}), 400

        existing_version_numbers = {v.version_number for v in file.versions} or {1}
        if pinned_version not in existing_version_numbers:
            return jsonify({"error": f"FileVersion {pinned_version} not found for this file"}), 404

    def _build_share(recipient_id=None) -> Share:
        s = Share(
            file_id=file_id,
            owner_id=current_user.id,
            recipient_id=recipient_id,
            share_token=Share.generate_token(),
            custom_slug=custom_slug,
            expires_at=expires_at,
            pinned_version=pinned_version,
            **perms,
        )
        if data.get("password"):
            s.set_password(data["password"])
        return s

    if recipient_ids:
        for rid in recipient_ids:
            try:
                rid_uuid = uuid.UUID(str(rid))
            except ValueError:
                return jsonify({"error": f"Invalid recipient_id: {rid}"}), 400

            recipient = db.session.get(User, rid_uuid)
            if recipient is None:
                return jsonify({"error": f"Recipient not found: {rid}"}), 404

            share = _build_share(recipient_id=rid_uuid)
            db.session.add(share)
            created_shares.append(share)
    else:
        # Open "anyone with the link" share
        share = _build_share()
        db.session.add(share)
        created_shares.append(share)

    db.session.commit()

    base_url = current_app.config["BASE_URL"]
    results = []
    for s in created_shares:
        entry = s.to_dict()
        identifier = s.custom_slug if s.custom_slug else s.share_token
        entry["share_url"] = f"{base_url}/api/shares/{identifier}/access"
        results.append(entry)

    return jsonify({"shares": results}), 201


# ---------------------------------------------------------------------------
# GET /api/files/<file_id>/shares
# ---------------------------------------------------------------------------

@bp.route("/files/<uuid:file_id>/shares", methods=["GET"])
@jwt_required
def list_file_shares(current_user: User, file_id: uuid.UUID):
    """List all active (non-revoked) shares for a file. Owner only."""
    file = db.session.get(File, file_id)
    if file is None or file.owner_id != current_user.id:
        return jsonify({"error": "File not found or access denied"}), 404

    shares = Share.query.filter_by(file_id=file_id, is_revoked=False).all()
    base_url = current_app.config["BASE_URL"]

    results = []
    for s in shares:
        entry = s.to_dict()
        identifier = s.custom_slug if s.custom_slug else s.share_token
        entry["share_url"] = f"{base_url}/api/shares/{identifier}/access"
        entry["is_expired"] = s.is_expired()
        receipts = _get_share_receipts(s)
        entry["first_viewed_at"] = receipts["first_viewed_at"]
        entry["first_downloaded_at"] = receipts["first_downloaded_at"]
        results.append(entry)

    return jsonify({"shares": results}), 200


# ---------------------------------------------------------------------------
# GET /api/shares/<token>/access
# ---------------------------------------------------------------------------

@bp.route("/shares/<string:token>/access", methods=["GET"])
@jwt_optional
def access_share(current_user, token: str):
    """
    Validate a share token or custom slug and return file metadata + allowed actions.
    Does NOT stream file content — that's /download.
    """
    share = _find_share_by_token_or_slug(token)

    if share is None:
        return jsonify({"error": "Share not found"}), 404

    user_id = current_user.id if current_user else None

    if not share.is_valid():
        if share.is_revoked:
            reason = "revoked"
        elif share.owner and not share.owner.is_active:
            reason = "disabled"
        else:
            reason = "expired"
        _log(share.id, user_id, "view", False, reason)
        return jsonify({"error": f"Share is {reason}"}), 410

    # If share is restricted to a specific recipient, enforce it
    if share.recipient_id and (current_user is None or current_user.id != share.recipient_id):
        _log(share.id, user_id, "view", False, "wrong_recipient")
        return jsonify({"error": "This share is not accessible with your account"}), 403

    # If password-protected, caller must first call /verify-password to get a grant token
    if share.password_hash:
        grant = request.headers.get("X-Share-Grant")
        if not grant or not _verify_grant_token(grant, share.id):
            _log(share.id, user_id, "view", False, "password_required")
            return jsonify({"error": "Password required", "password_protected": True}), 401

    _log(share.id, user_id, "view", True)

    target_version = None
    if share.pinned_version is not None:
        target_version = FileVersion.query.filter_by(
            file_id=share.file_id, version_number=share.pinned_version
        ).first()

    if target_version:
        file_dict = {
            "id": str(share.file.id),
            "filename": target_version.filename,
            "mime_type": target_version.mime_type,
            "size_bytes": target_version.size_bytes,
            "version": target_version.version_number,
            "created_at": target_version.created_at.isoformat(),
        }
    else:
        file_dict = share.file.to_dict()

    return jsonify(
        {
            "share": share.to_dict(),
            "file": file_dict,
            "permissions": share.permissions_dict(),
            "version": target_version.version_number if target_version else share.file.current_version_number,
            "is_pinned": share.pinned_version is not None,
        }
    ), 200


# ---------------------------------------------------------------------------
# POST /api/shares/<token>/verify-password
# Rate-limited: 5 attempts per 15 min per IP
# ---------------------------------------------------------------------------

@bp.route("/shares/<string:token>/verify-password", methods=["POST"])
@limiter.limit("5 per 15 minutes")
def verify_share_password(token: str):
    """
    Verify the share-link password.
    On success, returns a short-lived grant token (15 min) that must be sent
    as the X-Share-Grant header on subsequent access/download requests.
    """
    share = _find_share_by_token_or_slug(token)
    if share is None:
        return jsonify({"error": "Share not found"}), 404

    if not share.is_valid():
        return jsonify({"error": "Share is no longer valid"}), 410

    if not share.password_hash:
        return jsonify({"error": "This share is not password-protected"}), 400

    data = request.get_json(silent=True) or {}
    password = data.get("password", "")

    if not share.verify_password(password):
        _log(share.id, None, "password_verify", False, "wrong_password")
        return jsonify({"error": "Incorrect password"}), 403

    _log(share.id, None, "password_verify", True)
    grant_token = _issue_grant_token(share)
    return jsonify({"grant_token": grant_token}), 200


# ---------------------------------------------------------------------------
# GET /api/shares/<token>/download
# ---------------------------------------------------------------------------

@bp.route("/shares/<string:token>/download", methods=["GET"])
@jwt_optional
def download_share(current_user, token: str):
    """
    Stream the decrypted file to an authorised recipient.
    Decryption happens in-memory; no plaintext is written to disk.
    """
    share = _find_share_by_token_or_slug(token)
    if share is None:
        return jsonify({"error": "Share not found"}), 404

    user_id = current_user.id if current_user else None

    if not share.is_valid():
        if share.is_revoked:
            reason = "revoked"
        elif share.owner and not share.owner.is_active:
            reason = "disabled"
        else:
            reason = "expired"
        _log(share.id, user_id, "download", False, reason)
        return jsonify({"error": f"Share is {reason}"}), 410

    if not share.can_download:
        _log(share.id, user_id, "download", False, "no_download_permission")
        return jsonify({"error": "Download not permitted for this share"}), 403

    if share.recipient_id and (current_user is None or current_user.id != share.recipient_id):
        _log(share.id, user_id, "download", False, "wrong_recipient")
        return jsonify({"error": "Access denied"}), 403

    if share.password_hash:
        grant = request.headers.get("X-Share-Grant")
        if not grant or not _verify_grant_token(grant, share.id):
            _log(share.id, user_id, "download", False, "password_required")
            return jsonify({"error": "Password required"}), 401

    # Determine which version blob to download (pinned version or latest file)
    target_filename = share.file.filename
    target_mime = share.file.mime_type
    encrypted_path = share.file.encrypted_path
    nonce_hex = share.file.nonce_hex
    wrapped_key_hex = share.file.wrapped_key_hex

    if share.pinned_version is not None:
        target_version = FileVersion.query.filter_by(
            file_id=share.file_id, version_number=share.pinned_version
        ).first()
        if target_version:
            target_filename = target_version.filename
            target_mime = target_version.mime_type
            encrypted_path = target_version.encrypted_path
            nonce_hex = target_version.nonce_hex
            wrapped_key_hex = target_version.wrapped_key_hex

    # Decrypt in-memory
    try:
        plaintext = decrypt_file(
            encrypted_path,
            nonce_hex,
            wrapped_key_hex,
        )
    except Exception as exc:
        _log(share.id, user_id, "download", False, str(exc))
        return jsonify({"error": "File decryption failed"}), 500

    _log(share.id, user_id, "download", True)

    safe_ascii = secure_filename(target_filename) or "download"
    raw_name = target_filename or "download"
    encoded_filename = urllib.parse.quote(raw_name, safe="!#$&+-.^_`|~")
    content_disposition = f'attachment; filename="{safe_ascii}"; filename*=UTF-8\'\'{encoded_filename}'

    return Response(
        stream_with_context(iter([plaintext])),
        status=200,
        mimetype=share.file.mime_type,
        headers={
            "Content-Disposition": content_disposition,
            "Content-Length": str(len(plaintext)),
        },
    )


# ---------------------------------------------------------------------------
# GET /api/shares/<token>/preview
# ---------------------------------------------------------------------------

@bp.route("/shares/<string:token>/preview", methods=["GET"])
@jwt_optional
def preview_share(current_user, token: str):
    """
    Stream the decrypted file inline for in-browser preview to an authorised recipient.
    Only permitted when can_view=true and can_download=false.
    Decryption happens in-memory; no plaintext is written to disk.
    """
    share = _find_share_by_token_or_slug(token)
    if share is None:
        return jsonify({"error": "Share not found"}), 404

    user_id = current_user.id if current_user else None

    if not share.is_valid():
        if share.is_revoked:
            reason = "revoked"
        elif share.owner and not share.owner.is_active:
            reason = "disabled"
        else:
            reason = "expired"
        _log(share.id, user_id, "view", False, reason)
        return jsonify({"error": f"Share is {reason}"}), 410

    if not share.can_view:
        _log(share.id, user_id, "view", False, "no_view_permission")
        return jsonify({"error": "View not permitted for this share"}), 403

    if share.can_download:
        _log(share.id, user_id, "view", False, "download_permitted")
        return jsonify({"error": "Preview is only available for view-only shares"}), 403

    if share.recipient_id and (current_user is None or current_user.id != share.recipient_id):
        _log(share.id, user_id, "view", False, "wrong_recipient")
        return jsonify({"error": "Access denied"}), 403

    if share.password_hash:
        grant = request.headers.get("X-Share-Grant")
        if not grant or not _verify_grant_token(grant, share.id):
            _log(share.id, user_id, "view", False, "password_required")
            return jsonify({"error": "Password required"}), 401

    # Determine which version blob to preview (pinned version or latest file)
    target_filename = share.file.filename
    target_mime = share.file.mime_type
    encrypted_path = share.file.encrypted_path
    nonce_hex = share.file.nonce_hex
    wrapped_key_hex = share.file.wrapped_key_hex

    if share.pinned_version is not None:
        target_version = FileVersion.query.filter_by(
            file_id=share.file_id, version_number=share.pinned_version
        ).first()
        if target_version:
            target_filename = target_version.filename
            target_mime = target_version.mime_type
            encrypted_path = target_version.encrypted_path
            nonce_hex = target_version.nonce_hex
            wrapped_key_hex = target_version.wrapped_key_hex

    # Decrypt in-memory
    try:
        plaintext = decrypt_file(
            encrypted_path,
            nonce_hex,
            wrapped_key_hex,
        )
    except Exception as exc:
        _log(share.id, user_id, "view", False, str(exc))
        return jsonify({"error": "File decryption failed"}), 500

    _log(share.id, user_id, "view", True)

    safe_ascii = secure_filename(target_filename) or "preview"
    raw_name = target_filename or "preview"
    encoded_filename = urllib.parse.quote(raw_name, safe="!#$&+-.^_`|~")
    content_disposition = f'inline; filename="{safe_ascii}"; filename*=UTF-8\'\'{encoded_filename}'

    return Response(
        stream_with_context(iter([plaintext])),
        status=200,
        mimetype=target_mime or share.file.mime_type or "application/octet-stream",
        headers={
            "Content-Disposition": content_disposition,
            "Content-Length": str(len(plaintext)),
        },
    )


# ---------------------------------------------------------------------------
# GET /api/shares/<share_id>/receipts
# ---------------------------------------------------------------------------

@bp.route("/shares/<uuid:share_id>/receipts", methods=["GET"])
@jwt_required
def get_share_receipts(current_user: User, share_id: uuid.UUID):
    """
    Get read/download receipts for a share with a recipient.
    Returns whether and when the recipient first viewed and first downloaded the share.
    Owner only.
    """
    share = db.session.get(Share, share_id)
    if share is None:
        return jsonify({"error": "Share not found"}), 404

    err = _require_ownership(share, current_user)
    if err:
        return err

    receipts = _get_share_receipts(share)
    return jsonify({
        "share_id": str(share.id),
        "recipient_id": str(share.recipient_id) if share.recipient_id else None,
        "viewed": receipts["first_viewed_at"] is not None,
        "downloaded": receipts["first_downloaded_at"] is not None,
        "first_viewed_at": receipts["first_viewed_at"],
        "first_downloaded_at": receipts["first_downloaded_at"],
    }), 200


# ---------------------------------------------------------------------------
# PATCH /api/shares/<share_id>
# ---------------------------------------------------------------------------

@bp.route("/shares/<uuid:share_id>", methods=["PATCH"])
@jwt_required
def update_share(current_user: User, share_id: uuid.UUID):
    """
    Update permissions, expiry, or revoke a share. Owner only.

    Body (JSON) — all fields optional
    -----------------------------------
    {
        "permissions": { "can_view": true, "can_download": true, ... },
        "expires_at": "2026-12-31T23:59:59Z",
        "is_revoked": true
    }
    """
    share = db.session.get(Share, share_id)
    if share is None:
        return jsonify({"error": "Share not found"}), 404

    err = _require_ownership(share, current_user)
    if err:
        return err

    data = request.get_json(silent=True) or {}

    if "permissions" in data:
        perms = _parse_permissions(data)
        share.can_view = perms["can_view"]
        share.can_download = perms["can_download"]
        share.can_edit = perms["can_edit"]
        share.can_reshare = perms["can_reshare"]

    if "expires_at" in data:
        if data["expires_at"] is None:
            share.expires_at = None
        else:
            try:
                expires_at = datetime.datetime.fromisoformat(data["expires_at"])
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
                share.expires_at = expires_at
            except ValueError:
                return jsonify({"error": "Invalid expires_at format"}), 400

    was_revoked = share.is_revoked
    if "is_revoked" in data:
        share.is_revoked = bool(data["is_revoked"])

    if "custom_slug" in data:
        slug_val = data["custom_slug"]
        if slug_val is None:
            share.custom_slug = None
        else:
            slug, err_msg = _validate_custom_slug(slug_val)
            if err_msg:
                return jsonify({"error": err_msg}), 400
            existing = _find_share_by_token_or_slug(slug)
            if existing is not None and existing.id != share.id:
                return jsonify({"error": "custom_slug is already in use"}), 409
            share.custom_slug = slug

    if "pinned_version" in data:
        if data["pinned_version"] is None:
            share.pinned_version = None
        else:
            try:
                pv = int(data["pinned_version"])
                if pv < 1:
                    return jsonify({"error": "pinned_version must be a positive integer"}), 400
                existing_version_numbers = {v.version_number for v in share.file.versions} or {1}
                if pv not in existing_version_numbers:
                    return jsonify({"error": f"FileVersion {pv} not found for this file"}), 404
                share.pinned_version = pv
            except (ValueError, TypeError):
                return jsonify({"error": "Invalid pinned_version"}), 400

    share.updated_at = datetime.datetime.now(datetime.timezone.utc)
    db.session.commit()

    if not was_revoked and share.is_revoked:
        try:
            filename = share.file.filename if share.file else None
            dispatch_webhook_event(
                user_id=share.owner_id,
                event_type="share.revoked",
                data={
                    "share_id": str(share.id),
                    "file_id": str(share.file_id),
                    "filename": filename,
                    "recipient_id": str(share.recipient_id) if share.recipient_id else None,
                    "custom_slug": share.custom_slug,
                    "revoked_at": share.updated_at.isoformat(),
                },
            )
        except Exception as wh_exc:
            current_app.logger.warning(f"Failed to trigger share.revoked webhook: {wh_exc}")

    return jsonify({"share": share.to_dict()}), 200


# ---------------------------------------------------------------------------
# DELETE /api/shares/<share_id>
# ---------------------------------------------------------------------------

@bp.route("/shares/<uuid:share_id>", methods=["DELETE"])
@jwt_required
def delete_share(current_user: User, share_id: uuid.UUID):
    """Revoke (soft-delete) a share. Owner only."""
    share = db.session.get(Share, share_id)
    if share is None:
        return jsonify({"error": "Share not found"}), 404

    err = _require_ownership(share, current_user)
    if err:
        return err

    share.is_revoked = True
    share.updated_at = datetime.datetime.now(datetime.timezone.utc)
    db.session.commit()

    try:
        filename = share.file.filename if share.file else None
        dispatch_webhook_event(
            user_id=share.owner_id,
            event_type="share.revoked",
            data={
                "share_id": str(share.id),
                "file_id": str(share.file_id),
                "filename": filename,
                "recipient_id": str(share.recipient_id) if share.recipient_id else None,
                "custom_slug": share.custom_slug,
                "revoked_at": share.updated_at.isoformat(),
            },
        )
    except Exception as wh_exc:
        current_app.logger.warning(f"Failed to trigger share.revoked webhook: {wh_exc}")

    return jsonify({"message": "Share revoked"}), 200


# ---------------------------------------------------------------------------
# GET /api/shares/<token>/qrcode
# ---------------------------------------------------------------------------

@bp.route("/shares/<string:token>/qrcode", methods=["GET"])
@jwt_optional
def share_qrcode(current_user, token: str):
    """
    Return a QR code PNG encoding the share URL.
    The share must be valid and (if password-protected) the caller must
    supply X-Share-Grant so we don't expose protected links freely.
    """
    share = _find_share_by_token_or_slug(token)
    if share is None:
        return jsonify({"error": "Share not found"}), 404

    if not share.is_valid():
        return jsonify({"error": "Share is no longer valid"}), 410

    if share.password_hash:
        grant = request.headers.get("X-Share-Grant")
        if not grant or not _verify_grant_token(grant, share.id):
            return jsonify({"error": "Password required to access QR code"}), 401

    identifier = share.custom_slug if share.custom_slug else share.share_token
    share_url = f"{current_app.config['BASE_URL']}/api/shares/{identifier}/access"

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4,
    )
    qr.add_data(share_url)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)

    return Response(buf.getvalue(), status=200, mimetype="image/png")
