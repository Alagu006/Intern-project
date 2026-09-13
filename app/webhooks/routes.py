import secrets
import urllib.parse
import uuid
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from app.extensions import db
from app.models import User, Webhook
from app.auth.decorators import jwt_required
from app.webhooks.dispatcher import SUPPORTED_EVENTS
from app.webhooks.security import validate_webhook_url

bp = Blueprint("webhooks", __name__, url_prefix="/api/webhooks")


def _is_valid_url(url: str) -> tuple[bool, str]:
    return validate_webhook_url(url)


def _validate_event_types(events) -> tuple[bool, str]:
    if not isinstance(events, list):
        return False, "event_types must be a list"
    if not events:
        return False, "event_types cannot be empty"
    for ev in events:
        if not isinstance(ev, str):
            return False, "All event_types entries must be strings"
        if ev != "*" and ev not in SUPPORTED_EVENTS:
            return False, f"Unsupported event type: '{ev}'. Supported: {', '.join(sorted(SUPPORTED_EVENTS))}"
    return True, ""


# ---------------------------------------------------------------------------
# POST /api/webhooks — Register a new webhook
# ---------------------------------------------------------------------------
@bp.route("", methods=["POST"])
@jwt_required
def create_webhook(current_user: User):
    """
    Create a new webhook endpoint scoped to current_user.
    Body:
      - url (str, required)
      - secret (str, optional, defaults to 32-byte hex token)
      - event_types (list[str], optional, defaults to all supported events)
      - is_active (bool, optional, defaults to True)
    """
    data = request.get_json(silent=True) or {}

    url = data.get("url")
    is_valid, err_msg = validate_webhook_url(url)
    if not is_valid:
        return jsonify({"error": f"Invalid URL: {err_msg}"}), 400

    secret = data.get("secret")
    if secret is not None:
        if not isinstance(secret, str) or not secret.strip():
            return jsonify({"error": "Secret must be a non-empty string"}), 400
        secret = secret.strip()
    else:
        secret = secrets.token_hex(32)

    event_types = data.get("event_types")
    if event_types is not None:
        is_valid, err_msg = _validate_event_types(event_types)
        if not is_valid:
            return jsonify({"error": err_msg}), 400
    else:
        event_types = sorted(list(SUPPORTED_EVENTS))

    is_active = data.get("is_active", True)
    if not isinstance(is_active, bool):
        return jsonify({"error": "is_active must be a boolean"}), 400

    webhook = Webhook(
        user_id=current_user.id,
        url=url,
        secret=secret,
        event_types=event_types,
        is_active=is_active,
    )
    db.session.add(webhook)
    db.session.commit()

    return jsonify({"webhook": webhook.to_dict()}), 201


# ---------------------------------------------------------------------------
# GET /api/webhooks — List user's webhooks
# ---------------------------------------------------------------------------
@bp.route("", methods=["GET"])
@jwt_required
def list_webhooks(current_user: User):
    """
    List all webhooks configured by the authenticated user.
    """
    webhooks = (
        Webhook.query.filter_by(user_id=current_user.id)
        .order_by(Webhook.created_at.desc())
        .all()
    )
    return jsonify({"webhooks": [w.to_dict() for w in webhooks]}), 200


# ---------------------------------------------------------------------------
# GET /api/webhooks/<webhook_id> — Retrieve single webhook
# ---------------------------------------------------------------------------
@bp.route("/<uuid:webhook_id>", methods=["GET"])
@jwt_required
def get_webhook(current_user: User, webhook_id: uuid.UUID):
    """
    Retrieve a specific webhook configuration owned by the authenticated user.
    """
    webhook = db.session.get(Webhook, webhook_id)
    if webhook is None:
        return jsonify({"error": "Webhook not found"}), 404

    if webhook.user_id != current_user.id:
        return jsonify({"error": "Forbidden"}), 403

    return jsonify({"webhook": webhook.to_dict()}), 200


# ---------------------------------------------------------------------------
# PATCH /api/webhooks/<webhook_id> — Update webhook
# ---------------------------------------------------------------------------
@bp.route("/<uuid:webhook_id>", methods=["PATCH"])
@jwt_required
def update_webhook(current_user: User, webhook_id: uuid.UUID):
    """
    Update webhook fields (url, secret, event_types, is_active).
    """
    webhook = db.session.get(Webhook, webhook_id)
    if webhook is None:
        return jsonify({"error": "Webhook not found"}), 404

    if webhook.user_id != current_user.id:
        return jsonify({"error": "Forbidden"}), 403

    data = request.get_json(silent=True) or {}

    if "url" in data:
        url = data["url"]
        is_valid, err_msg = validate_webhook_url(url)
        if not is_valid:
            return jsonify({"error": f"Invalid URL: {err_msg}"}), 400
        webhook.url = url

    if "secret" in data:
        secret = data["secret"]
        if not isinstance(secret, str) or not secret.strip():
            return jsonify({"error": "Secret must be a non-empty string"}), 400
        webhook.secret = secret.strip()

    if "event_types" in data:
        events = data["event_types"]
        is_valid, err_msg = _validate_event_types(events)
        if not is_valid:
            return jsonify({"error": err_msg}), 400
        webhook.event_types = events

    if "is_active" in data:
        is_active = data["is_active"]
        if not isinstance(is_active, bool):
            return jsonify({"error": "is_active must be a boolean"}), 400
        webhook.is_active = is_active

    webhook.updated_at = datetime.now(timezone.utc)
    db.session.commit()

    return jsonify({"webhook": webhook.to_dict()}), 200


# ---------------------------------------------------------------------------
# DELETE /api/webhooks/<webhook_id> — Delete webhook
# ---------------------------------------------------------------------------
@bp.route("/<uuid:webhook_id>", methods=["DELETE"])
@jwt_required
def delete_webhook(current_user: User, webhook_id: uuid.UUID):
    """
    Delete a webhook configured by the authenticated user.
    """
    webhook = db.session.get(Webhook, webhook_id)
    if webhook is None:
        return jsonify({"error": "Webhook not found"}), 404

    if webhook.user_id != current_user.id:
        return jsonify({"error": "Forbidden"}), 403

    db.session.delete(webhook)
    db.session.commit()

    return jsonify({"message": "Webhook deleted"}), 200
