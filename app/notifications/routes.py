"""
Notifications endpoints: list notifications (paginated, newest first) and mark as read.
"""

import uuid
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from sqlalchemy import desc
from app.extensions import db
from app.models import Notification
from app.auth.decorators import jwt_required
from app.utils import _get_pagination_params, _paginate_query

bp = Blueprint("notifications", __name__, url_prefix="/api/notifications")


@bp.route("", methods=["GET"])
@jwt_required
def list_notifications(current_user):
    """
    List notifications for the current authenticated user (newest first).
    Query parameters:
    - page (int): page number (default 1)
    - per_page (int): items per page (default 20, max 100)
    - unread (bool): filter to only unread notifications if true
    """
    page, per_page = _get_pagination_params(max_per_page=100)

    query = Notification.query.filter_by(user_id=current_user.id)

    # Optional filter: unread only
    unread_arg = request.args.get("unread")
    if unread_arg is not None and unread_arg.lower() in ("true", "1", "yes"):
        query = query.filter(Notification.read_at.is_(None))

    query = query.order_by(desc(Notification.created_at), desc(Notification.id))

    result = _paginate_query(query, page, per_page)
    notification_items = [n.to_dict() for n in result["items"]]

    unread_count = Notification.query.filter_by(
        user_id=current_user.id, read_at=None
    ).count()

    return jsonify({
        "notifications": notification_items,
        "items": notification_items,
        "total": result["total"],
        "page": result["page"],
        "per_page": result["per_page"],
        "pages": result["pages"],
        "unread_count": unread_count,
    }), 200


@bp.route("/<uuid:notification_id>/read", methods=["PATCH"])
@jwt_required
def mark_notification_read(current_user, notification_id: uuid.UUID):
    """
    Mark a specific notification as read.
    """
    notification = db.session.get(Notification, notification_id)
    if notification is None:
        return jsonify({"error": "Notification not found"}), 404

    if notification.user_id != current_user.id:
        return jsonify({"error": "Forbidden: You do not own this notification"}), 403

    if notification.read_at is None:
        notification.read_at = datetime.now(timezone.utc)
        db.session.commit()

    return jsonify({
        "message": "Notification marked as read",
        "notification": notification.to_dict(),
    }), 200
