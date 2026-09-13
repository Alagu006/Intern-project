"""
Module 6: Admin Dashboard & User Management
Blueprint: /api/admin

All endpoints require JWT + admin role.

Endpoints
---------
GET    /api/admin/users                     — list users (paginated, searchable)
GET    /api/admin/users/<user_id>           — user detail with stats
PATCH  /api/admin/users/<user_id>/disable   — disable user account
PATCH  /api/admin/users/<user_id>/enable    — enable user account
GET    /api/admin/files                     — list all files system-wide
GET    /api/admin/storage                   — storage usage breakdown
GET    /api/admin/audit-logs                — audit logs (paginated, filterable)
GET    /api/admin/audit-logs/export         — export logs as CSV
GET    /api/admin/stats/summary             — system statistics
GET    /api/admin/stats/charts              — time-series data for charts
"""

import io
import csv
import uuid
from datetime import datetime, timedelta, timezone
from flask import Blueprint, request, jsonify, Response
from sqlalchemy import func, desc, and_
from app.extensions import db
from app.models import User, File, Share, AccessLog
from app.auth.decorators import admin_required

bp = Blueprint("admin", __name__, url_prefix="/api/admin")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

from app.utils import _get_pagination_params, _paginate_query


def _log_admin_action(admin_user, action, detail=None):
    """Log an admin action to AccessLog."""
    log = AccessLog(
        share_id=None,  # admin actions don't relate to shares
        accessed_by=admin_user.id,
        ip_address=request.remote_addr,
        action=action,
        success=True,
        detail=detail,
    )
    db.session.add(log)
    db.session.commit()


def _sanitize_csv_field(value):
    """
    Sanitize CSV field against formula injection.
    Prefix cells starting with =, +, -, @ with a single quote.
    """
    if value is None:
        return ""
    value_str = str(value)
    if value_str and value_str[0] in ("=", "+", "-", "@"):
        return "'" + value_str
    return value_str


# ---------------------------------------------------------------------------
# GET /api/admin/users — List users with search and filters
# ---------------------------------------------------------------------------

@bp.route("/users", methods=["GET"])
@admin_required
def list_users(current_user):
    """
    List all users with pagination, search, and filters.
    
    Query params:
    - page (int): page number (default 1)
    - per_page (int): items per page (default 20, max 100)
    - search (str): search username or email
    - role (str): filter by role ('admin' or 'user')
    - active (bool): filter by is_active status
    """
    page, per_page = _get_pagination_params()
    
    query = User.query
    
    # Search by username or email
    search = request.args.get("search", "").strip()
    if search:
        pattern = f"%{search}%"
        query = query.filter(
            (User.username.ilike(pattern)) | (User.email.ilike(pattern))
        )
    
    # Filter by role
    role = request.args.get("role", "").strip().lower()
    if role in ("admin", "user"):
        query = query.filter(User.role == role)
    
    # Filter by active status
    active = request.args.get("active")
    if active is not None:
        is_active = active.lower() in ("true", "1", "yes")
        query = query.filter(User.is_active == is_active)
    
    # Order by created_at desc
    query = query.order_by(desc(User.created_at))
    
    # Paginate
    result = _paginate_query(query, page, per_page)
    
    # Convert to admin dict
    result["items"] = [user.to_admin_dict() for user in result["items"]]
    
    return jsonify(result), 200


# ---------------------------------------------------------------------------
# GET /api/admin/users/<user_id> — User detail with stats
# ---------------------------------------------------------------------------

@bp.route("/users/<uuid:user_id>", methods=["GET"])
@admin_required
def get_user_detail(current_user, user_id):
    """
    Get detailed user information including:
    - Profile data
    - File count
    - Total storage used
    - Share count (created and received)
    - Last login
    - MFA status
    """
    user = db.session.get(User, user_id)
    if user is None:
        return jsonify({"error": "User not found"}), 404
    
    # Calculate stats
    file_count = File.query.filter_by(owner_id=user_id).count()
    storage_used = db.session.query(func.sum(File.size_bytes)).filter(
        File.owner_id == user_id
    ).scalar() or 0
    
    shares_created_count = Share.query.filter_by(owner_id=user_id).count()
    shares_received_count = Share.query.filter_by(recipient_id=user_id).count()
    
    # Recent activity (last 10 access logs)
    recent_activity = AccessLog.query.filter_by(accessed_by=user_id).order_by(
        desc(AccessLog.timestamp)
    ).limit(10).all()
    
    result = {
        "user": user.to_admin_dict(),
        "stats": {
            "file_count": file_count,
            "storage_used_bytes": storage_used,
            "shares_created": shares_created_count,
            "shares_received": shares_received_count,
        },
        "recent_activity": [log.to_dict() for log in recent_activity],
    }
    
    return jsonify(result), 200


# ---------------------------------------------------------------------------
# PATCH /api/admin/users/<user_id>/disable — Disable user account
# ---------------------------------------------------------------------------

@bp.route("/users/<uuid:user_id>/disable", methods=["PATCH"])
@admin_required
def disable_user(current_user, user_id):
    """
    Disable a user account.
    Sets is_active=False and records disabled_at timestamp.
    Admin cannot disable themselves.
    """
    if user_id == current_user.id:
        return jsonify({"error": "Cannot disable your own account"}), 400
    
    user = db.session.get(User, user_id)
    if user is None:
        return jsonify({"error": "User not found"}), 404
    
    if not user.is_active:
        return jsonify({"error": "User is already disabled"}), 400
    
    # Disable the account
    user.is_active = False
    user.disabled_at = datetime.now(timezone.utc)
    db.session.commit()
    
    # Log the admin action
    _log_admin_action(
        current_user,
        "admin_disable_user",
        f"Disabled user {user.username} ({user_id})"
    )
    
    return jsonify({
        "message": "User disabled successfully",
        "user": user.to_admin_dict()
    }), 200


# ---------------------------------------------------------------------------
# PATCH /api/admin/users/<user_id>/enable — Enable user account
# ---------------------------------------------------------------------------

@bp.route("/users/<uuid:user_id>/enable", methods=["PATCH"])
@admin_required
def enable_user(current_user, user_id):
    """
    Enable a previously disabled user account.
    Sets is_active=True and clears disabled_at.
    """
    user = db.session.get(User, user_id)
    if user is None:
        return jsonify({"error": "User not found"}), 404
    
    if user.is_active:
        return jsonify({"error": "User is already enabled"}), 400
    
    # Enable the account
    user.is_active = True
    user.disabled_at = None
    db.session.commit()
    
    # Log the admin action
    _log_admin_action(
        current_user,
        "admin_enable_user",
        f"Enabled user {user.username} ({user_id})"
    )
    
    return jsonify({
        "message": "User enabled successfully",
        "user": user.to_admin_dict()
    }), 200


# ---------------------------------------------------------------------------
# PATCH /api/admin/users/<user_id>/quota — Update user storage quota
# ---------------------------------------------------------------------------

@bp.route("/users/<uuid:user_id>/quota", methods=["PATCH"])
@admin_required
def update_user_quota(current_user, user_id):
    """
    Update a user's storage quota in bytes (or null for unlimited).
    Accepts JSON:
    - storage_quota_bytes: integer (>= 0) or null (for unlimited)
    - storage_quota_mb: integer/float (>= 0) or null (for unlimited)
    """
    user = db.session.get(User, user_id)
    if user is None:
        return jsonify({"error": "User not found"}), 404

    data = request.get_json(silent=True) or {}
    if "storage_quota_bytes" not in data and "storage_quota_mb" not in data:
        return jsonify({"error": "storage_quota_bytes or storage_quota_mb is required"}), 400

    new_quota = None
    if "storage_quota_bytes" in data:
        val = data["storage_quota_bytes"]
        if val is not None:
            try:
                val = int(val)
            except (ValueError, TypeError):
                return jsonify({"error": "storage_quota_bytes must be an integer or null"}), 400
            if val < 0:
                return jsonify({"error": "storage_quota_bytes cannot be negative"}), 400
            new_quota = val
        else:
            new_quota = None
    elif "storage_quota_mb" in data:
        val = data["storage_quota_mb"]
        if val is not None:
            try:
                val = float(val)
            except (ValueError, TypeError):
                return jsonify({"error": "storage_quota_mb must be a number or null"}), 400
            if val < 0:
                return jsonify({"error": "storage_quota_mb cannot be negative"}), 400
            new_quota = int(val * 1024 * 1024)
        else:
            new_quota = None

    user.storage_quota_bytes = new_quota
    db.session.commit()

    quota_display = f"{new_quota} bytes" if new_quota is not None else "unlimited"
    _log_admin_action(
        current_user,
        "admin_update_quota",
        f"Updated storage quota for user {user.username} ({user_id}) to {quota_display}"
    )

    return jsonify({
        "message": "Storage quota updated successfully",
        "user": user.to_admin_dict(),
        "storage_quota_bytes": user.storage_quota_bytes,
    }), 200


# ---------------------------------------------------------------------------
# GET /api/admin/files — List all files system-wide
# ---------------------------------------------------------------------------

@bp.route("/files", methods=["GET"])
@admin_required
def list_all_files(current_user):
    """
    List all files in the system with pagination.
    
    Query params:
    - page, per_page
    - owner_id: filter by owner
    - sort: 'size' | 'date' (default: date desc)
    """
    page, per_page = _get_pagination_params()
    
    query = File.query
    
    # Filter by owner
    owner_id = request.args.get("owner_id")
    if owner_id:
        try:
            query = query.filter(File.owner_id == uuid.UUID(owner_id))
        except ValueError:
            return jsonify({"error": "Invalid owner_id"}), 400
    
    # Sort
    sort = request.args.get("sort", "date")
    if sort == "size":
        query = query.order_by(desc(File.size_bytes))
    else:
        query = query.order_by(desc(File.created_at))
    
    # Paginate
    result = _paginate_query(query, page, per_page)
    
    # Add owner info and share count to each file
    items_with_owner = []
    for file in result["items"]:
        share_count = Share.query.filter_by(file_id=file.id, is_revoked=False).count()
        file_dict = file.to_dict()
        file_dict["owner"] = {
            "id": str(file.owner.id),
            "username": file.owner.username,
            "email": file.owner.email,
        }
        file_dict["share_count"] = share_count
        items_with_owner.append(file_dict)
    
    result["items"] = items_with_owner
    
    return jsonify(result), 200


# ---------------------------------------------------------------------------
# GET /api/admin/storage — Storage usage breakdown
# ---------------------------------------------------------------------------

@bp.route("/storage", methods=["GET"])
@admin_required
def storage_usage(current_user):
    """
    Get storage usage statistics:
    - Total storage used across all users
    - Top 10 users by storage consumption
    - Storage breakdown by file type (mime_type)
    """
    # Total storage
    total_storage = db.session.query(func.sum(File.size_bytes)).scalar() or 0
    
    # Top users by storage
    top_users = db.session.query(
        User.id,
        User.username,
        User.email,
        func.sum(File.size_bytes).label("storage_used")
    ).join(File, File.owner_id == User.id).group_by(
        User.id, User.username, User.email
    ).order_by(desc("storage_used")).limit(10).all()
    
    top_users_list = [
        {
            "user_id": str(user.id),
            "username": user.username,
            "email": user.email,
            "storage_used_bytes": user.storage_used,
        }
        for user in top_users
    ]
    
    # Storage by file type
    storage_by_type = db.session.query(
        File.mime_type,
        func.count(File.id).label("file_count"),
        func.sum(File.size_bytes).label("total_size")
    ).group_by(File.mime_type).order_by(desc("total_size")).limit(20).all()
    
    storage_by_type_list = [
        {
            "mime_type": row.mime_type,
            "file_count": row.file_count,
            "total_size_bytes": row.total_size,
        }
        for row in storage_by_type
    ]
    
    return jsonify({
        "total_storage_bytes": total_storage,
        "top_users": top_users_list,
        "storage_by_type": storage_by_type_list,
    }), 200


# ---------------------------------------------------------------------------
# GET /api/admin/audit-logs — View audit logs (paginated, filterable)
# ---------------------------------------------------------------------------

@bp.route("/audit-logs", methods=["GET"])
@admin_required
def get_audit_logs(current_user):
    """
    Get audit logs with pagination and filters.
    
    Query params:
    - page, per_page
    - user_id: filter by accessed_by
    - action: filter by action type
    - start_date, end_date: date range (ISO-8601)
    - success: filter by success (true/false)
    """
    page, per_page = _get_pagination_params()
    
    query = AccessLog.query
    
    # Filter by user
    user_id = request.args.get("user_id")
    if user_id:
        try:
            query = query.filter(AccessLog.accessed_by == uuid.UUID(user_id))
        except ValueError:
            return jsonify({"error": "Invalid user_id"}), 400
    
    # Filter by action
    action = request.args.get("action")
    if action:
        query = query.filter(AccessLog.action == action)
    
    # Filter by date range
    start_date = request.args.get("start_date")
    if start_date:
        try:
            start_dt = datetime.fromisoformat(start_date)
            if start_dt.tzinfo is None:
                start_dt = start_dt.replace(tzinfo=timezone.utc)
            query = query.filter(AccessLog.timestamp >= start_dt)
        except ValueError:
            return jsonify({"error": "Invalid start_date format"}), 400
    
    end_date = request.args.get("end_date")
    if end_date:
        try:
            end_dt = datetime.fromisoformat(end_date)
            if end_dt.tzinfo is None:
                end_dt = end_dt.replace(tzinfo=timezone.utc)
            query = query.filter(AccessLog.timestamp <= end_dt)
        except ValueError:
            return jsonify({"error": "Invalid end_date format"}), 400
    
    # Filter by success
    success = request.args.get("success")
    if success is not None:
        is_success = success.lower() in ("true", "1", "yes")
        query = query.filter(AccessLog.success == is_success)
    
    # Order by timestamp desc
    query = query.order_by(desc(AccessLog.timestamp))
    
    # Paginate
    result = _paginate_query(query, page, per_page)
    
    # Convert to dict
    result["items"] = [log.to_dict() for log in result["items"]]
    
    return jsonify(result), 200


# ---------------------------------------------------------------------------
# GET /api/admin/audit-logs/export — Export audit logs as CSV
# ---------------------------------------------------------------------------

@bp.route("/audit-logs/export", methods=["GET"])
@admin_required
def export_audit_logs(current_user):
    """
    Export audit logs as CSV file.
    Accepts same filters as GET /api/admin/audit-logs.
    """
    query = AccessLog.query
    
    # Apply same filters as get_audit_logs
    user_id = request.args.get("user_id")
    if user_id:
        try:
            query = query.filter(AccessLog.accessed_by == uuid.UUID(user_id))
        except ValueError:
            pass
    
    action = request.args.get("action")
    if action:
        query = query.filter(AccessLog.action == action)
    
    start_date = request.args.get("start_date")
    if start_date:
        try:
            start_dt = datetime.fromisoformat(start_date)
            if start_dt.tzinfo is None:
                start_dt = start_dt.replace(tzinfo=timezone.utc)
            query = query.filter(AccessLog.timestamp >= start_dt)
        except ValueError:
            pass
    
    end_date = request.args.get("end_date")
    if end_date:
        try:
            end_dt = datetime.fromisoformat(end_date)
            if end_dt.tzinfo is None:
                end_dt = end_dt.replace(tzinfo=timezone.utc)
            query = query.filter(AccessLog.timestamp <= end_dt)
        except ValueError:
            pass
    
    success = request.args.get("success")
    if success is not None:
        is_success = success.lower() in ("true", "1", "yes")
        query = query.filter(AccessLog.success == is_success)
    
    query = query.order_by(desc(AccessLog.timestamp))
    
    # Limit export to 10,000 rows
    logs = query.limit(10000).all()
    
    # Generate CSV
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow([
        "ID", "Share ID", "Accessed By", "IP Address",
        "Action", "Success", "Detail", "Timestamp"
    ])
    
    # Data rows with sanitization
    for log in logs:
        writer.writerow([
            _sanitize_csv_field(str(log.id)),
            _sanitize_csv_field(str(log.share_id) if log.share_id else ""),
            _sanitize_csv_field(str(log.accessed_by) if log.accessed_by else ""),
            _sanitize_csv_field(log.ip_address),
            _sanitize_csv_field(log.action),
            _sanitize_csv_field(log.success),
            _sanitize_csv_field(log.detail),
            _sanitize_csv_field(log.timestamp.isoformat() if log.timestamp else ""),
        ])
    
    output.seek(0)
    
    # Log the export action
    _log_admin_action(
        current_user,
        "admin_export_logs",
        f"Exported {len(logs)} audit log records"
    )
    
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=audit_logs_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
        }
    )


# ---------------------------------------------------------------------------
# GET /api/admin/stats/summary — System statistics summary
# ---------------------------------------------------------------------------

@bp.route("/stats/summary", methods=["GET"])
@admin_required
def stats_summary(current_user):
    """
    Get system-wide statistics:
    - Total users
    - Total files
    - Uploads today
    - Downloads today
    - Shared files count (active shares)
    - Failed login attempts today
    """
    # Total users
    total_users = User.query.count()
    
    # Total files
    total_files = File.query.count()
    
    # Today's range
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    today_end = today_start + timedelta(days=1)
    
    # Uploads today
    uploads_today = File.query.filter(
        and_(
            File.created_at >= today_start,
            File.created_at < today_end
        )
    ).count()
    
    # Downloads today (from access logs)
    downloads_today = AccessLog.query.filter(
        and_(
            AccessLog.action == "download",
            AccessLog.success == True,
            AccessLog.timestamp >= today_start,
            AccessLog.timestamp < today_end
        )
    ).count()
    
    # Active shared files (non-revoked, non-expired shares)
    now = datetime.now(timezone.utc)
    shared_files_count = db.session.query(func.count(func.distinct(Share.file_id))).filter(
        and_(
            Share.is_revoked == False,
            (Share.expires_at == None) | (Share.expires_at > now)
        )
    ).scalar() or 0
    
    # Failed login attempts today (assume action='login' or similar pattern)
    # Since we don't have explicit login logs yet, we'll count failed password verifications
    failed_login_attempts = AccessLog.query.filter(
        and_(
            AccessLog.action.in_(["password_verify", "login"]),
            AccessLog.success == False,
            AccessLog.timestamp >= today_start,
            AccessLog.timestamp < today_end
        )
    ).count()
    
    return jsonify({
        "total_users": total_users,
        "total_files": total_files,
        "uploads_today": uploads_today,
        "downloads_today": downloads_today,
        "shared_files_count": shared_files_count,
        "failed_login_attempts_today": failed_login_attempts,
    }), 200


# ---------------------------------------------------------------------------
# GET /api/admin/stats/charts — Time-series data for charts
# ---------------------------------------------------------------------------

@bp.route("/stats/charts", methods=["GET"])
@admin_required
def stats_charts(current_user):
    """
    Get time-series data for charts.
    
    Query params:
    - metric: 'uploads' | 'downloads' | 'storage' | 'activity'
    - range: '7d' | '30d' | '90d' (default: 7d)
    
    Returns daily data points for the specified range.
    """
    metric = request.args.get("metric", "uploads")
    range_param = request.args.get("range", "7d")
    
    # Parse range
    if range_param == "30d":
        days = 30
    elif range_param == "90d":
        days = 90
    else:
        days = 7
    
    # Calculate date range
    end_date = datetime.now(timezone.utc).replace(hour=23, minute=59, second=59, microsecond=999999)
    start_date = end_date - timedelta(days=days - 1)
    start_date = start_date.replace(hour=0, minute=0, second=0, microsecond=0)
    
    # Generate data based on metric
    if metric == "uploads":
        # Count files uploaded per day
        data = []
        for i in range(days):
            day_start = start_date + timedelta(days=i)
            day_end = day_start + timedelta(days=1)
            
            count = File.query.filter(
                and_(
                    File.created_at >= day_start,
                    File.created_at < day_end
                )
            ).count()
            
            data.append({
                "date": day_start.date().isoformat(),
                "value": count
            })
    
    elif metric == "downloads":
        # Count downloads per day from access logs
        data = []
        for i in range(days):
            day_start = start_date + timedelta(days=i)
            day_end = day_start + timedelta(days=1)
            
            count = AccessLog.query.filter(
                and_(
                    AccessLog.action == "download",
                    AccessLog.success == True,
                    AccessLog.timestamp >= day_start,
                    AccessLog.timestamp < day_end
                )
            ).count()
            
            data.append({
                "date": day_start.date().isoformat(),
                "value": count
            })
    
    elif metric == "storage":
        # Cumulative storage usage per day
        data = []
        for i in range(days):
            day_end = start_date + timedelta(days=i + 1)
            
            total_storage = db.session.query(func.sum(File.size_bytes)).filter(
                File.created_at < day_end
            ).scalar() or 0
            
            data.append({
                "date": (day_end - timedelta(days=1)).date().isoformat(),
                "value": total_storage
            })
    
    elif metric == "activity":
        # User activity per day (unique users with any access log entry)
        data = []
        for i in range(days):
            day_start = start_date + timedelta(days=i)
            day_end = day_start + timedelta(days=1)
            
            active_users = db.session.query(
                func.count(func.distinct(AccessLog.accessed_by))
            ).filter(
                and_(
                    AccessLog.timestamp >= day_start,
                    AccessLog.timestamp < day_end,
                    AccessLog.accessed_by != None
                )
            ).scalar() or 0
            
            data.append({
                "date": day_start.date().isoformat(),
                "value": active_users
            })
    
    else:
        return jsonify({"error": "Invalid metric. Choose: uploads, downloads, storage, activity"}), 400
    
    return jsonify({
        "metric": metric,
        "range": range_param,
        "data": data
    }), 200
