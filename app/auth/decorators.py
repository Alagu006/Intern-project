"""
JWT authentication decorators.

Every protected route uses @jwt_required.  The decorator validates the
Bearer token, loads the User from the DB, and injects it as the first
argument to the wrapped function.

Module 6 adds @admin_required for admin-only routes.

Usage
-----
@bp.route("/protected")
@jwt_required
def protected_route(current_user):
    ...

@bp.route("/admin-only")
@admin_required
def admin_route(current_user):
    # current_user is guaranteed to be admin
    ...
"""

import jwt
from functools import wraps
from flask import request, jsonify, current_app
from app.extensions import db
from app.models.user import User
import uuid


def _extract_token() -> str | None:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return None


def _parse_user_id(sub) -> uuid.UUID | None:
    """Safely parse a subject claim into a UUID, returning None if missing or malformed."""
    if not sub:
        return None
    try:
        return uuid.UUID(str(sub))
    except (ValueError, TypeError, AttributeError):
        return None


def _authenticate_request(optional: bool = False):
    """
    Extract Bearer token, decode JWT, and load User from DB.

    Returns:
        tuple[User | None, tuple | None]: (user, error_response)
        - On success: (user, None)
        - On failure (when not optional): (None, (jsonify(...), status_code))
        - When optional and no token: (None, None)
    """
    token = _extract_token()
    if not token:
        if optional:
            return None, None
        return None, (jsonify({"error": "Missing authentication token"}), 401)

    # Personal Access Token authentication (prefixed with 'pat_')
    if token.startswith("pat_"):
        from app.models.personal_access_token import PersonalAccessToken
        import datetime

        token_hash = PersonalAccessToken.hash_token(token)
        pat = PersonalAccessToken.query.filter_by(token_hash=token_hash).first()
        if pat is None:
            return None, (jsonify({"error": "Invalid token"}), 401)

        if pat.is_expired():
            return None, (jsonify({"error": "Token has expired"}), 401)

        user = db.session.get(User, pat.user_id)
        if user is None:
            return None, (jsonify({"error": "User not found"}), 401)

        # Update last_used_at timestamp
        try:
            pat.last_used_at = datetime.datetime.now(datetime.timezone.utc)
            db.session.commit()
        except Exception:
            db.session.rollback()

        return user, None

    try:
        payload = jwt.decode(
            token,
            current_app.config["JWT_SECRET_KEY"],
            algorithms=["HS256"],
        )
    except jwt.ExpiredSignatureError:
        return None, (jsonify({"error": "Token has expired"}), 401)
    except jwt.InvalidTokenError:
        return None, (jsonify({"error": "Invalid token"}), 401)

    user_id = _parse_user_id(payload.get("sub"))
    if user_id is None:
        return None, (jsonify({"error": "Invalid token"}), 401)

    user = db.session.get(User, user_id)
    if user is None:
        return None, (jsonify({"error": "User not found"}), 401)

    return user, None


def jwt_required(f):
    """Decorator: validates JWT and passes current_user to the route."""

    @wraps(f)
    def decorated(*args, **kwargs):
        user, err = _authenticate_request()
        if err:
            return err

        return f(current_user=user, *args, **kwargs)

    return decorated


def jwt_optional(f):
    """
    Like jwt_required but passes current_user=None when no token is provided.
    Useful for share-access endpoints that allow anonymous access.
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        user, err = _authenticate_request(optional=True)
        if err:
            return err

        return f(current_user=user, *args, **kwargs)

    return decorated


def generate_access_token(user: User) -> str:
    """Issue a signed JWT for a user (used by login / MFA verify endpoints)."""
    import datetime

    payload = {
        "sub": str(user.id),
        "iat": datetime.datetime.now(datetime.timezone.utc),
        "exp": datetime.datetime.now(datetime.timezone.utc)
        + current_app.config["JWT_ACCESS_TOKEN_EXPIRES"],
    }
    return jwt.encode(payload, current_app.config["JWT_SECRET_KEY"], algorithm="HS256")


def admin_required(f):
    """
    Decorator: validates JWT and ensures user has admin role.
    Returns 403 if user is not admin or account is disabled.
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        user, err = _authenticate_request()
        if err:
            return err

        # Check if account is active
        if not user.is_active:
            return jsonify({"error": "Account is disabled"}), 403

        # Check if user is admin
        if not user.is_admin():
            return jsonify({"error": "Admin access required"}), 403

        return f(current_user=user, *args, **kwargs)

    return decorated
