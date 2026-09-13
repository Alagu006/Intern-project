"""
Auth endpoints: register, login (with optional TOTP), user search.
"""

import io
import json
import base64
import qrcode
import pyotp
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, redirect, session, current_app
from sqlalchemy import func
from requests_oauthlib import OAuth2Session
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
    base64url_to_bytes,
)
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
)
from app.extensions import db, limiter
from app.models.user import User
from app.models.file import File
from app.models.webauthn_credential import WebAuthnCredential
from app.auth.decorators import generate_access_token, jwt_required

bp = Blueprint("auth", __name__, url_prefix="/api/auth")


def _get_login_email():
    """Extract and normalize the email from request body for per-email rate limiting."""
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()
    return f"email:{email}" if email else ""


def _no_email_in_request():
    """Exempt request from per-email limit if email was not supplied."""
    data = request.get_json(silent=True) or {}
    return not bool(data.get("email", "").strip())


@bp.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not username or not email or not password:
        return jsonify({"error": "username, email, and password are required"}), 400

    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({"error": "Username or email already taken"}), 409

    user = User(username=username, email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify({"user": user.to_public_dict()}), 201


@bp.route("/login", methods=["POST"])
@limiter.limit("10 per 15 minutes")
@limiter.limit("10 per 15 minutes", key_func=_get_login_email, exempt_when=_no_email_in_request)
def login():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    user = User.query.filter_by(email=email).first()
    if not user or not user.verify_password(password):
        if user and user.oauth_provider and not user.password_hash:
            return jsonify({
                "error": "Password login is disabled for OAuth-only accounts. Please sign in with Google."
            }), 400
        return jsonify({"error": "Invalid credentials"}), 401

    # Check if account is active (Module 6)
    if not user.is_active:
        return jsonify({"error": "Account is disabled"}), 403

    if user.mfa_enabled:
        totp_code = data.get("totp_code", "")
        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(totp_code):
            return jsonify({"error": "Invalid MFA code"}), 401

    # Update last login timestamp (Module 6)
    from datetime import datetime, timezone
    user.last_login = datetime.now(timezone.utc)
    db.session.commit()

    token = generate_access_token(user)
    return jsonify({"access_token": token, "user": user.to_public_dict()}), 200


@bp.route("/users/search", methods=["GET"])
@jwt_required
def search_users(current_user):
    """
    Search users by username or email (for the recipient picker in the UI).
    Query param: q=<string>
    """
    q = request.args.get("q", "").strip()
    if len(q) < 2:
        return jsonify({"users": []}), 200

    pattern = f"%{q}%"
    users = (
        User.query.filter(
            (User.username.ilike(pattern)) | (User.email.ilike(pattern))
        )
        .limit(20)
        .all()
    )
    # Never return the requester themselves
    results = [u.to_public_dict() for u in users if u.id != current_user.id]
    return jsonify({"users": results}), 200


# ---------------------------------------------------------------------------
# MFA Endpoints
# ---------------------------------------------------------------------------

@bp.route("/mfa/setup", methods=["POST"])
@jwt_required
def mfa_setup(current_user):
    """
    Generate a new TOTP secret for the user and return both the raw secret
    and a QR code (base64 PNG) encoding the otpauth:// URI.
    The secret is stored on the user as pending (mfa_enabled remains False).
    """
    if current_user.mfa_enabled:
        return jsonify({"error": "MFA is already enabled"}), 400

    secret = pyotp.random_base32()
    current_user.totp_secret = secret
    db.session.commit()

    totp = pyotp.TOTP(secret)
    otpauth_uri = totp.provisioning_uri(
        name=current_user.email,
        issuer_name="SecureFileShare",
    )

    qr_img = qrcode.make(otpauth_uri)
    buf = io.BytesIO()
    qr_img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    return jsonify({
        "secret": secret,
        "otpauth_uri": otpauth_uri,
        "qr_code": f"data:image/png;base64,{qr_b64}",
        "qr_code_base64": qr_b64,
    }), 200


@bp.route("/mfa/enable", methods=["POST"])
@jwt_required
def mfa_enable(current_user):
    """
    Verify a TOTP code against the pending secret and enable MFA.
    """
    if current_user.mfa_enabled:
        return jsonify({"error": "MFA is already enabled"}), 400

    if not current_user.totp_secret:
        return jsonify({"error": "MFA setup has not been initiated"}), 400

    data = request.get_json(silent=True) or {}
    code = str(data.get("code") or data.get("totp_code") or "").strip()
    if not code:
        return jsonify({"error": "Verification code is required"}), 400

    totp = pyotp.TOTP(current_user.totp_secret)
    if not totp.verify(code):
        return jsonify({"error": "Invalid verification code"}), 400

    current_user.mfa_enabled = True
    db.session.commit()

    return jsonify({
        "message": "MFA enabled successfully",
        "mfa_enabled": True,
    }), 200


@bp.route("/mfa/disable", methods=["POST"])
@jwt_required
def mfa_disable(current_user):
    """
    Disable MFA. Requires the user's password, and if MFA is currently enabled,
    a valid TOTP code. Clears totp_secret.
    """
    if not current_user.mfa_enabled and not current_user.totp_secret:
        return jsonify({"error": "MFA is not enabled"}), 400

    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    if not password:
        return jsonify({"error": "Password is required"}), 400

    if not current_user.verify_password(password):
        return jsonify({"error": "Invalid password"}), 401

    if current_user.mfa_enabled:
        totp_code = str(data.get("totp_code") or data.get("code") or "").strip()
        if not totp_code:
            return jsonify({"error": "TOTP code is required"}), 400

        totp = pyotp.TOTP(current_user.totp_secret)
        if not totp.verify(totp_code):
            return jsonify({"error": "Invalid MFA code"}), 401

    current_user.mfa_enabled = False
    current_user.totp_secret = None
    db.session.commit()

    return jsonify({
        "message": "MFA disabled successfully",
        "mfa_enabled": False,
    }), 200


# ---------------------------------------------------------------------------
# Profile & Password Management Endpoints
# ---------------------------------------------------------------------------

@bp.route("/me", methods=["GET"])
@jwt_required
def get_current_user_profile(current_user):
    """
    Fetch the authenticated user's profile, including MFA status, last login,
    and storage quota/usage statistics.
    """
    storage_used = db.session.query(func.sum(File.size_bytes)).filter(
        File.owner_id == current_user.id
    ).scalar() or 0

    profile = current_user.to_public_dict()
    profile["mfa_enabled"] = current_user.mfa_enabled
    profile["last_login"] = (
        current_user.last_login.isoformat() if current_user.last_login else None
    )
    profile["storage_used_bytes"] = storage_used
    profile["storage_quota_bytes"] = current_user.storage_quota_bytes
    return jsonify({"user": profile, **profile}), 200


# NOTE: Forgotten-password reset email flow (e.g. POST /api/auth/forgot-password and
# POST /api/auth/reset-password) is a planned follow-up task that requires integrating
# an email sending provider (e.g., SendGrid, AWS SES, or SMTP), which is not yet present
# in this codebase.
@bp.route("/change-password", methods=["POST"])
@jwt_required
def change_password(current_user):
    """
    Change the current user's password.
    Requires current_password and new_password. Validates current password and
    enforces a minimum length of 8 characters and non-identical new password.
    """
    data = request.get_json(silent=True) or {}
    current_password = data.get("current_password", "")
    new_password = data.get("new_password", "")

    if not current_password or not new_password:
        return jsonify({"error": "current_password and new_password are required"}), 400

    if not current_user.verify_password(current_password):
        return jsonify({"error": "Invalid current password"}), 401

    if len(new_password) < 8:
        return jsonify({"error": "New password must be at least 8 characters long"}), 400

    if new_password == current_password:
        return jsonify({"error": "New password must be different from current password"}), 400

    current_user.set_password(new_password)
    db.session.commit()

    return jsonify({"message": "Password changed successfully"}), 200


# ---------------------------------------------------------------------------
# Personal Access Tokens (PAT) Endpoints
# ---------------------------------------------------------------------------

@bp.route("/tokens", methods=["POST"])
@jwt_required
def create_personal_access_token(current_user):
    """
    Create a new personal access token for the authenticated user.
    Body:
    - name (str, required): token description/label
    - expires_in_days (int, optional): lifetime in days
    - expires_at (str, optional): ISO formatted expiration timestamp
    """
    import secrets
    from datetime import datetime, timedelta, timezone
    from app.models.personal_access_token import PersonalAccessToken

    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400

    expires_at = None
    if "expires_in_days" in data and data["expires_in_days"] is not None:
        try:
            days = int(data["expires_in_days"])
            if days <= 0:
                return jsonify({"error": "expires_in_days must be positive"}), 400
            expires_at = datetime.now(timezone.utc) + timedelta(days=days)
        except (ValueError, TypeError):
            return jsonify({"error": "expires_in_days must be an integer"}), 400
    elif "expires_at" in data and data["expires_at"] is not None:
        try:
            expires_at = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid expires_at format"}), 400

    raw_token = f"pat_{secrets.token_urlsafe(32)}"
    token_hash = PersonalAccessToken.hash_token(raw_token)

    pat = PersonalAccessToken(
        user_id=current_user.id,
        name=name,
        token_hash=token_hash,
        expires_at=expires_at,
    )
    db.session.add(pat)
    db.session.commit()

    return jsonify({
        "message": "Personal access token created successfully",
        "token": pat.to_dict(),
        "raw_token": raw_token,
    }), 201


@bp.route("/tokens", methods=["GET"])
@jwt_required
def list_personal_access_tokens(current_user):
    """
    List all personal access tokens for the authenticated user (metadata only).
    """
    from app.models.personal_access_token import PersonalAccessToken

    tokens = (
        PersonalAccessToken.query.filter_by(user_id=current_user.id)
        .order_by(PersonalAccessToken.created_at.desc())
        .all()
    )
    return jsonify({"tokens": [t.to_dict() for t in tokens]}), 200


@bp.route("/tokens/<uuid:token_id>", methods=["DELETE"])
@jwt_required
def revoke_personal_access_token(current_user, token_id):
    """
    Revoke (delete) a personal access token.
    """
    from app.models.personal_access_token import PersonalAccessToken

    pat = db.session.get(PersonalAccessToken, token_id)
    if pat is None:
        return jsonify({"error": "Token not found"}), 404

    if pat.user_id != current_user.id:
        return jsonify({"error": "Forbidden: You do not own this token"}), 403

    db.session.delete(pat)
    db.session.commit()

    return jsonify({"message": "Token revoked successfully"}), 200


# ---------------------------------------------------------------------------
# Google OAuth Endpoints
# ---------------------------------------------------------------------------

def _is_google_oauth_enabled() -> bool:
    client_id = current_app.config.get("GOOGLE_OAUTH_CLIENT_ID")
    client_secret = current_app.config.get("GOOGLE_OAUTH_CLIENT_SECRET")
    return bool(client_id and client_secret)


def _get_google_redirect_uri() -> str:
    configured_uri = current_app.config.get("GOOGLE_OAUTH_REDIRECT_URI")
    if configured_uri:
        return configured_uri
    return request.host_url.rstrip("/") + "/api/auth/oauth/google/callback"


@bp.route("/oauth/google/start", methods=["GET"])
def google_oauth_start():
    """
    Redirects to Google's OAuth consent screen.
    Gated behind GOOGLE_OAUTH_CLIENT_ID / GOOGLE_OAUTH_CLIENT_SECRET (returns 404 if unset).
    """
    if not _is_google_oauth_enabled():
        return jsonify({"error": "Google OAuth is not configured"}), 404

    client_id = current_app.config.get("GOOGLE_OAUTH_CLIENT_ID")
    redirect_uri = _get_google_redirect_uri()
    scope = ["openid", "email", "profile"]

    oauth = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scope)
    authorization_url, state = oauth.authorization_url(
        "https://accounts.google.com/o/oauth2/v2/auth",
        access_type="offline",
        prompt="select_account",
    )
    session["oauth_state"] = state
    return redirect(authorization_url, code=302)


@bp.route("/oauth/google/callback", methods=["GET"])
def google_oauth_callback():
    """
    Exchanges code for Google tokens, verifies ID token, and logs in or registers user.
    Gated behind GOOGLE_OAUTH_CLIENT_ID / GOOGLE_OAUTH_CLIENT_SECRET (returns 404 if unset).
    """
    if not _is_google_oauth_enabled():
        return jsonify({"error": "Google OAuth is not configured"}), 404

    error = request.args.get("error")
    if error:
        return jsonify({"error": f"Google OAuth error: {error}"}), 400

    code = request.args.get("code")
    if not code:
        return jsonify({"error": "Authorization code is required"}), 400

    client_id = current_app.config.get("GOOGLE_OAUTH_CLIENT_ID")
    client_secret = current_app.config.get("GOOGLE_OAUTH_CLIENT_SECRET")
    redirect_uri = _get_google_redirect_uri()

    try:
        oauth = OAuth2Session(client_id, redirect_uri=redirect_uri)
        token_response = oauth.fetch_token(
            "https://oauth2.googleapis.com/token",
            code=code,
            client_secret=client_secret,
        )
    except Exception as exc:
        return jsonify({"error": f"Failed to exchange code with Google: {str(exc)}"}), 400

    raw_id_token = token_response.get("id_token")
    if not raw_id_token:
        return jsonify({"error": "Missing id_token in Google response"}), 400

    try:
        id_info = id_token.verify_oauth2_token(
            raw_id_token,
            google_requests.Request(),
            client_id,
        )
    except Exception as exc:
        return jsonify({"error": f"Invalid ID token: {str(exc)}"}), 400

    email = id_info.get("email", "").strip().lower()
    email_verified = id_info.get("email_verified", True)

    if not email:
        return jsonify({"error": "Google account did not provide an email"}), 400

    if not email_verified:
        return jsonify({"error": "Google account email is not verified"}), 400

    # Match existing user by verified email or create a new user
    user = User.query.filter_by(email=email).first()
    is_new_user = False

    if user is None:
        base_name = id_info.get("name") or email.split("@")[0]
        cleaned_name = "".join(c for c in base_name if c.isalnum() or c in ("_", "-")).strip("_-")
        if not cleaned_name:
            cleaned_name = "google_user"

        username = cleaned_name[:50]
        if User.query.filter_by(username=username).first():
            import uuid
            username = f"{username[:42]}_{uuid.uuid4().hex[:6]}"

        user = User(
            username=username,
            email=email,
            oauth_provider="google",
            password_hash=None,
        )
        db.session.add(user)
        is_new_user = True
    else:
        if not user.is_active:
            return jsonify({"error": "Account is disabled"}), 403

        if not user.oauth_provider:
            user.oauth_provider = "google"

    from datetime import datetime, timezone
    user.last_login = datetime.now(timezone.utc)
    db.session.commit()

    token = generate_access_token(user)
    return jsonify({
        "access_token": token,
        "user": user.to_public_dict(),
        "is_new_user": is_new_user,
    }), 200


# ---------------------------------------------------------------------------
# WebAuthn / Passkeys Endpoints
# ---------------------------------------------------------------------------

def _get_webauthn_rp_id() -> str:
    return current_app.config.get("WEBAUTHN_RP_ID", "localhost")


def _get_webauthn_rp_name() -> str:
    return current_app.config.get("WEBAUTHN_RP_NAME", "Secure File Share")


def _get_webauthn_origins() -> list[str]:
    origins = set()
    configured_origin = current_app.config.get("WEBAUTHN_ORIGIN")
    if configured_origin:
        origins.add(configured_origin.rstrip("/"))
    if request.host_url:
        origins.add(request.host_url.rstrip("/"))
    rp_id = _get_webauthn_rp_id()
    origins.add(f"http://{rp_id}")
    origins.add(f"https://{rp_id}")
    if request.host:
        origins.add(f"http://{request.host}")
        origins.add(f"https://{request.host}")
    return list(origins)


@bp.route("/webauthn/register/start", methods=["POST"])
@jwt_required
def webauthn_register_start(current_user):
    """
    Start WebAuthn passkey registration for an authenticated user.
    Returns PublicKeyCredentialCreationOptions.
    """
    rp_id = _get_webauthn_rp_id()
    rp_name = _get_webauthn_rp_name()

    existing_creds = current_user.webauthn_credentials.all()
    exclude_descriptors = [
        PublicKeyCredentialDescriptor(id=c.credential_id)
        for c in existing_creds
    ]

    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=rp_name,
        user_id=current_user.id.bytes,
        user_name=current_user.username,
        user_display_name=current_user.username,
        exclude_credentials=exclude_descriptors or None,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )

    challenge_b64 = base64.urlsafe_b64encode(options.challenge).decode("utf-8").rstrip("=")
    session["webauthn_reg_challenge"] = challenge_b64
    session["webauthn_reg_user_id"] = str(current_user.id)

    data = request.get_json(silent=True) or {}
    nickname = data.get("nickname")
    if nickname:
        session["webauthn_reg_nickname"] = nickname

    options_dict = json.loads(options_to_json(options))
    return jsonify({
        "options": options_dict,
        "challenge": challenge_b64,
    }), 200


@bp.route("/webauthn/register/finish", methods=["POST"])
@jwt_required
def webauthn_register_finish(current_user):
    """
    Verify client's registration response and store WebAuthn credential.
    """
    data = request.get_json(silent=True) or {}
    credential_payload = data.get("credential") or data

    challenge_str = data.get("challenge") or session.get("webauthn_reg_challenge")
    if not challenge_str:
        return jsonify({"error": "Registration challenge not found or expired"}), 400

    try:
        expected_challenge = base64url_to_bytes(challenge_str)
    except Exception:
        return jsonify({"error": "Invalid challenge encoding"}), 400

    rp_id = _get_webauthn_rp_id()
    origins = _get_webauthn_origins()

    try:
        verified = verify_registration_response(
            credential=credential_payload,
            expected_challenge=expected_challenge,
            expected_rp_id=rp_id,
            expected_origin=origins,
            require_user_verification=False,
        )
    except Exception as exc:
        return jsonify({"error": f"WebAuthn registration verification failed: {str(exc)}"}), 400

    nickname = data.get("nickname") or session.pop("webauthn_reg_nickname", None) or "Passkey"

    # Check if credential_id already exists
    existing = WebAuthnCredential.query.filter_by(credential_id=verified.credential_id).first()
    if existing:
        return jsonify({"error": "Credential already registered"}), 409

    cred = WebAuthnCredential(
        user_id=current_user.id,
        credential_id=verified.credential_id,
        public_key=verified.credential_public_key,
        sign_count=verified.sign_count,
        nickname=nickname,
    )
    db.session.add(cred)
    db.session.commit()

    session.pop("webauthn_reg_challenge", None)
    session.pop("webauthn_reg_user_id", None)

    return jsonify({
        "message": "Passkey registered successfully",
        "credential": cred.to_dict(),
    }), 201


@bp.route("/webauthn/login/start", methods=["POST"])
def webauthn_login_start():
    """
    Start WebAuthn passkey authentication.
    Optionally accepts username or email in JSON body to restrict allowed credentials.
    """
    data = request.get_json(silent=True) or {}
    identifier = data.get("email") or data.get("username")

    allow_descriptors = None
    target_user = None

    if identifier:
        target_user = User.query.filter(
            (User.email == identifier.strip().lower()) | (User.username == identifier.strip())
        ).first()
        if target_user:
            creds = target_user.webauthn_credentials.all()
            if creds:
                allow_descriptors = [
                    PublicKeyCredentialDescriptor(id=c.credential_id)
                    for c in creds
                ]

    rp_id = _get_webauthn_rp_id()
    options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=allow_descriptors,
        user_verification=UserVerificationRequirement.PREFERRED,
    )

    challenge_b64 = base64.urlsafe_b64encode(options.challenge).decode("utf-8").rstrip("=")
    session["webauthn_auth_challenge"] = challenge_b64
    if target_user:
        session["webauthn_auth_user_id"] = str(target_user.id)

    options_dict = json.loads(options_to_json(options))
    return jsonify({
        "options": options_dict,
        "challenge": challenge_b64,
    }), 200


@bp.route("/webauthn/login/finish", methods=["POST"])
def webauthn_login_finish():
    """
    Verify WebAuthn authentication response and log user in.
    """
    data = request.get_json(silent=True) or {}
    credential_payload = data.get("credential") or data

    # Extract rawId or id from credential payload
    raw_id_str = credential_payload.get("rawId") or credential_payload.get("id")
    if not raw_id_str:
        return jsonify({"error": "Missing credential ID in authentication response"}), 400

    try:
        cred_id_bytes = base64url_to_bytes(raw_id_str)
    except Exception:
        return jsonify({"error": "Invalid credential ID encoding"}), 400

    cred = WebAuthnCredential.query.filter_by(credential_id=cred_id_bytes).first()
    if cred is None:
        return jsonify({"error": "Passkey not recognized"}), 404

    user = cred.user
    if not user.is_active:
        return jsonify({"error": "Account is disabled"}), 403

    challenge_str = data.get("challenge") or session.get("webauthn_auth_challenge")
    if not challenge_str:
        return jsonify({"error": "Authentication challenge not found or expired"}), 400

    try:
        expected_challenge = base64url_to_bytes(challenge_str)
    except Exception:
        return jsonify({"error": "Invalid challenge encoding"}), 400

    rp_id = _get_webauthn_rp_id()
    origins = _get_webauthn_origins()

    try:
        verified = verify_authentication_response(
            credential=credential_payload,
            expected_challenge=expected_challenge,
            expected_rp_id=rp_id,
            expected_origin=origins,
            credential_public_key=cred.public_key,
            credential_current_sign_count=cred.sign_count,
            require_user_verification=False,
        )
    except Exception as exc:
        return jsonify({"error": f"WebAuthn authentication verification failed: {str(exc)}"}), 400

    # Update sign count and last login
    cred.sign_count = verified.new_sign_count
    user.last_login = datetime.now(timezone.utc)
    db.session.commit()

    session.pop("webauthn_auth_challenge", None)
    session.pop("webauthn_auth_user_id", None)

    token = generate_access_token(user)
    return jsonify({
        "access_token": token,
        "user": user.to_public_dict(),
    }), 200

