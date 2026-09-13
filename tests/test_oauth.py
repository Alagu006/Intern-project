"""
Tests for optional Google OAuth authentication.

Covers:
- Unconfigured state: routes return 404 when GOOGLE_OAUTH_CLIENT_ID / GOOGLE_OAUTH_CLIENT_SECRET are unset.
- OAuth start flow: GET /api/auth/oauth/google/start redirects to Google consent screen (302).
- OAuth callback flow:
  - New user provisioning: creates user with oauth_provider="google" and password_hash=None.
  - Existing user login: logs in user matched by verified email.
  - Disabled user rejection: returns 403 if account is inactive.
  - Unverified email rejection: returns 400 if email_verified is False.
  - Missing authorization code / Google error handling: returns 400.
- Password login prevention for OAuth-only accounts:
  - POST /api/auth/login rejects login attempts on OAuth-only accounts with clear error.
"""

from unittest.mock import patch
import pytest

from app.extensions import db
from app.models.user import User


@pytest.fixture
def enable_google_oauth(app):
    """Fixture that configures Google OAuth credentials on the Flask app."""
    app.config["GOOGLE_OAUTH_CLIENT_ID"] = "mock-client-id.apps.googleusercontent.com"
    app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = "mock-client-secret-12345"
    app.config["GOOGLE_OAUTH_REDIRECT_URI"] = "https://localhost:5000/api/auth/oauth/google/callback"
    yield
    app.config["GOOGLE_OAUTH_CLIENT_ID"] = None
    app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = None
    app.config["GOOGLE_OAUTH_REDIRECT_URI"] = None


class TestGoogleOAuthUnconfigured:
    """Ensure OAuth routes 404 when environment variables are not set."""

    def test_start_route_returns_404_when_unconfigured(self, client, app):
        app.config["GOOGLE_OAUTH_CLIENT_ID"] = None
        app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = None

        res = client.get("/api/auth/oauth/google/start")
        assert res.status_code == 404
        assert "not configured" in res.get_json()["error"].lower()

    def test_callback_route_returns_404_when_unconfigured(self, client, app):
        app.config["GOOGLE_OAUTH_CLIENT_ID"] = None
        app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = None

        res = client.get("/api/auth/oauth/google/callback?code=some_code")
        assert res.status_code == 404
        assert "not configured" in res.get_json()["error"].lower()


class TestGoogleOAuthFlow:
    """Test suite for configured Google OAuth flow."""

    def test_oauth_start_redirects_to_google_consent_screen(self, client, enable_google_oauth):
        """GET /api/auth/oauth/google/start redirects (302) to Google's consent screen."""
        res = client.get("/api/auth/oauth/google/start")
        assert res.status_code == 302
        location = res.headers.get("Location", "")
        assert location.startswith("https://accounts.google.com/o/oauth2/v2/auth")
        assert "client_id=mock-client-id.apps.googleusercontent.com" in location
        assert "response_type=code" in location
        assert "scope=" in location

    @patch("requests_oauthlib.OAuth2Session.fetch_token")
    @patch("google.oauth2.id_token.verify_oauth2_token")
    def test_oauth_callback_provisions_new_user(
        self, mock_verify, mock_fetch, client, app, enable_google_oauth
    ):
        """Callback exchanges code, verifies ID token, and provisions a new user with oauth_provider='google'."""
        mock_fetch.return_value = {"id_token": "valid_mock_jwt_id_token"}
        mock_verify.return_value = {
            "email": "new_google_user@example.com",
            "email_verified": True,
            "name": "Jane Google",
            "sub": "google-sub-123456",
        }

        res = client.get("/api/auth/oauth/google/callback?code=mock_google_code_xyz")
        assert res.status_code == 200
        data = res.get_json()

        assert "access_token" in data
        assert data["is_new_user"] is True
        assert data["user"]["email"] == "new_google_user@example.com"
        assert data["user"]["oauth_provider"] == "google"

        # Verify record in database
        with app.app_context():
            user = User.query.filter_by(email="new_google_user@example.com").first()
            assert user is not None
            assert user.oauth_provider == "google"
            assert user.password_hash is None
            assert user.is_active is True
            assert user.last_login is not None

    @patch("requests_oauthlib.OAuth2Session.fetch_token")
    @patch("google.oauth2.id_token.verify_oauth2_token")
    def test_oauth_callback_logs_in_existing_user(
        self, mock_verify, mock_fetch, client, app, enable_google_oauth
    ):
        """Callback logs in an existing user matching the verified email without creating a duplicate."""
        with app.app_context():
            existing = User(
                username="existing_member",
                email="member@example.com",
            )
            existing.set_password("SecretPassword123!")
            db.session.add(existing)
            db.session.commit()
            existing_id = existing.id

        mock_fetch.return_value = {"id_token": "valid_mock_jwt_id_token"}
        mock_verify.return_value = {
            "email": "member@example.com",
            "email_verified": True,
            "name": "Existing Member",
            "sub": "google-sub-999999",
        }

        res = client.get("/api/auth/oauth/google/callback?code=valid_code")
        assert res.status_code == 200
        data = res.get_json()

        assert "access_token" in data
        assert data["is_new_user"] is False
        assert data["user"]["id"] == str(existing_id)
        assert data["user"]["email"] == "member@example.com"

        # Verify user now has oauth_provider set to google while preserving password_hash
        with app.app_context():
            user = db.session.get(User, existing_id)
            assert user.oauth_provider == "google"
            assert user.password_hash is not None
            assert user.verify_password("SecretPassword123!") is True

    def test_password_login_disabled_for_oauth_only_account(self, client, app):
        """OAuth-only accounts (with password_hash=None) cannot log in via POST /api/auth/login."""
        with app.app_context():
            oauth_user = User(
                username="oauth_only_user",
                email="oauthonly@example.com",
                oauth_provider="google",
                password_hash=None,
            )
            db.session.add(oauth_user)
            db.session.commit()

        login_res = client.post(
            "/api/auth/login",
            json={"email": "oauthonly@example.com", "password": "AnyPassword123!"},
        )
        assert login_res.status_code == 400
        assert "Google OAuth" in login_res.get_json()["error"] or "Google" in login_res.get_json()["error"]

    @patch("requests_oauthlib.OAuth2Session.fetch_token")
    @patch("google.oauth2.id_token.verify_oauth2_token")
    def test_oauth_callback_disabled_account_rejected(
        self, mock_verify, mock_fetch, client, app, enable_google_oauth
    ):
        """Disabled accounts cannot authenticate via OAuth (returns 403)."""
        with app.app_context():
            disabled_user = User(
                username="disabled_google_user",
                email="disabled@example.com",
                oauth_provider="google",
                is_active=False,
            )
            db.session.add(disabled_user)
            db.session.commit()

        mock_fetch.return_value = {"id_token": "valid_mock_jwt_id_token"}
        mock_verify.return_value = {
            "email": "disabled@example.com",
            "email_verified": True,
            "name": "Disabled User",
        }

        res = client.get("/api/auth/oauth/google/callback?code=mock_code")
        assert res.status_code == 403
        assert "disabled" in res.get_json()["error"].lower()

    @patch("requests_oauthlib.OAuth2Session.fetch_token")
    @patch("google.oauth2.id_token.verify_oauth2_token")
    def test_oauth_callback_unverified_email_rejected(
        self, mock_verify, mock_fetch, client, enable_google_oauth
    ):
        """Rejects Google account if email is not verified (returns 400)."""
        mock_fetch.return_value = {"id_token": "valid_mock_jwt_id_token"}
        mock_verify.return_value = {
            "email": "unverified@example.com",
            "email_verified": False,
            "name": "Unverified User",
        }

        res = client.get("/api/auth/oauth/google/callback?code=mock_code")
        assert res.status_code == 400
        assert "not verified" in res.get_json()["error"].lower()

    def test_oauth_callback_missing_code_or_error_param(self, client, enable_google_oauth):
        """Returns 400 if code parameter is missing or Google returns an error."""
        # 1. Missing code
        res_no_code = client.get("/api/auth/oauth/google/callback")
        assert res_no_code.status_code == 400
        assert "code" in res_no_code.get_json()["error"].lower()

        # 2. Google error parameter
        res_error = client.get("/api/auth/oauth/google/callback?error=access_denied")
        assert res_error.status_code == 400
        assert "access_denied" in res_error.get_json()["error"]
