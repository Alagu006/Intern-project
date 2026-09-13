"""
Unit tests for authentication endpoints, specifically rate limiting on POST /api/auth/login.
"""

import pytest
import jwt
import pyotp
from datetime import datetime, timezone, timedelta
from app import create_app
from app.config import TestingConfig
from app.extensions import db as _db, limiter
from app.models import User


class RateLimitTestingConfig(TestingConfig):
    """Testing config with rate limiting explicitly enabled."""
    RATELIMIT_ENABLED = True
    RATELIMIT_STORAGE_URI = "memory://"


@pytest.fixture(scope="function")
def rl_app():
    """Create a test application instance with rate limiting enabled."""
    app = create_app(RateLimitTestingConfig)
    with app.app_context():
        _db.create_all()
        limiter.reset()
        yield app
        limiter.reset()
        _db.session.remove()
        _db.drop_all()


@pytest.fixture(scope="function")
def rl_client(rl_app):
    return rl_app.test_client()


class TestLoginRateLimiting:
    """Test suite for login endpoint rate limiting."""

    def test_login_rate_limit_per_ip_same_credentials(self, rl_client):
        """
        An attacker repeatedly guessing passwords from the same IP
        is blocked after 10 attempts (11th attempt returns 429).
        """
        payload = {"email": "victim@example.com", "password": "wrong_password"}

        for i in range(10):
            res = rl_client.post("/api/auth/login", json=payload)
            assert res.status_code == 401, f"Attempt {i + 1} should return 401"
            assert res.get_json()["error"] == "Invalid credentials"

        # 11th attempt should hit rate limit
        res_limited = rl_client.post("/api/auth/login", json=payload)
        assert res_limited.status_code == 429
        assert res_limited.content_type.startswith("application/json")

        data = res_limited.get_json()
        assert data is not None
        assert data.get("error") == "Rate limit exceeded"
        assert "message" in data
        assert "15 minute" in data["message"]

    def test_login_rate_limit_per_ip_across_different_emails(self, rl_client):
        """
        An attacker enumerating or credential stuffing multiple emails from
        the same IP is blocked after 10 attempts total.
        """
        for i in range(10):
            res = rl_client.post(
                "/api/auth/login",
                json={"email": f"user{i}@example.com", "password": "wrong_password"},
            )
            assert res.status_code == 401

        # 11th attempt with a different email should still be blocked by IP rate limit
        res_limited = rl_client.post(
            "/api/auth/login",
            json={"email": "another_user@example.com", "password": "wrong_password"},
        )
        assert res_limited.status_code == 429
        data = res_limited.get_json()
        assert data["error"] == "Rate limit exceeded"

    def test_login_rate_limit_per_email_distributed_ips(self, rl_client):
        """
        An attacker distributing password guesses against a single target account
        across 10 different IP addresses is blocked on the 11th attempt.
        """
        target_email = "target@example.com"

        for i in range(10):
            ip = f"198.51.100.{i + 1}"
            res = rl_client.post(
                "/api/auth/login",
                json={"email": target_email, "password": "wrong_password"},
                environ_base={"REMOTE_ADDR": ip},
            )
            assert res.status_code == 401

        # 11th attempt against target_email from a fresh IP (198.51.100.99)
        res_limited = rl_client.post(
            "/api/auth/login",
            json={"email": target_email, "password": "wrong_password"},
            environ_base={"REMOTE_ADDR": "198.51.100.99"},
        )
        assert res_limited.status_code == 429
        assert res_limited.get_json()["error"] == "Rate limit exceeded"

        # A different email from that fresh IP should NOT be rate limited
        res_other = rl_client.post(
            "/api/auth/login",
            json={"email": "someone_else@example.com", "password": "wrong_password"},
            environ_base={"REMOTE_ADDR": "198.51.100.99"},
        )
        assert res_other.status_code == 401

    def test_login_rate_limit_successful_logins(self, rl_app, rl_client):
        """
        Verify that rate limiting applies to the endpoint even on valid credentials,
        preventing automated token hammering.
        """
        with rl_app.app_context():
            user = User(username="legituser", email="legit@example.com")
            user.set_password("CorrectPass123!")
            _db.session.add(user)
            _db.session.commit()

        payload = {"email": "legit@example.com", "password": "CorrectPass123!"}

        for i in range(10):
            res = rl_client.post("/api/auth/login", json=payload)
            assert res.status_code == 200, f"Attempt {i + 1} should succeed"
            assert "access_token" in res.get_json()

        # 11th attempt should hit rate limit
        res_limited = rl_client.post("/api/auth/login", json=payload)
        assert res_limited.status_code == 429
        assert res_limited.get_json()["error"] == "Rate limit exceeded"

    def test_rate_limit_clear_json_format_and_headers(self, rl_client):
        """
        Verify the 429 response has proper JSON structure and standard headers.
        """
        for _ in range(10):
            rl_client.post("/api/auth/login", json={"email": "json_test@test.com", "password": "x"})

        res = rl_client.post("/api/auth/login", json={"email": "json_test@test.com", "password": "x"})
        assert res.status_code == 429
        assert res.is_json
        body = res.get_json()
        assert isinstance(body, dict)
        assert body["error"] == "Rate limit exceeded"
        assert isinstance(body["message"], str)
        assert len(body["message"]) > 0
        assert "Retry-After" in res.headers

    def test_login_rate_limit_empty_payload(self, rl_client):
        """
        Requests with missing or invalid bodies are still constrained by the IP rate limit.
        """
        for i in range(10):
            res = rl_client.post("/api/auth/login", json={})
            assert res.status_code == 401

        res_limited = rl_client.post("/api/auth/login", json={})
        assert res_limited.status_code == 429
        assert res_limited.get_json()["error"] == "Rate limit exceeded"

    def test_share_password_verification_returns_json_429(self, rl_client):
        """
        Verify that the global 429 error handler also returns JSON for the share password
        verification endpoint (limited to 5 per 15 minutes).
        """
        fake_token = "some_share_token_string_here"
        for _ in range(5):
            rl_client.post(f"/api/shares/{fake_token}/verify-password", json={"password": "wrong"})

        res = rl_client.post(f"/api/shares/{fake_token}/verify-password", json={"password": "wrong"})
        assert res.status_code == 429
        assert res.is_json
        assert res.get_json()["error"] == "Rate limit exceeded"

    def test_limiter_respects_ratelimit_storage_uri_redis(self):
        """
        Verify that Limiter reads RATELIMIT_STORAGE_URI from app.config at init_app time,
        instantiating RedisStorage when configured with a redis:// URI rather than
        being hardcoded to MemoryStorage.
        """
        try:
            create_app({
                "RATELIMIT_ENABLED": True,
                "RATELIMIT_STORAGE_URI": "redis://localhost:6379",
            })
            assert type(limiter.storage).__name__ == "RedisStorage"
        finally:
            # Restore in-memory storage for subsequent tests
            create_app({
                "RATELIMIT_ENABLED": True,
                "RATELIMIT_STORAGE_URI": "memory://",
            })
            assert type(limiter.storage).__name__ == "MemoryStorage"


class TestStartupSecretKeyValidation:
    """Test startup checks for insecure default placeholder secrets in non-testing mode."""

    def test_startup_check_raises_runtime_error_with_default_placeholders(self, monkeypatch):
        """create_app() without testing mode raises RuntimeError if placeholder keys are used."""
        monkeypatch.delenv("SECRET_KEY", raising=False)
        monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
        from app.config import Config
        monkeypatch.setattr(Config, "SECRET_KEY", "change-me-in-production")
        monkeypatch.setattr(Config, "JWT_SECRET_KEY", "jwt-secret-change-me")

        with pytest.raises(RuntimeError) as exc_info:
            create_app()

        err_msg = str(exc_info.value)
        assert "Insecure startup configuration" in err_msg
        assert "SECRET_KEY" in err_msg
        assert "JWT_SECRET_KEY" in err_msg
        assert "change-me-in-production" in err_msg
        assert "jwt-secret-change-me" in err_msg
        assert "environment variables" in err_msg

    def test_startup_check_raises_in_production_mode(self, monkeypatch):
        """create_app('production') raises RuntimeError with default placeholders."""
        monkeypatch.delenv("SECRET_KEY", raising=False)
        monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
        from app.config import Config
        monkeypatch.setattr(Config, "SECRET_KEY", "change-me-in-production")
        monkeypatch.setattr(Config, "JWT_SECRET_KEY", "jwt-secret-change-me")

        with pytest.raises(RuntimeError) as exc_info:
            create_app("production")

        assert "Insecure startup configuration" in str(exc_info.value)

    def test_startup_check_raises_when_secret_key_missing(self):
        """create_app raises RuntimeError if SECRET_KEY is missing or empty in non-testing mode."""
        with pytest.raises(RuntimeError) as exc_info:
            create_app({
                "TESTING": False,
                "SECRET_KEY": "",
                "JWT_SECRET_KEY": "valid-custom-jwt-secret-key-12345",
            })

        err_msg = str(exc_info.value)
        assert "Insecure startup configuration" in err_msg
        assert "SECRET_KEY" in err_msg

    def test_startup_check_raises_when_jwt_secret_key_missing(self):
        """create_app raises RuntimeError if JWT_SECRET_KEY is missing or empty in non-testing mode."""
        with pytest.raises(RuntimeError) as exc_info:
            create_app({
                "TESTING": False,
                "SECRET_KEY": "valid-custom-secret-key-12345",
                "JWT_SECRET_KEY": "",
            })

        err_msg = str(exc_info.value)
        assert "Insecure startup configuration" in err_msg
        assert "JWT_SECRET_KEY" in err_msg

    def test_startup_check_passes_with_secure_keys(self):
        """create_app succeeds in non-testing mode when secure custom keys are provided."""
        app = create_app({
            "TESTING": False,
            "SECRET_KEY": "a-strong-production-secret-key-12345",
            "JWT_SECRET_KEY": "a-strong-production-jwt-key-67890",
        })
        assert app is not None
        assert app.config["SECRET_KEY"] == "a-strong-production-secret-key-12345"
        assert app.config["JWT_SECRET_KEY"] == "a-strong-production-jwt-key-67890"

    def test_startup_check_skipped_for_testing_config(self):
        """create_app('testing') boots normally without requiring custom secret keys."""
        app = create_app("testing")
        assert app is not None
        assert app.config["TESTING"] is True


class TestInvalidTokenClaims:
    """Test suite verifying tokens with missing, non-UUID, or malformed 'sub' claims return 401 instead of crashing (500)."""

    def _make_token(self, app, payload_data):
        payload = {
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
            **payload_data,
        }
        return jwt.encode(payload, app.config["JWT_SECRET_KEY"], algorithm="HS256")

    def test_jwt_required_malformed_sub_returns_401(self, rl_app, rl_client):
        """jwt_required returns 401 (not 500) when token has non-UUID string sub claim."""
        bad_token = self._make_token(rl_app, {"sub": "not-a-valid-uuid"})
        res = rl_client.get(
            "/api/auth/users/search?q=test",
            headers={"Authorization": f"Bearer {bad_token}"},
        )
        assert res.status_code == 401
        assert res.get_json()["error"] == "Invalid token"

    def test_jwt_required_missing_sub_returns_401(self, rl_app, rl_client):
        """jwt_required returns 401 (not 500) when token is missing the sub claim."""
        bad_token = self._make_token(rl_app, {"username": "attacker"})
        res = rl_client.get(
            "/api/auth/users/search?q=test",
            headers={"Authorization": f"Bearer {bad_token}"},
        )
        assert res.status_code == 401
        assert res.get_json()["error"] == "Invalid token"

    def test_jwt_required_non_string_sub_returns_401(self, rl_app, rl_client):
        """jwt_required returns 401 (not 500) when sub claim is integer or None."""
        bad_token = self._make_token(rl_app, {"sub": 12345})
        res = rl_client.get(
            "/api/auth/users/search?q=test",
            headers={"Authorization": f"Bearer {bad_token}"},
        )
        assert res.status_code == 401
        assert res.get_json()["error"] == "Invalid token"

    def test_admin_required_malformed_sub_returns_401(self, rl_app, rl_client):
        """admin_required returns 401 (not 500) when token has bad sub claim."""
        bad_token = self._make_token(rl_app, {"sub": "malformed-admin-sub"})
        res = rl_client.get(
            "/api/admin/users",
            headers={"Authorization": f"Bearer {bad_token}"},
        )
        assert res.status_code == 401
        assert res.get_json()["error"] == "Invalid token"

    def test_jwt_optional_malformed_sub_returns_401(self, rl_app, rl_client):
        """jwt_optional returns 401 (not 500) when token is provided with bad sub claim."""
        bad_token = self._make_token(rl_app, {"sub": "not-a-uuid-for-optional"})
        res = rl_client.get(
            "/api/shares/test-token/access",
            headers={"Authorization": f"Bearer {bad_token}"},
        )
        assert res.status_code == 401
        assert res.get_json()["error"] == "Invalid token"


class TestAuthRegistrationAndLogin:
    """Test suite covering registration, login, duplicates, disabled users, and MFA."""

    def test_register_happy_path(self, client):
        """User can register successfully with unique username and email."""
        res = client.post(
            "/api/auth/register",
            json={
                "username": "new_user",
                "email": "new_user@example.com",
                "password": "Password123!",
            },
        )
        assert res.status_code == 201
        data = res.get_json()
        assert "user" in data
        assert data["user"]["username"] == "new_user"
        assert data["user"]["email"] == "new_user@example.com"
        assert "id" in data["user"]

    def test_register_duplicate_username_rejected(self, client):
        """Registering with an already existing username returns 409 Conflict."""
        # First registration
        client.post(
            "/api/auth/register",
            json={
                "username": "dup_username",
                "email": "user1@example.com",
                "password": "Password123!",
            },
        )
        # Duplicate username with different email
        res = client.post(
            "/api/auth/register",
            json={
                "username": "dup_username",
                "email": "user2@example.com",
                "password": "Password123!",
            },
        )
        assert res.status_code == 409
        assert res.get_json()["error"] == "Username or email already taken"

    def test_register_duplicate_email_rejected(self, client):
        """Registering with an already existing email returns 409 Conflict."""
        # First registration
        client.post(
            "/api/auth/register",
            json={
                "username": "user_a",
                "email": "same_email@example.com",
                "password": "Password123!",
            },
        )
        # Duplicate email with different username
        res = client.post(
            "/api/auth/register",
            json={
                "username": "user_b",
                "email": "same_email@example.com",
                "password": "Password123!",
            },
        )
        assert res.status_code == 409
        assert res.get_json()["error"] == "Username or email already taken"

    def test_login_happy_path(self, app, client, db):
        """Active user can log in with valid credentials and receive an access token."""
        with app.app_context():
            user = User(username="login_user", email="login_user@example.com")
            user.set_password("CorrectPass123!")
            db.session.add(user)
            db.session.commit()

        res = client.post(
            "/api/auth/login",
            json={"email": "login_user@example.com", "password": "CorrectPass123!"},
        )
        assert res.status_code == 200
        data = res.get_json()
        assert "access_token" in data
        assert data["user"]["email"] == "login_user@example.com"

    def test_login_wrong_password_rejected(self, app, client, db):
        """Attempting to log in with an incorrect password returns 401."""
        with app.app_context():
            user = User(username="wrong_pass_user", email="wrong_pass@example.com")
            user.set_password("Secret123!")
            db.session.add(user)
            db.session.commit()

        res = client.post(
            "/api/auth/login",
            json={"email": "wrong_pass@example.com", "password": "WrongPassword!"},
        )
        assert res.status_code == 401
        assert res.get_json()["error"] == "Invalid credentials"

    def test_login_disabled_account_rejected(self, app, client, db):
        """Disabled user account cannot log in and receives 403 Account is disabled."""
        with app.app_context():
            user = User(username="disabled_user", email="disabled@example.com")
            user.set_password("ValidPassword123!")
            user.is_active = False
            db.session.add(user)
            db.session.commit()

        res = client.post(
            "/api/auth/login",
            json={"email": "disabled@example.com", "password": "ValidPassword123!"},
        )
        assert res.status_code == 403
        assert res.get_json()["error"] == "Account is disabled"

    def test_login_mfa_enabled_happy_path(self, app, client, db, monkeypatch):
        """User with MFA enabled can log in with valid credentials and verified TOTP code."""
        with app.app_context():
            user = User(username="mfa_user", email="mfa_user@example.com")
            user.set_password("MfaPassword123!")
            user.mfa_enabled = True
            user.totp_secret = "JBSWY3DPEHPK3PXP"
            db.session.add(user)
            db.session.commit()

        import pyotp
        monkeypatch.setattr(pyotp.TOTP, "verify", lambda self, code: code == "123456")

        res = client.post(
            "/api/auth/login",
            json={
                "email": "mfa_user@example.com",
                "password": "MfaPassword123!",
                "totp_code": "123456",
            },
        )
        assert res.status_code == 200
        data = res.get_json()
        assert "access_token" in data

    def test_login_mfa_enabled_invalid_code_rejected(self, app, client, db, monkeypatch):
        """User with MFA enabled is rejected with 401 when supplying an invalid TOTP code."""
        with app.app_context():
            user = User(username="mfa_fail_user", email="mfa_fail@example.com")
            user.set_password("MfaPassword123!")
            user.mfa_enabled = True
            user.totp_secret = "JBSWY3DPEHPK3PXP"
            db.session.add(user)
            db.session.commit()

        import pyotp
        monkeypatch.setattr(pyotp.TOTP, "verify", lambda self, code: False)

        res = client.post(
            "/api/auth/login",
            json={
                "email": "mfa_fail@example.com",
                "password": "MfaPassword123!",
                "totp_code": "999999",
            },
        )
        assert res.status_code == 401
        assert res.get_json()["error"] == "Invalid MFA code"


class TestMFALifecycle:
    """Test suite covering MFA Setup, Enable, Login with MFA, and Disable flow."""

    def test_mfa_setup_happy_path(self, client, owner, owner_token, app, db):
        """Calling /api/auth/mfa/setup generates secret and QR code, leaving mfa_enabled=False."""
        res = client.post(
            "/api/auth/mfa/setup",
            headers={"Authorization": f"Bearer {owner_token}"},
        )
        assert res.status_code == 200
        data = res.get_json()
        assert "secret" in data
        assert len(data["secret"]) == 32
        assert "otpauth_uri" in data
        assert data["otpauth_uri"].startswith("otpauth://totp/")
        assert "qr_code" in data
        assert data["qr_code"].startswith("data:image/png;base64,")
        assert "qr_code_base64" in data

        with app.app_context():
            user = db.session.get(User, owner.id)
            assert user.totp_secret == data["secret"]
            assert user.mfa_enabled is False

    def test_mfa_setup_unauthorized_rejected(self, client):
        """Calling /api/auth/mfa/setup without a token returns 401."""
        res = client.post("/api/auth/mfa/setup")
        assert res.status_code == 401
        assert res.get_json()["error"] == "Missing authentication token"

    def test_mfa_setup_when_already_enabled_rejected(self, client, owner, owner_token, app, db):
        """Calling setup when MFA is already enabled returns 400."""
        with app.app_context():
            user = db.session.get(User, owner.id)
            user.mfa_enabled = True
            user.totp_secret = "JBSWY3DPEHPK3PXP"
            db.session.commit()

        res = client.post(
            "/api/auth/mfa/setup",
            headers={"Authorization": f"Bearer {owner_token}"},
        )
        assert res.status_code == 400
        assert res.get_json()["error"] == "MFA is already enabled"

    def test_mfa_enable_happy_path(self, client, owner, owner_token, app, db):
        """Enabling MFA with a valid TOTP code flips mfa_enabled to True."""
        setup_res = client.post(
            "/api/auth/mfa/setup",
            headers={"Authorization": f"Bearer {owner_token}"},
        )
        secret = setup_res.get_json()["secret"]

        valid_code = pyotp.TOTP(secret).now()
        enable_res = client.post(
            "/api/auth/mfa/enable",
            json={"code": valid_code},
            headers={"Authorization": f"Bearer {owner_token}"},
        )
        assert enable_res.status_code == 200
        data = enable_res.get_json()
        assert data["mfa_enabled"] is True
        assert data["message"] == "MFA enabled successfully"

        with app.app_context():
            user = db.session.get(User, owner.id)
            assert user.mfa_enabled is True
            assert user.totp_secret == secret

    def test_mfa_enable_with_totp_code_field(self, client, owner, owner_token):
        """Enabling MFA accepts either 'code' or 'totp_code' in JSON body."""
        setup_res = client.post(
            "/api/auth/mfa/setup",
            headers={"Authorization": f"Bearer {owner_token}"},
        )
        secret = setup_res.get_json()["secret"]

        valid_code = pyotp.TOTP(secret).now()
        enable_res = client.post(
            "/api/auth/mfa/enable",
            json={"totp_code": valid_code},
            headers={"Authorization": f"Bearer {owner_token}"},
        )
        assert enable_res.status_code == 200
        assert enable_res.get_json()["mfa_enabled"] is True

    def test_mfa_enable_invalid_code_rejected(self, client, owner, owner_token, app, db):
        """Enabling MFA with an invalid code returns 400 and keeps mfa_enabled=False."""
        client.post(
            "/api/auth/mfa/setup",
            headers={"Authorization": f"Bearer {owner_token}"},
        )

        enable_res = client.post(
            "/api/auth/mfa/enable",
            json={"code": "000000"},
            headers={"Authorization": f"Bearer {owner_token}"},
        )
        assert enable_res.status_code == 400
        assert enable_res.get_json()["error"] == "Invalid verification code"

        with app.app_context():
            user = db.session.get(User, owner.id)
            assert user.mfa_enabled is False

    def test_mfa_enable_missing_code_rejected(self, client, owner_token):
        """Enabling MFA without supplying a code returns 400."""
        client.post(
            "/api/auth/mfa/setup",
            headers={"Authorization": f"Bearer {owner_token}"},
        )

        enable_res = client.post(
            "/api/auth/mfa/enable",
            json={},
            headers={"Authorization": f"Bearer {owner_token}"},
        )
        assert enable_res.status_code == 400
        assert enable_res.get_json()["error"] == "Verification code is required"

    def test_mfa_enable_without_setup_rejected(self, client, owner_token):
        """Attempting to enable MFA before running setup returns 400."""
        enable_res = client.post(
            "/api/auth/mfa/enable",
            json={"code": "123456"},
            headers={"Authorization": f"Bearer {owner_token}"},
        )
        assert enable_res.status_code == 400
        assert enable_res.get_json()["error"] == "MFA setup has not been initiated"

    def test_mfa_enable_when_already_enabled_rejected(self, client, owner, owner_token, app, db):
        """Attempting to enable MFA when already enabled returns 400."""
        with app.app_context():
            user = db.session.get(User, owner.id)
            user.mfa_enabled = True
            user.totp_secret = "JBSWY3DPEHPK3PXP"
            db.session.commit()

        enable_res = client.post(
            "/api/auth/mfa/enable",
            json={"code": "123456"},
            headers={"Authorization": f"Bearer {owner_token}"},
        )
        assert enable_res.status_code == 400
        assert enable_res.get_json()["error"] == "MFA is already enabled"

    def test_mfa_disable_wrong_password_rejected(self, client, owner, owner_token):
        """Disabling MFA with an incorrect password returns 401."""
        client.post("/api/auth/mfa/setup", headers={"Authorization": f"Bearer {owner_token}"})
        # Try disable with bad password
        res = client.post(
            "/api/auth/mfa/disable",
            json={"password": "WrongPassword123!"},
            headers={"Authorization": f"Bearer {owner_token}"},
        )
        assert res.status_code == 401
        assert res.get_json()["error"] == "Invalid password"

    def test_mfa_disable_missing_password_rejected(self, client, owner_token):
        """Disabling MFA without a password returns 400."""
        client.post("/api/auth/mfa/setup", headers={"Authorization": f"Bearer {owner_token}"})
        res = client.post(
            "/api/auth/mfa/disable",
            json={},
            headers={"Authorization": f"Bearer {owner_token}"},
        )
        assert res.status_code == 400
        assert res.get_json()["error"] == "Password is required"

    def test_mfa_disable_wrong_totp_rejected(self, client, owner, owner_token):
        """Disabling an active MFA account with an invalid TOTP code returns 401."""
        setup_res = client.post("/api/auth/mfa/setup", headers={"Authorization": f"Bearer {owner_token}"})
        secret = setup_res.get_json()["secret"]
        client.post(
            "/api/auth/mfa/enable",
            json={"code": pyotp.TOTP(secret).now()},
            headers={"Authorization": f"Bearer {owner_token}"},
        )

        res = client.post(
            "/api/auth/mfa/disable",
            json={"password": "Test1234!", "totp_code": "000000"},
            headers={"Authorization": f"Bearer {owner_token}"},
        )
        assert res.status_code == 401
        assert res.get_json()["error"] == "Invalid MFA code"

    def test_mfa_disable_missing_totp_when_enabled_rejected(self, client, owner, owner_token):
        """Disabling an active MFA account without a TOTP code returns 400."""
        setup_res = client.post("/api/auth/mfa/setup", headers={"Authorization": f"Bearer {owner_token}"})
        secret = setup_res.get_json()["secret"]
        client.post(
            "/api/auth/mfa/enable",
            json={"code": pyotp.TOTP(secret).now()},
            headers={"Authorization": f"Bearer {owner_token}"},
        )

        res = client.post(
            "/api/auth/mfa/disable",
            json={"password": "Test1234!"},
            headers={"Authorization": f"Bearer {owner_token}"},
        )
        assert res.status_code == 400
        assert res.get_json()["error"] == "TOTP code is required"

    def test_mfa_disable_happy_path(self, client, owner, owner_token, app, db):
        """Disabling MFA resets mfa_enabled to False and clears totp_secret."""
        setup_res = client.post("/api/auth/mfa/setup", headers={"Authorization": f"Bearer {owner_token}"})
        secret = setup_res.get_json()["secret"]
        client.post(
            "/api/auth/mfa/enable",
            json={"code": pyotp.TOTP(secret).now()},
            headers={"Authorization": f"Bearer {owner_token}"},
        )

        disable_res = client.post(
            "/api/auth/mfa/disable",
            json={"password": "Test1234!", "totp_code": pyotp.TOTP(secret).now()},
            headers={"Authorization": f"Bearer {owner_token}"},
        )
        assert disable_res.status_code == 200
        assert disable_res.get_json()["mfa_enabled"] is False

        with app.app_context():
            user = db.session.get(User, owner.id)
            assert user.mfa_enabled is False
            assert user.totp_secret is None

    def test_full_mfa_lifecycle_flow(self, client, owner, app, db):
        """
        Complete end-to-end integration test:
        1. Login without MFA succeeds.
        2. Setup MFA generates secret, login still succeeds without MFA.
        3. Enable MFA with TOTP code.
        4. Login without TOTP code fails.
        5. Login with wrong TOTP code fails.
        6. Login with valid TOTP code succeeds.
        7. Disable MFA with password + TOTP code.
        8. Login without TOTP code succeeds again.
        """
        # 1. Login without MFA
        res = client.post("/api/auth/login", json={"email": owner.email, "password": "Test1234!"})
        assert res.status_code == 200
        token = res.get_json()["access_token"]

        # 2. Setup MFA
        setup_res = client.post("/api/auth/mfa/setup", headers={"Authorization": f"Bearer {token}"})
        assert setup_res.status_code == 200
        secret = setup_res.get_json()["secret"]

        # Login still succeeds without MFA because it's only pending
        res_pending_login = client.post("/api/auth/login", json={"email": owner.email, "password": "Test1234!"})
        assert res_pending_login.status_code == 200

        # 3. Enable MFA
        code = pyotp.TOTP(secret).now()
        enable_res = client.post(
            "/api/auth/mfa/enable",
            json={"code": code},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert enable_res.status_code == 200
        assert enable_res.get_json()["mfa_enabled"] is True

        # 4. Login without TOTP code fails (401)
        res_no_totp = client.post("/api/auth/login", json={"email": owner.email, "password": "Test1234!"})
        assert res_no_totp.status_code == 401
        assert res_no_totp.get_json()["error"] == "Invalid MFA code"

        # 5. Login with wrong TOTP code fails (401)
        res_wrong_totp = client.post(
            "/api/auth/login",
            json={"email": owner.email, "password": "Test1234!", "totp_code": "000000"},
        )
        assert res_wrong_totp.status_code == 401
        assert res_wrong_totp.get_json()["error"] == "Invalid MFA code"

        # 6. Login with valid TOTP code succeeds (200)
        valid_totp = pyotp.TOTP(secret).now()
        res_valid_totp = client.post(
            "/api/auth/login",
            json={"email": owner.email, "password": "Test1234!", "totp_code": valid_totp},
        )
        assert res_valid_totp.status_code == 200
        new_token = res_valid_totp.get_json()["access_token"]

        # 7. Disable MFA
        disable_totp = pyotp.TOTP(secret).now()
        disable_res = client.post(
            "/api/auth/mfa/disable",
            json={"password": "Test1234!", "totp_code": disable_totp},
            headers={"Authorization": f"Bearer {new_token}"},
        )
        assert disable_res.status_code == 200
        assert disable_res.get_json()["mfa_enabled"] is False

        # 8. Login without TOTP code succeeds again
        final_login = client.post("/api/auth/login", json={"email": owner.email, "password": "Test1234!"})
        assert final_login.status_code == 200


class TestUserProfileAndChangePassword:
    """Tests for GET /api/auth/me and POST /api/auth/change-password."""

    def test_get_me_profile_success(self, client, owner, owner_token):
        """GET /api/auth/me returns the current user profile, mfa_enabled, and last_login."""
        res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {owner_token}"})
        assert res.status_code == 200
        data = res.get_json()
        assert "user" in data
        user = data["user"]
        assert user["id"] == str(owner.id)
        assert user["username"] == owner.username
        assert user["email"] == owner.email
        assert user["mfa_enabled"] is False
        assert "last_login" in user

    def test_get_me_unauthorized_rejected(self, client):
        """GET /api/auth/me without a Bearer token returns 401."""
        res = client.get("/api/auth/me")
        assert res.status_code == 401
        assert res.get_json()["error"] == "Missing authentication token"

    def test_change_password_success(self, client, owner, owner_token):
        """Authenticated user can change password with correct current password and valid new password."""
        res = client.post(
            "/api/auth/change-password",
            json={
                "current_password": "Test1234!",
                "new_password": "BrandNewPassword123!",
            },
            headers={"Authorization": f"Bearer {owner_token}"},
        )
        assert res.status_code == 200
        assert res.get_json()["message"] == "Password changed successfully"

        # Old password no longer works
        old_login = client.post(
            "/api/auth/login",
            json={"email": owner.email, "password": "Test1234!"},
        )
        assert old_login.status_code == 401
        assert old_login.get_json()["error"] == "Invalid credentials"

        # New password works
        new_login = client.post(
            "/api/auth/login",
            json={"email": owner.email, "password": "BrandNewPassword123!"},
        )
        assert new_login.status_code == 200
        assert "access_token" in new_login.get_json()

    def test_change_password_wrong_current_password_rejected(self, client, owner_token):
        """POST /api/auth/change-password with invalid current password returns 401."""
        res = client.post(
            "/api/auth/change-password",
            json={
                "current_password": "WrongPassword999!",
                "new_password": "BrandNewPassword123!",
            },
            headers={"Authorization": f"Bearer {owner_token}"},
        )
        assert res.status_code == 401
        assert res.get_json()["error"] == "Invalid current password"

    def test_change_password_missing_fields_rejected(self, client, owner_token):
        """POST /api/auth/change-password with missing fields returns 400."""
        # Missing new_password
        res1 = client.post(
            "/api/auth/change-password",
            json={"current_password": "Test1234!"},
            headers={"Authorization": f"Bearer {owner_token}"},
        )
        assert res1.status_code == 400
        assert "required" in res1.get_json()["error"]

        # Missing current_password
        res2 = client.post(
            "/api/auth/change-password",
            json={"new_password": "BrandNewPassword123!"},
            headers={"Authorization": f"Bearer {owner_token}"},
        )
        assert res2.status_code == 400
        assert "required" in res2.get_json()["error"]

        # Empty body
        res3 = client.post(
            "/api/auth/change-password",
            json={},
            headers={"Authorization": f"Bearer {owner_token}"},
        )
        assert res3.status_code == 400
        assert "required" in res3.get_json()["error"]

    def test_change_password_short_password_rejected(self, client, owner_token):
        """New password shorter than 8 characters is rejected with 400."""
        res = client.post(
            "/api/auth/change-password",
            json={
                "current_password": "Test1234!",
                "new_password": "short",
            },
            headers={"Authorization": f"Bearer {owner_token}"},
        )
        assert res.status_code == 400
        assert "at least 8 characters" in res.get_json()["error"]

    def test_change_password_same_password_rejected(self, client, owner_token):
        """New password matching current password is rejected with 400."""
        res = client.post(
            "/api/auth/change-password",
            json={
                "current_password": "Test1234!",
                "new_password": "Test1234!",
            },
            headers={"Authorization": f"Bearer {owner_token}"},
        )
        assert res.status_code == 400
        assert "different" in res.get_json()["error"]

    def test_change_password_unauthorized_rejected(self, client):
        """POST /api/auth/change-password without a Bearer token returns 401."""
        res = client.post(
            "/api/auth/change-password",
            json={
                "current_password": "Test1234!",
                "new_password": "BrandNewPassword123!",
            },
        )
        assert res.status_code == 401
        assert res.get_json()["error"] == "Missing authentication token"

