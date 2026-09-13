"""
Tests for WebAuthn passkey authentication.

Covers:
- POST /api/auth/webauthn/register/start: returns creation options for logged-in user.
- POST /api/auth/webauthn/register/finish: verifies registration and stores WebAuthnCredential.
- POST /api/auth/webauthn/login/start: returns authentication options (public, discoverable or scoped).
- POST /api/auth/webauthn/login/finish: verifies authentication, updates sign_count, returns JWT token.
- Passkey not recognized returns 404.
- Disabled account passkey login returns 403.
- Unauthenticated registration attempts return 401.
- Duplicate credential registration returns 409.
- Existing password login remains fully functional for users with passkeys (additive).
"""

import base64
from unittest.mock import patch, MagicMock
import pytest

from app.extensions import db
from app.models.user import User
from app.models.webauthn_credential import WebAuthnCredential
from webauthn.registration.verify_registration_response import VerifiedRegistration
from webauthn.authentication.verify_authentication_response import VerifiedAuthentication


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


class TestWebAuthnRegistration:
    """Test suite for WebAuthn registration endpoints."""

    def test_register_start_success(self, client, owner, owner_token):
        """Authenticated user can initiate passkey registration and receive options."""
        res = client.post(
            "/api/auth/webauthn/register/start",
            headers=auth_header(owner_token),
            json={"nickname": "YubiKey 5C"},
        )
        assert res.status_code == 200
        data = res.get_json()

        assert "options" in data
        assert "challenge" in data
        options = data["options"]
        assert options["rp"]["name"] == "Secure File Share"
        assert options["user"]["name"] == owner.username

    def test_register_start_unauthenticated_rejected(self, client):
        """Unauthenticated call to register/start is rejected with 401."""
        res = client.post("/api/auth/webauthn/register/start")
        assert res.status_code == 401

    @patch("app.auth.routes.verify_registration_response")
    def test_register_finish_success(self, mock_verify_reg, client, owner, owner_token, app):
        """Registration finish successfully verifies and stores WebAuthnCredential."""
        cred_id = b"credential_id_sample_bytes_123"
        pub_key = b"sample_public_key_bytes_456"

        mock_verify_reg.return_value = MagicMock(
            credential_id=cred_id,
            credential_public_key=pub_key,
            sign_count=0,
        )

        b64_challenge = base64.urlsafe_b64encode(b"test_challenge_16_bytes!").decode("utf-8").rstrip("=")

        payload = {
            "credential": {
                "id": base64.urlsafe_b64encode(cred_id).decode("utf-8").rstrip("="),
                "rawId": base64.urlsafe_b64encode(cred_id).decode("utf-8").rstrip("="),
                "response": {
                    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0",
                    "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG1rgA",
                },
                "type": "public-key",
            },
            "challenge": b64_challenge,
            "nickname": "MacBook Touch ID",
        }

        res = client.post(
            "/api/auth/webauthn/register/finish",
            headers=auth_header(owner_token),
            json=payload,
        )
        assert res.status_code == 201
        data = res.get_json()
        assert data["message"] == "Passkey registered successfully"
        assert data["credential"]["nickname"] == "MacBook Touch ID"

        # Verify in database
        with app.app_context():
            stored = WebAuthnCredential.query.filter_by(credential_id=cred_id).first()
            assert stored is not None
            assert stored.user_id == owner.id
            assert stored.public_key == pub_key
            assert stored.sign_count == 0

    @patch("app.auth.routes.verify_registration_response")
    def test_register_finish_duplicate_credential_rejected(
        self, mock_verify_reg, client, owner, owner_token, app
    ):
        """Attempting to register an already existing credential ID returns 409 Conflict."""
        dup_cred_id = b"duplicate_cred_id_789"
        with app.app_context():
            existing = WebAuthnCredential(
                user_id=owner.id,
                credential_id=dup_cred_id,
                public_key=b"pub_key",
                nickname="Primary",
            )
            db.session.add(existing)
            db.session.commit()

        mock_verify_reg.return_value = MagicMock(
            credential_id=dup_cred_id,
            credential_public_key=b"pub_key_2",
            sign_count=0,
        )

        b64_challenge = base64.urlsafe_b64encode(b"test_challenge_bytes_12").decode("utf-8").rstrip("=")
        payload = {
            "credential": {"id": "dummy", "rawId": "dummy"},
            "challenge": b64_challenge,
        }

        res = client.post(
            "/api/auth/webauthn/register/finish",
            headers=auth_header(owner_token),
            json=payload,
        )
        assert res.status_code == 409
        assert "already registered" in res.get_json()["error"].lower()


class TestWebAuthnAuthentication:
    """Test suite for WebAuthn authentication (passkey login) endpoints."""

    def test_login_start_public_and_discoverable(self, client):
        """Public call to login/start without user returns options for discoverable passkeys."""
        res = client.post("/api/auth/webauthn/login/start", json={})
        assert res.status_code == 200
        data = res.get_json()
        assert "options" in data
        assert "challenge" in data

    def test_login_start_scoped_to_user_credentials(self, client, owner, app):
        """When email or username is provided, login/start scopes allowCredentials."""
        cred_id = b"user_specific_cred_id_321"
        with app.app_context():
            cred = WebAuthnCredential(
                user_id=owner.id,
                credential_id=cred_id,
                public_key=b"public_key_321",
                nickname="Work Passkey",
            )
            db.session.add(cred)
            db.session.commit()

        res = client.post(
            "/api/auth/webauthn/login/start",
            json={"email": owner.email},
        )
        assert res.status_code == 200
        data = res.get_json()
        options = data["options"]
        assert "allowCredentials" in options
        assert len(options["allowCredentials"]) == 1

    @patch("app.auth.routes.verify_authentication_response")
    def test_login_finish_success(self, mock_verify_auth, client, owner, app):
        """Successful passkey login issues JWT token and updates sign_count."""
        cred_id = b"login_test_credential_id"
        pub_key = b"login_test_public_key"

        with app.app_context():
            cred = WebAuthnCredential(
                user_id=owner.id,
                credential_id=cred_id,
                public_key=pub_key,
                sign_count=10,
                nickname="Home Laptop",
            )
            db.session.add(cred)
            db.session.commit()

        mock_verify_auth.return_value = MagicMock(
            credential_id=cred_id,
            new_sign_count=11,
        )

        b64_cred_id = base64.urlsafe_b64encode(cred_id).decode("utf-8").rstrip("=")
        b64_challenge = base64.urlsafe_b64encode(b"sample_auth_challenge_bytes").decode("utf-8").rstrip("=")

        payload = {
            "credential": {
                "id": b64_cred_id,
                "rawId": b64_cred_id,
                "response": {
                    "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAIA",
                    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
                    "signature": "MEQCIBY8kQ4w...",
                },
                "type": "public-key",
            },
            "challenge": b64_challenge,
        }

        res = client.post("/api/auth/webauthn/login/finish", json=payload)
        assert res.status_code == 200
        data = res.get_json()

        assert "access_token" in data
        assert data["user"]["id"] == str(owner.id)

        # Confirm sign_count and last_login updated
        with app.app_context():
            updated_cred = WebAuthnCredential.query.filter_by(credential_id=cred_id).first()
            assert updated_cred.sign_count == 11
            updated_user = db.session.get(User, owner.id)
            assert updated_user.last_login is not None

    def test_login_finish_unrecognized_passkey_returns_404(self, client):
        """When an unknown passkey credential ID is presented, returns 404."""
        unknown_id = base64.urlsafe_b64encode(b"completely_unknown_credential").decode("utf-8").rstrip("=")
        b64_challenge = base64.urlsafe_b64encode(b"any_challenge").decode("utf-8").rstrip("=")

        payload = {
            "credential": {"id": unknown_id, "rawId": unknown_id},
            "challenge": b64_challenge,
        }
        res = client.post("/api/auth/webauthn/login/finish", json=payload)
        assert res.status_code == 404
        assert "not recognized" in res.get_json()["error"].lower()

    @patch("app.auth.routes.verify_authentication_response")
    def test_login_finish_disabled_user_rejected(self, mock_verify_auth, client, app):
        """Passkey login for a disabled user account is rejected with 403."""
        cred_id = b"disabled_user_cred_id"
        with app.app_context():
            disabled_user = User(
                username="disabled_passkey_user",
                email="disabled_passkey@example.com",
                is_active=False,
            )
            db.session.add(disabled_user)
            db.session.flush()

            cred = WebAuthnCredential(
                user_id=disabled_user.id,
                credential_id=cred_id,
                public_key=b"public_key_disabled",
            )
            db.session.add(cred)
            db.session.commit()

        b64_cred_id = base64.urlsafe_b64encode(cred_id).decode("utf-8").rstrip("=")
        payload = {
            "credential": {"id": b64_cred_id, "rawId": b64_cred_id},
            "challenge": "dummy_challenge",
        }
        res = client.post("/api/auth/webauthn/login/finish", json=payload)
        assert res.status_code == 403
        assert "disabled" in res.get_json()["error"].lower()

    def test_existing_password_login_works_for_passkey_user(self, client, owner, app):
        """Users with passkeys can still log in using their password (additive)."""
        with app.app_context():
            cred = WebAuthnCredential(
                user_id=owner.id,
                credential_id=b"existing_passkey_123",
                public_key=b"existing_pubkey_123",
            )
            db.session.add(cred)
            db.session.commit()

        # Regular password login must work
        res = client.post(
            "/api/auth/login",
            json={"email": owner.email, "password": "Test1234!"},
        )
        assert res.status_code == 200
        assert "access_token" in res.get_json()
