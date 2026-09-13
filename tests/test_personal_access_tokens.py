"""
Tests for Personal Access Tokens (PAT):
- Creation, hashing, and raw token single-display
- Listing and user isolation
- Authentication on protected endpoints with Bearer pat_<token>
- Tracking last_used_at
- Expiration enforcement
- Revocation and access invalidation
"""

import uuid
import datetime
import pytest
from app.models import User, PersonalAccessToken
from app.auth.decorators import generate_access_token


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


class TestPersonalAccessTokenCreation:
    """Tests for POST /api/auth/tokens."""

    def test_create_pat_success(self, app, client, db, owner, owner_token):
        """User can create a PAT; raw token is returned once and starts with pat_."""
        res = client.post(
            "/api/auth/tokens",
            json={"name": "CLI Script Token"},
            headers=auth_header(owner_token),
        )
        assert res.status_code == 201
        data = res.get_json()
        assert data["message"] == "Personal access token created successfully"
        assert "raw_token" in data
        raw_token = data["raw_token"]
        assert raw_token.startswith("pat_")

        # Metadata dictionary checks
        tok = data["token"]
        assert tok["name"] == "CLI Script Token"
        assert tok["user_id"] == str(owner.id)
        assert tok["is_expired"] is False
        assert tok["last_used_at"] is None
        # Must never expose hash or raw token in to_dict()
        assert "token_hash" not in tok
        assert "raw_token" not in tok

        # Verify DB entry
        with app.app_context():
            pat = db.session.get(PersonalAccessToken, uuid.UUID(tok["id"]))
            assert pat is not None
            assert pat.name == "CLI Script Token"
            assert pat.token_hash == PersonalAccessToken.hash_token(raw_token)
            assert pat.expires_at is None

    def test_create_pat_with_expiry(self, app, client, db, owner, owner_token):
        """User can specify expires_in_days to set token expiration."""
        res = client.post(
            "/api/auth/tokens",
            json={"name": "Temporary Token", "expires_in_days": 14},
            headers=auth_header(owner_token),
        )
        assert res.status_code == 201
        data = res.get_json()
        assert data["token"]["expires_at"] is not None

        with app.app_context():
            pat = db.session.get(PersonalAccessToken, uuid.UUID(data["token"]["id"]))
            assert pat.expires_at is not None
            # Approximately 14 days in future
            exp = pat.expires_at if pat.expires_at.tzinfo else pat.expires_at.replace(tzinfo=datetime.timezone.utc)
            diff = exp - datetime.datetime.now(datetime.timezone.utc)
            assert 13 <= diff.days <= 14

    def test_create_pat_validation_error(self, client, owner_token):
        """Empty name or negative expires_in_days is rejected with 400."""
        # Missing name
        res1 = client.post(
            "/api/auth/tokens",
            json={},
            headers=auth_header(owner_token),
        )
        assert res1.status_code == 400
        assert "name is required" in res1.get_json()["error"]

        # Blank name
        res2 = client.post(
            "/api/auth/tokens",
            json={"name": "   "},
            headers=auth_header(owner_token),
        )
        assert res2.status_code == 400

        # Negative expires_in_days
        res3 = client.post(
            "/api/auth/tokens",
            json={"name": "Valid", "expires_in_days": -5},
            headers=auth_header(owner_token),
        )
        assert res3.status_code == 400


class TestPersonalAccessTokenListing:
    """Tests for GET /api/auth/tokens."""

    def test_list_pats_success(self, client, owner_token):
        """GET /api/auth/tokens lists all tokens for the user without raw tokens or hashes."""
        # Create two tokens
        client.post(
            "/api/auth/tokens",
            json={"name": "Token 1"},
            headers=auth_header(owner_token),
        )
        client.post(
            "/api/auth/tokens",
            json={"name": "Token 2"},
            headers=auth_header(owner_token),
        )

        res = client.get("/api/auth/tokens", headers=auth_header(owner_token))
        assert res.status_code == 200
        tokens = res.get_json()["tokens"]
        assert len(tokens) >= 2
        # Verify no sensitive fields
        for t in tokens:
            assert "token_hash" not in t
            assert "raw_token" not in t
            assert "id" in t
            assert "name" in t

    def test_list_pats_user_isolation(self, client, owner_token, recipient_token):
        """Users can only view their own personal access tokens."""
        client.post(
            "/api/auth/tokens",
            json={"name": "Owner Secret Token"},
            headers=auth_header(owner_token),
        )

        res = client.get("/api/auth/tokens", headers=auth_header(recipient_token))
        assert res.status_code == 200
        assert len(res.get_json()["tokens"]) == 0


class TestPersonalAccessTokenAuthentication:
    """Tests authenticating against API endpoints using Authorization: Bearer pat_<token>."""

    def test_authenticate_with_pat_on_auth_me(self, client, owner, owner_token):
        """A user can call GET /api/auth/me using their PAT."""
        create_res = client.post(
            "/api/auth/tokens",
            json={"name": "Auth Me Test"},
            headers=auth_header(owner_token),
        )
        raw_token = create_res.get_json()["raw_token"]

        # Call /api/auth/me using PAT
        me_res = client.get("/api/auth/me", headers=auth_header(raw_token))
        assert me_res.status_code == 200
        data = me_res.get_json()
        assert data["user"]["id"] == str(owner.id)
        assert data["user"]["username"] == owner.username

    def test_authenticate_with_pat_on_files(self, client, owner, owner_token):
        """A user can list files using their PAT."""
        create_res = client.post(
            "/api/auth/tokens",
            json={"name": "Files List Test"},
            headers=auth_header(owner_token),
        )
        raw_token = create_res.get_json()["raw_token"]

        files_res = client.get("/api/files", headers=auth_header(raw_token))
        assert files_res.status_code == 200
        assert "files" in files_res.get_json()

    def test_pat_updates_last_used_at(self, app, client, db, owner_token):
        """Using a PAT updates its last_used_at timestamp in the database."""
        create_res = client.post(
            "/api/auth/tokens",
            json={"name": "Last Used Test"},
            headers=auth_header(owner_token),
        )
        raw_token = create_res.get_json()["raw_token"]
        token_id = uuid.UUID(create_res.get_json()["token"]["id"])

        with app.app_context():
            pat = db.session.get(PersonalAccessToken, token_id)
            assert pat.last_used_at is None

        # Authenticate with PAT
        client.get("/api/auth/me", headers=auth_header(raw_token))

        with app.app_context():
            pat = db.session.get(PersonalAccessToken, token_id)
            assert pat.last_used_at is not None

    def test_expired_pat_rejected(self, app, client, db, owner):
        """An expired PAT is rejected with 401 Token has expired."""
        raw_token = "pat_expired_test_token_string_123456"
        token_hash = PersonalAccessToken.hash_token(raw_token)

        with app.app_context():
            past_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
            pat = PersonalAccessToken(
                user_id=owner.id,
                name="Already Expired",
                token_hash=token_hash,
                expires_at=past_time,
            )
            db.session.add(pat)
            db.session.commit()

        res = client.get("/api/auth/me", headers=auth_header(raw_token))
        assert res.status_code == 401
        assert res.get_json()["error"] == "Token has expired"

    def test_tampered_or_invalid_pat_rejected(self, client):
        """A nonexistent or invalid pat_ token is rejected with 401 Invalid token."""
        res = client.get("/api/auth/me", headers=auth_header("pat_nonexistent_random_token_9999"))
        assert res.status_code == 401
        assert res.get_json()["error"] == "Invalid token"


class TestPersonalAccessTokenRevocation:
    """Tests for DELETE /api/auth/tokens/<id>."""

    def test_revoke_pat_success(self, client, owner_token):
        """Revoking a PAT deletes it and prevents any future authentication with it."""
        create_res = client.post(
            "/api/auth/tokens",
            json={"name": "Token to Revoke"},
            headers=auth_header(owner_token),
        )
        raw_token = create_res.get_json()["raw_token"]
        token_id = create_res.get_json()["token"]["id"]

        # Confirm PAT works
        ok_res = client.get("/api/auth/me", headers=auth_header(raw_token))
        assert ok_res.status_code == 200

        # Revoke PAT
        del_res = client.delete(f"/api/auth/tokens/{token_id}", headers=auth_header(owner_token))
        assert del_res.status_code == 200
        assert del_res.get_json()["message"] == "Token revoked successfully"

        # Subsequent use fails with 401 Invalid token
        revoked_res = client.get("/api/auth/me", headers=auth_header(raw_token))
        assert revoked_res.status_code == 401
        assert revoked_res.get_json()["error"] == "Invalid token"

    def test_revoke_pat_forbidden_for_other_user(self, client, owner_token, recipient_token):
        """A user cannot revoke another user's PAT."""
        create_res = client.post(
            "/api/auth/tokens",
            json={"name": "Owner Token"},
            headers=auth_header(owner_token),
        )
        token_id = create_res.get_json()["token"]["id"]

        res = client.delete(f"/api/auth/tokens/{token_id}", headers=auth_header(recipient_token))
        assert res.status_code == 403
        assert "Forbidden" in res.get_json()["error"]

    def test_revoke_pat_not_found(self, client, owner_token):
        """Attempting to revoke a nonexistent token returns 404."""
        random_id = uuid.uuid4()
        res = client.delete(f"/api/auth/tokens/{random_id}", headers=auth_header(owner_token))
        assert res.status_code == 404
        assert res.get_json()["error"] == "Token not found"
