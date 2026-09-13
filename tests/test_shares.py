"""
Unit tests for Module 4: Access Control & Secure File Sharing.

Covers:
- Permission enforcement (view / download / edit / reshare)
- Expiry enforcement
- Password verification + rate limiting
- Revocation
- QR code generation
"""

import datetime
import uuid
import pytest
from app.extensions import db
from app.models import Share, File, AccessLog
from app.crypto.file_crypto import encrypt_file


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def create_share(client, file_id, owner_token, body):
    return client.post(
        f"/api/files/{file_id}/share",
        json=body,
        headers=auth_header(owner_token),
    )


# ---------------------------------------------------------------------------
# 1. Create share & basic access
# ---------------------------------------------------------------------------

class TestCreateShare:
    def test_create_open_share(self, client, shared_file, owner_token):
        res = create_share(client, shared_file.id, owner_token, {
            "permissions": {"can_view": True, "can_download": False},
        })
        assert res.status_code == 201
        data = res.get_json()
        assert len(data["shares"]) == 1
        share = data["shares"][0]
        assert share["can_view"] is True
        assert share["can_download"] is False
        assert "share_token" in share
        assert len(share["share_token"]) >= 40  # urlsafe base64 of 32 bytes

    def test_create_share_for_recipient(self, client, shared_file, owner_token, recipient):
        res = create_share(client, shared_file.id, owner_token, {
            "recipient_ids": [str(recipient.id)],
            "permissions": {"can_view": True, "can_download": True},
        })
        assert res.status_code == 201
        share = res.get_json()["shares"][0]
        assert share["recipient_id"] == str(recipient.id)

    def test_non_owner_cannot_create_share(self, client, shared_file, recipient_token):
        res = create_share(client, shared_file.id, recipient_token, {
            "permissions": {"can_view": True},
        })
        assert res.status_code == 404  # owner check returns 404 to avoid enumeration

    def test_invalid_file_returns_404(self, client, owner_token):
        import uuid
        res = create_share(client, uuid.uuid4(), owner_token, {
            "permissions": {"can_view": True},
        })
        assert res.status_code == 404


# ---------------------------------------------------------------------------
# 2. Permission enforcement
# ---------------------------------------------------------------------------

class TestPermissions:
    @pytest.fixture(autouse=True)
    def _setup(self, client, shared_file, owner_token):
        # Create a view-only share
        res = create_share(client, shared_file.id, owner_token, {
            "permissions": {
                "can_view": True,
                "can_download": False,
                "can_edit": False,
                "can_reshare": False,
            },
        })
        assert res.status_code == 201
        self.token = res.get_json()["shares"][0]["share_token"]

    def test_view_allowed(self, client):
        res = client.get(f"/api/shares/{self.token}/access")
        assert res.status_code == 200
        perms = res.get_json()["permissions"]
        assert perms["can_view"] is True

    def test_download_blocked(self, client):
        res = client.get(f"/api/shares/{self.token}/download")
        assert res.status_code == 403

    def test_permissions_in_metadata(self, client):
        data = client.get(f"/api/shares/{self.token}/access").get_json()
        assert data["permissions"]["can_download"] is False
        assert data["permissions"]["can_edit"] is False
        assert data["permissions"]["can_reshare"] is False


# ---------------------------------------------------------------------------
# 3. Expiry enforcement
# ---------------------------------------------------------------------------

class TestExpiry:
    def test_expired_share_rejected(self, client, shared_file, owner_token):
        past = (
            datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(seconds=1)
        ).isoformat()
        res = create_share(client, shared_file.id, owner_token, {
            "permissions": {"can_view": True},
            "expires_at": past,
        })
        assert res.status_code == 201
        token = res.get_json()["shares"][0]["share_token"]

        res2 = client.get(f"/api/shares/{token}/access")
        assert res2.status_code == 410
        assert "expired" in res2.get_json()["error"]

    def test_valid_expiry_allows_access(self, client, shared_file, owner_token):
        future = (
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(hours=1)
        ).isoformat()
        res = create_share(client, shared_file.id, owner_token, {
            "permissions": {"can_view": True},
            "expires_at": future,
        })
        token = res.get_json()["shares"][0]["share_token"]
        res2 = client.get(f"/api/shares/{token}/access")
        assert res2.status_code == 200


# ---------------------------------------------------------------------------
# 4. Password verification
# ---------------------------------------------------------------------------

class TestPasswordProtection:
    @pytest.fixture(autouse=True)
    def _setup(self, client, shared_file, owner_token):
        res = create_share(client, shared_file.id, owner_token, {
            "permissions": {"can_view": True, "can_download": True},
            "password": "s3cur3P@ss",
        })
        assert res.status_code == 201
        self.token = res.get_json()["shares"][0]["share_token"]

    def test_access_without_password_blocked(self, client):
        res = client.get(f"/api/shares/{self.token}/access")
        assert res.status_code == 401
        assert res.get_json().get("password_protected") is True

    def test_wrong_password_rejected(self, client):
        res = client.post(
            f"/api/shares/{self.token}/verify-password",
            json={"password": "wrongpass"},
        )
        assert res.status_code == 403

    def test_correct_password_issues_grant(self, client):
        res = client.post(
            f"/api/shares/{self.token}/verify-password",
            json={"password": "s3cur3P@ss"},
        )
        assert res.status_code == 200
        assert "grant_token" in res.get_json()

    def test_grant_allows_access(self, client):
        grant = client.post(
            f"/api/shares/{self.token}/verify-password",
            json={"password": "s3cur3P@ss"},
        ).get_json()["grant_token"]

        res = client.get(
            f"/api/shares/{self.token}/access",
            headers={"X-Share-Grant": grant},
        )
        assert res.status_code == 200

    def test_tampered_grant_rejected(self, client):
        res = client.get(
            f"/api/shares/{self.token}/access",
            headers={"X-Share-Grant": "totally.fake.token"},
        )
        assert res.status_code == 401


# ---------------------------------------------------------------------------
# 5. Revocation
# ---------------------------------------------------------------------------

class TestRevocation:
    def test_revoked_share_rejected(self, client, shared_file, owner_token):
        res = create_share(client, shared_file.id, owner_token, {
            "permissions": {"can_view": True},
        })
        share = res.get_json()["shares"][0]
        token = share["share_token"]
        share_id = share["id"]

        # Revoke via PATCH
        patch = client.patch(
            f"/api/shares/{share_id}",
            json={"is_revoked": True},
            headers=auth_header(owner_token),
        )
        assert patch.status_code == 200

        access = client.get(f"/api/shares/{token}/access")
        assert access.status_code == 410
        assert "revoked" in access.get_json()["error"]

    def test_delete_endpoint_revokes(self, client, shared_file, owner_token):
        res = create_share(client, shared_file.id, owner_token, {
            "permissions": {"can_view": True},
        })
        share = res.get_json()["shares"][0]
        token = share["share_token"]
        share_id = share["id"]

        delete = client.delete(
            f"/api/shares/{share_id}",
            headers=auth_header(owner_token),
        )
        assert delete.status_code == 200

        access = client.get(f"/api/shares/{token}/access")
        assert access.status_code == 410

    def test_non_owner_cannot_revoke(self, client, shared_file, owner_token, recipient_token):
        res = create_share(client, shared_file.id, owner_token, {
            "permissions": {"can_view": True},
        })
        share_id = res.get_json()["shares"][0]["id"]

        patch = client.patch(
            f"/api/shares/{share_id}",
            json={"is_revoked": True},
            headers=auth_header(recipient_token),
        )
        assert patch.status_code == 403

    def test_disabled_owner_share_rejected(self, app, client, shared_file, owner_token, owner):
        """
        When the share's owner account is disabled, the share link must be
        treated as invalid, returning 410 on access and download.
        """
        res = create_share(client, shared_file.id, owner_token, {
            "permissions": {"can_view": True, "can_download": True},
        })
        token = res.get_json()["shares"][0]["share_token"]

        # Accessible while owner is active
        ok = client.get(f"/api/shares/{token}/access")
        assert ok.status_code == 200

        # Disable the owner's account
        with app.app_context():
            from app.models import User
            user = db.session.get(User, owner.id)
            user.is_active = False
            db.session.commit()

        # Access should now be rejected with 410
        access = client.get(f"/api/shares/{token}/access")
        assert access.status_code == 410
        assert "disabled" in access.get_json()["error"]

        # Download should also be rejected with 410
        download = client.get(f"/api/shares/{token}/download")
        assert download.status_code == 410
        assert "disabled" in download.get_json()["error"]


# ---------------------------------------------------------------------------
# 6. QR code
# ---------------------------------------------------------------------------

class TestQRCode:
    def test_qrcode_returns_png(self, client, shared_file, owner_token):
        res = create_share(client, shared_file.id, owner_token, {
            "permissions": {"can_view": True},
        })
        token = res.get_json()["shares"][0]["share_token"]

        qr = client.get(f"/api/shares/{token}/qrcode")
        assert qr.status_code == 200
        assert qr.content_type == "image/png"
        # PNG magic bytes
        assert qr.data[:4] == b"\x89PNG"


# ---------------------------------------------------------------------------
# 7. Audit log
# ---------------------------------------------------------------------------

class TestAuditLog:
    def test_access_creates_log(self, app, client, shared_file, owner_token):
        res = create_share(client, shared_file.id, owner_token, {
            "permissions": {"can_view": True},
        })
        token = res.get_json()["shares"][0]["share_token"]
        share_id = res.get_json()["shares"][0]["id"]

        client.get(f"/api/shares/{token}/access")

        with app.app_context():
            from app.models import Share as S, AccessLog
            import uuid
            logs = AccessLog.query.filter_by(share_id=uuid.UUID(share_id)).all()
            assert len(logs) >= 1
            assert logs[-1].action == "view"
            assert logs[-1].success is True


# ---------------------------------------------------------------------------
# 8. Content-Disposition & Filename Sanitization Security
# ---------------------------------------------------------------------------

class TestContentDispositionSecurity:
    def test_upload_malicious_filename_sanitized_and_safe_header(self, client, owner_token):
        """
        Uploading a file with quotes, CRLF, and header injection attempts
        must have its filename sanitized, preventing header splitting and malformed
        Content-Disposition headers on download.
        """
        import io
        evil_filename = 'evil".pdf\r\nX-Injected: 1'
        file_content = b"%PDF-1.4 malicious content"

        # 1. Upload the file with the malicious filename
        upload_res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(file_content), evil_filename)},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        assert upload_res.status_code == 201
        file_data = upload_res.get_json()["file"]
        file_id = file_data["id"]
        stored_filename = file_data["filename"]

        # Ensure the filename stored in the database has no quotes or CRLF
        assert "\r" not in stored_filename
        assert "\n" not in stored_filename
        assert '"' not in stored_filename
        assert stored_filename in ("evil", "evil.pdf_X-Injected_1")

        # 2. Create a share with download permission
        share_res = create_share(client, file_id, owner_token, {
            "permissions": {"can_view": True, "can_download": True},
        })
        assert share_res.status_code == 201
        token = share_res.get_json()["shares"][0]["share_token"]

        # 3. Download the share and inspect Content-Disposition
        dl_res = client.get(f"/api/shares/{token}/download")
        assert dl_res.status_code == 200
        assert dl_res.data == file_content

        cd_header = dl_res.headers.get("Content-Disposition", "")
        # Confirm header has standard attachment type, safe filename, and RFC 5987 filename*
        assert "attachment;" in cd_header
        assert f'filename="{stored_filename}"' in cd_header
        assert f"filename*=UTF-8''{stored_filename}" in cd_header

        # Ensure no CRLF injection occurred and no injected header exists
        assert "\r" not in cd_header
        assert "\n" not in cd_header
        assert "X-Injected" not in dl_res.headers

    def test_download_share_with_injected_filename_in_db(self, app, client, db, owner, owner_token):
        """
        Even if a raw malicious filename exists in the database (legacy or bypassed),
        download_share must sanitize the ASCII fallback and RFC 5987 percent-encode
        all quotes and CRLF characters to prevent HTTP response splitting.
        """
        from tests.conftest import make_file
        with app.app_context():
            f = make_file(app, db.session, owner)
            f.filename = 'evil".pdf\r\nX-Injected: 1'
            db.session.commit()
            file_id = str(f.id)

        share_res = create_share(client, file_id, owner_token, {
            "permissions": {"can_view": True, "can_download": True},
        })
        assert share_res.status_code == 201
        token = share_res.get_json()["shares"][0]["share_token"]

        dl_res = client.get(f"/api/shares/{token}/download")
        assert dl_res.status_code == 200

        cd_header = dl_res.headers.get("Content-Disposition", "")
        assert 'filename="evil.pdf_X-Injected_1"' in cd_header
        assert "filename*=UTF-8''evil%22.pdf%0D%0AX-Injected%3A%201" in cd_header
        assert "\r" not in cd_header
        assert "\n" not in cd_header
        assert "X-Injected" not in dl_res.headers

    def test_download_share_with_non_ascii_filename_rfc5987(self, app, client, db, owner, owner_token):
        """
        Files with non-ASCII filenames should produce both an ASCII fallback
        filename and an RFC 5987 encoded filename* parameter.
        """
        from tests.conftest import make_file
        with app.app_context():
            f = make_file(app, db.session, owner)
            f.filename = "rapport_été_2026.pdf"
            db.session.commit()
            file_id = str(f.id)

        share_res = create_share(client, file_id, owner_token, {
            "permissions": {"can_view": True, "can_download": True},
        })
        assert share_res.status_code == 201
        token = share_res.get_json()["shares"][0]["share_token"]

        dl_res = client.get(f"/api/shares/{token}/download")
        assert dl_res.status_code == 200

        cd_header = dl_res.headers.get("Content-Disposition", "")
        assert 'filename="rapport_ete_2026.pdf"' in cd_header
        assert "filename*=UTF-8''rapport_%C3%A9t%C3%A9_2026.pdf" in cd_header
        assert "\r" not in cd_header
        assert "\n" not in cd_header


# ---------------------------------------------------------------------------
# 9. File Upload Size Limits & 413 Handling
# ---------------------------------------------------------------------------

class TestFileUploadSizeLimits:
    def test_oversized_upload_rejected_with_json_413(self, app, client, owner_token):
        """
        An upload exceeding MAX_CONTENT_LENGTH must be rejected with HTTP 413
        and a clean JSON response instead of the default HTML error page.
        """
        import io
        # Configure a small limit for testing (500 bytes)
        app.config["MAX_CONTENT_LENGTH"] = 500

        oversized_data = io.BytesIO(b"X" * 1024)
        res = client.post(
            "/api/files",
            data={"file": (oversized_data, "oversized.bin")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        assert res.status_code == 413
        assert res.content_type == "application/json"
        body = res.get_json()
        assert body is not None
        assert "error" in body
        assert "Request entity too large" in body["error"]
        assert "message" in body

    def test_upload_within_limit_succeeds(self, app, client, owner_token):
        """An upload within MAX_CONTENT_LENGTH must succeed with HTTP 201."""
        import io
        app.config["MAX_CONTENT_LENGTH"] = 5000

        data = io.BytesIO(b"Safe small content")
        res = client.post(
            "/api/files",
            data={"file": (data, "small.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        assert res.status_code == 201
        assert "file" in res.get_json()

    def test_config_max_upload_size_default(self):
        """Verify MAX_UPLOAD_SIZE_MB and MAX_CONTENT_LENGTH configuration defaults."""
        from app.config import Config

        assert Config.MAX_UPLOAD_SIZE_MB == 100
        assert Config.MAX_CONTENT_LENGTH == 100 * 1024 * 1024


# ---------------------------------------------------------------------------
# 10. Share Recipient Receipts
# ---------------------------------------------------------------------------

class TestShareReceipts:
    def test_recipient_view_then_download_receipts(
        self, client, shared_file, owner_token, recipient, recipient_token
    ):
        """
        Simulate a recipient viewing then downloading a share, asserting that
        first_viewed_at and first_downloaded_at show up both on
        GET /api/shares/<share_id>/receipts and GET /api/files/<file_id>/shares.
        """
        # 1. Create a share for the recipient
        res = create_share(client, shared_file.id, owner_token, {
            "recipient_ids": [str(recipient.id)],
            "permissions": {"can_view": True, "can_download": True},
        })
        assert res.status_code == 201
        share_data = res.get_json()["shares"][0]
        share_id = share_data["id"]
        token = share_data["share_token"]

        # 2. Before any access, receipts should have None timestamps
        receipts_res = client.get(
            f"/api/shares/{share_id}/receipts",
            headers=auth_header(owner_token),
        )
        assert receipts_res.status_code == 200
        receipts = receipts_res.get_json()
        assert receipts["share_id"] == str(share_id)
        assert receipts["recipient_id"] == str(recipient.id)
        assert receipts["first_viewed_at"] is None
        assert receipts["first_downloaded_at"] is None
        assert receipts["viewed"] is False
        assert receipts["downloaded"] is False

        # Check /api/files/<id>/shares before access
        list_res = client.get(
            f"/api/files/{shared_file.id}/shares",
            headers=auth_header(owner_token),
        )
        assert list_res.status_code == 200
        listed_shares = list_res.get_json()["shares"]
        entry = next(s for s in listed_shares if s["id"] == str(share_id))
        assert entry["first_viewed_at"] is None
        assert entry["first_downloaded_at"] is None

        # 3. Recipient views the share
        view_res = client.get(
            f"/api/shares/{token}/access",
            headers=auth_header(recipient_token),
        )
        assert view_res.status_code == 200

        # Verify receipts now show first_viewed_at
        receipts_res = client.get(
            f"/api/shares/{share_id}/receipts",
            headers=auth_header(owner_token),
        )
        assert receipts_res.status_code == 200
        receipts = receipts_res.get_json()
        first_viewed_at = receipts["first_viewed_at"]
        assert first_viewed_at is not None
        assert receipts["first_downloaded_at"] is None
        assert receipts["viewed"] is True
        assert receipts["downloaded"] is False

        # Verify GET /api/files/<id>/shares shows first_viewed_at
        list_res = client.get(
            f"/api/files/{shared_file.id}/shares",
            headers=auth_header(owner_token),
        )
        listed_shares = list_res.get_json()["shares"]
        entry = next(s for s in listed_shares if s["id"] == str(share_id))
        assert entry["first_viewed_at"] == first_viewed_at
        assert entry["first_downloaded_at"] is None

        # 4. Recipient downloads the share
        dl_res = client.get(
            f"/api/shares/{token}/download",
            headers=auth_header(recipient_token),
        )
        assert dl_res.status_code == 200

        # Verify receipts now show both first_viewed_at and first_downloaded_at
        receipts_res = client.get(
            f"/api/shares/{share_id}/receipts",
            headers=auth_header(owner_token),
        )
        assert receipts_res.status_code == 200
        receipts = receipts_res.get_json()
        assert receipts["first_viewed_at"] == first_viewed_at
        first_downloaded_at = receipts["first_downloaded_at"]
        assert first_downloaded_at is not None
        assert receipts["viewed"] is True
        assert receipts["downloaded"] is True

        # Verify GET /api/files/<id>/shares includes the pair
        list_res = client.get(
            f"/api/files/{shared_file.id}/shares",
            headers=auth_header(owner_token),
        )
        listed_shares = list_res.get_json()["shares"]
        entry = next(s for s in listed_shares if s["id"] == str(share_id))
        assert entry["first_viewed_at"] == first_viewed_at
        assert entry["first_downloaded_at"] == first_downloaded_at

    def test_receipts_earliest_timestamp_preserved(
        self, client, shared_file, owner_token, recipient, recipient_token
    ):
        """Subsequent views/downloads do not overwrite the earliest timestamp."""
        res = create_share(client, shared_file.id, owner_token, {
            "recipient_ids": [str(recipient.id)],
            "permissions": {"can_view": True, "can_download": True},
        })
        share_data = res.get_json()["shares"][0]
        share_id = share_data["id"]
        token = share_data["share_token"]

        # View once
        client.get(f"/api/shares/{token}/access", headers=auth_header(recipient_token))
        first_receipts = client.get(
            f"/api/shares/{share_id}/receipts",
            headers=auth_header(owner_token),
        ).get_json()
        first_view_ts = first_receipts["first_viewed_at"]
        assert first_view_ts is not None

        # View again
        client.get(f"/api/shares/{token}/access", headers=auth_header(recipient_token))
        second_receipts = client.get(
            f"/api/shares/{share_id}/receipts",
            headers=auth_header(owner_token),
        ).get_json()
        assert second_receipts["first_viewed_at"] == first_view_ts

        # Download once
        client.get(f"/api/shares/{token}/download", headers=auth_header(recipient_token))
        third_receipts = client.get(
            f"/api/shares/{share_id}/receipts",
            headers=auth_header(owner_token),
        ).get_json()
        first_dl_ts = third_receipts["first_downloaded_at"]
        assert first_dl_ts is not None

        # Download again
        client.get(f"/api/shares/{token}/download", headers=auth_header(recipient_token))
        fourth_receipts = client.get(
            f"/api/shares/{share_id}/receipts",
            headers=auth_header(owner_token),
        ).get_json()
        assert fourth_receipts["first_downloaded_at"] == first_dl_ts

    def test_non_owner_cannot_access_receipts(
        self, client, shared_file, owner_token, recipient, recipient_token
    ):
        """Only the share owner can view receipts."""
        res = create_share(client, shared_file.id, owner_token, {
            "recipient_ids": [str(recipient.id)],
        })
        share_id = res.get_json()["shares"][0]["id"]

        # Recipient attempts to access receipts -> 403 Forbidden
        receipts_res = client.get(
            f"/api/shares/{share_id}/receipts",
            headers=auth_header(recipient_token),
        )
        assert receipts_res.status_code == 403

    def test_unauthenticated_receipts_rejected(self, client, shared_file, owner_token):
        """Unauthenticated call to receipts endpoint returns 401."""
        res = create_share(client, shared_file.id, owner_token, {})
        share_id = res.get_json()["shares"][0]["id"]

        receipts_res = client.get(f"/api/shares/{share_id}/receipts")
        assert receipts_res.status_code == 401

    def test_nonexistent_share_receipts_returns_404(self, client, owner_token):
        """Requesting receipts for nonexistent share UUID returns 404."""
        import uuid
        receipts_res = client.get(
            f"/api/shares/{uuid.uuid4()}/receipts",
            headers=auth_header(owner_token),
        )
        assert receipts_res.status_code == 404


# ---------------------------------------------------------------------------
# 11. Custom Share Slugs
# ---------------------------------------------------------------------------

class TestCustomSlug:
    def test_create_share_with_custom_slug(self, client, shared_file, owner_token):
        """Owner creates a share with a custom slug and can access it via slug or token."""
        res = create_share(client, shared_file.id, owner_token, {
            "permissions": {"can_view": True, "can_download": True},
            "custom_slug": "team-wiki",
        })
        assert res.status_code == 201
        share = res.get_json()["shares"][0]
        assert share["custom_slug"] == "team-wiki"
        assert "team-wiki" in share["share_url"]

        token = share["share_token"]

        # Access via custom slug
        res_slug = client.get("/api/shares/team-wiki/access")
        assert res_slug.status_code == 200
        data_slug = res_slug.get_json()
        assert data_slug["share"]["custom_slug"] == "team-wiki"
        assert data_slug["file"]["filename"] == "test.txt"

        # Access via opaque share token still works
        res_token = client.get(f"/api/shares/{token}/access")
        assert res_token.status_code == 200
        assert res_token.get_json()["share"]["id"] == share["id"]

    def test_download_share_with_custom_slug(self, client, shared_file, owner_token):
        """Streaming file download works using the custom slug or share token."""
        res = create_share(client, shared_file.id, owner_token, {
            "permissions": {"can_view": True, "can_download": True},
            "custom_slug": "sales-report-2026",
        })
        assert res.status_code == 201
        token = res.get_json()["shares"][0]["share_token"]

        # Download via custom slug
        dl_slug = client.get("/api/shares/sales-report-2026/download")
        assert dl_slug.status_code == 200
        assert dl_slug.data == b"Hello, secure world!"

        # Download via share token
        dl_token = client.get(f"/api/shares/{token}/download")
        assert dl_token.status_code == 200
        assert dl_token.data == b"Hello, secure world!"

    def test_custom_slug_collision_rejection(self, client, shared_file, owner_token):
        """Attempting to create another share with an existing custom slug returns 409 Conflict."""
        res1 = create_share(client, shared_file.id, owner_token, {
            "custom_slug": "roadmap-2026",
        })
        assert res1.status_code == 201

        # Duplicate slug collision
        res2 = create_share(client, shared_file.id, owner_token, {
            "custom_slug": "roadmap-2026",
        })
        assert res2.status_code == 409
        assert "already in use" in res2.get_json()["error"]

    def test_patch_custom_slug_lifecycle(self, client, shared_file, owner_token):
        """Test setting, collision rejection, idempotent self-update, and removal of custom slug via PATCH."""
        res = create_share(client, shared_file.id, owner_token, {
            "permissions": {"can_view": True},
        })
        assert res.status_code == 201
        share = res.get_json()["shares"][0]
        share_id = share["id"]
        token = share["share_token"]
        assert share["custom_slug"] is None

        # 1. Add custom slug via PATCH
        patch1 = client.patch(
            f"/api/shares/{share_id}",
            json={"custom_slug": "engineering-handbook"},
            headers=auth_header(owner_token),
        )
        assert patch1.status_code == 200
        assert patch1.get_json()["share"]["custom_slug"] == "engineering-handbook"

        # Access via newly assigned slug
        acc = client.get("/api/shares/engineering-handbook/access")
        assert acc.status_code == 200

        # 2. Create another share with slug 'design-system'
        create_share(client, shared_file.id, owner_token, {
            "custom_slug": "design-system",
        })

        # 3. Try to PATCH first share to 'design-system' -> 409 Conflict
        patch_conflict = client.patch(
            f"/api/shares/{share_id}",
            json={"custom_slug": "design-system"},
            headers=auth_header(owner_token),
        )
        assert patch_conflict.status_code == 409
        assert "already in use" in patch_conflict.get_json()["error"]

        # 4. PATCH first share with same existing slug -> 200 (idempotent, no self-collision)
        patch_same = client.patch(
            f"/api/shares/{share_id}",
            json={"custom_slug": "engineering-handbook"},
            headers=auth_header(owner_token),
        )
        assert patch_same.status_code == 200

        # 5. Clear custom slug by passing None
        patch_clear = client.patch(
            f"/api/shares/{share_id}",
            json={"custom_slug": None},
            headers=auth_header(owner_token),
        )
        assert patch_clear.status_code == 200
        assert patch_clear.get_json()["share"]["custom_slug"] is None

        # Custom slug no longer resolves
        assert client.get("/api/shares/engineering-handbook/access").status_code == 404
        # But share token still resolves
        assert client.get(f"/api/shares/{token}/access").status_code == 200

    def test_custom_slug_format_validation(self, client, shared_file, owner_token):
        """Invalid slug formats (<3 chars, >64 chars, special chars, non-strings) return 400."""
        # Too short (< 3 chars)
        res_short = create_share(client, shared_file.id, owner_token, {"custom_slug": "ab"})
        assert res_short.status_code == 400
        assert "custom_slug must be 3-64" in res_short.get_json()["error"]

        # Too long (> 64 chars)
        res_long = create_share(client, shared_file.id, owner_token, {"custom_slug": "a" * 65})
        assert res_long.status_code == 400

        # Invalid characters (spaces, underscores, special characters)
        for bad_slug in ["has space", "under_score", "slug@domain", "slug!"]:
            res_bad = create_share(client, shared_file.id, owner_token, {"custom_slug": bad_slug})
            assert res_bad.status_code == 400

        # Non-string
        res_non_str = create_share(client, shared_file.id, owner_token, {"custom_slug": 12345})
        assert res_non_str.status_code == 400

        # Valid slug with uppercase, digits, hyphens
        res_valid = create_share(client, shared_file.id, owner_token, {"custom_slug": "Alpha-Beta-99"})
        assert res_valid.status_code == 201
        assert res_valid.get_json()["shares"][0]["custom_slug"] == "Alpha-Beta-99"

    def test_custom_slug_with_multiple_recipients_rejected(
        self, client, shared_file, owner_token, recipient
    ):
        """Passing custom_slug when specifying multiple recipient_ids returns 400."""
        user2 = client.post("/api/auth/register", json={
            "username": "user_two",
            "email": "two@test.com",
            "password": "Password123!",
        }).get_json()["user"]

        res = create_share(client, shared_file.id, owner_token, {
            "recipient_ids": [str(recipient.id), user2["id"]],
            "custom_slug": "multi-slug",
        })
        assert res.status_code == 400
        assert "multiple shares" in res.get_json()["error"]

    def test_password_and_qrcode_with_custom_slug(self, client, shared_file, owner_token):
        """Password verification and QR code retrieval work seamlessly with custom slugs."""
        res = create_share(client, shared_file.id, owner_token, {
            "permissions": {"can_view": True},
            "custom_slug": "secret-spec",
            "password": "CorrectHorse99!",
        })
        assert res.status_code == 201
        token = res.get_json()["shares"][0]["share_token"]

        # Password required without grant
        assert client.get("/api/shares/secret-spec/access").status_code == 401
        assert client.get("/api/shares/secret-spec/qrcode").status_code == 401

        # Verify password via custom slug
        grant_res = client.post("/api/shares/secret-spec/verify-password", json={
            "password": "CorrectHorse99!",
        })
        assert grant_res.status_code == 200
        grant = grant_res.get_json()["grant_token"]

        # Access with grant via slug
        acc = client.get(
            "/api/shares/secret-spec/access",
            headers={"X-Share-Grant": grant},
        )
        assert acc.status_code == 200

        # QR code with grant via slug
        qr_slug = client.get(
            "/api/shares/secret-spec/qrcode",
            headers={"X-Share-Grant": grant},
        )
        assert qr_slug.status_code == 200
        assert qr_slug.mimetype == "image/png"

        # QR code with grant via token
        qr_token = client.get(
            f"/api/shares/{token}/qrcode",
            headers={"X-Share-Grant": grant},
        )
        assert qr_token.status_code == 200
        assert qr_token.mimetype == "image/png"

    def test_list_file_shares_includes_custom_slug(self, client, shared_file, owner_token):
        """GET /api/files/<id>/shares includes custom_slug and formatted share_url."""
        create_share(client, shared_file.id, owner_token, {
            "custom_slug": "q3-roadmap",
        })
        list_res = client.get(
            f"/api/files/{shared_file.id}/shares",
            headers=auth_header(owner_token),
        )
        assert list_res.status_code == 200
        shares = list_res.get_json()["shares"]
        matched = [s for s in shares if s.get("custom_slug") == "q3-roadmap"]
        assert len(matched) == 1
        assert "q3-roadmap" in matched[0]["share_url"]


# ---------------------------------------------------------------------------
# In-browser preview mode (can_view=True, can_download=False)
# ---------------------------------------------------------------------------

class TestSharePreview:
    @pytest.fixture
    def image_file(self, app, db, owner):
        with app.app_context():
            png_bytes = (
                b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
                b"\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\rIDATx\x9cc`\x00\x00\x00\x02"
                b"\x00\x01H\xaf\xa4q\x00\x00\x00\x00IEND\xaeB`\x82"
            )
            ciphertext, nonce_hex, wrapped_key_hex = encrypt_file(png_bytes)
            import tempfile
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".enc")
            tmp.write(ciphertext)
            tmp.close()

            f = File(
                owner_id=owner.id,
                filename="preview_image.png",
                mime_type="image/png",
                size_bytes=len(png_bytes),
                encrypted_path=tmp.name,
                nonce_hex=nonce_hex,
                wrapped_key_hex=wrapped_key_hex,
            )
            db.session.add(f)
            db.session.commit()
            db.session.refresh(f)
            return f, png_bytes

    def test_can_download_false_can_preview_image_but_download_returns_403(
        self, client, image_file, owner_token
    ):
        f, png_bytes = image_file
        res = create_share(client, f.id, owner_token, {
            "permissions": {"can_view": True, "can_download": False},
        })
        assert res.status_code == 201
        token = res.get_json()["shares"][0]["share_token"]

        # Preview allows viewing the image
        preview_res = client.get(f"/api/shares/{token}/preview")
        assert preview_res.status_code == 200
        assert preview_res.data == png_bytes
        assert preview_res.mimetype == "image/png"
        assert "inline" in preview_res.headers.get("Content-Disposition", "")
        assert "preview_image.png" in preview_res.headers.get("Content-Disposition", "")

        # Direct download attempt returns 403 Forbidden
        download_res = client.get(f"/api/shares/{token}/download")
        assert download_res.status_code == 403
        assert "Download not permitted" in download_res.get_json()["error"]

    def test_preview_rejected_when_can_download_is_true(
        self, client, image_file, owner_token
    ):
        f, _ = image_file
        res = create_share(client, f.id, owner_token, {
            "permissions": {"can_view": True, "can_download": True},
        })
        assert res.status_code == 201
        token = res.get_json()["shares"][0]["share_token"]

        # Preview returns 403 when download is allowed
        preview_res = client.get(f"/api/shares/{token}/preview")
        assert preview_res.status_code == 403
        assert "Preview is only available for view-only shares" in preview_res.get_json()["error"]

    def test_preview_rejected_when_can_view_is_false(
        self, client, image_file, owner_token
    ):
        f, _ = image_file
        res = create_share(client, f.id, owner_token, {
            "permissions": {"can_view": False, "can_download": False},
        })
        assert res.status_code == 201
        token = res.get_json()["shares"][0]["share_token"]

        preview_res = client.get(f"/api/shares/{token}/preview")
        assert preview_res.status_code == 403
        assert "View not permitted" in preview_res.get_json()["error"]

    def test_preview_password_protection(self, client, image_file, owner_token):
        f, png_bytes = image_file
        res = create_share(client, f.id, owner_token, {
            "permissions": {"can_view": True, "can_download": False},
            "password": "SecretImagePass!",
        })
        assert res.status_code == 201
        token = res.get_json()["shares"][0]["share_token"]

        # 401 without grant
        res_no_grant = client.get(f"/api/shares/{token}/preview")
        assert res_no_grant.status_code == 401

        # Verify password
        verify_res = client.post(f"/api/shares/{token}/verify-password", json={
            "password": "SecretImagePass!",
        })
        assert verify_res.status_code == 200
        grant = verify_res.get_json()["grant_token"]

        # 200 with grant
        res_with_grant = client.get(
            f"/api/shares/{token}/preview",
            headers={"X-Share-Grant": grant},
        )
        assert res_with_grant.status_code == 200
        assert res_with_grant.data == png_bytes

    def test_preview_expiry_and_revocation(self, client, image_file, owner_token):
        f, _ = image_file
        past = (
            datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(minutes=5)
        ).isoformat()

        # Expired
        res_exp = create_share(client, f.id, owner_token, {
            "permissions": {"can_view": True, "can_download": False},
            "expires_at": past,
        })
        token_exp = res_exp.get_json()["shares"][0]["share_token"]
        assert client.get(f"/api/shares/{token_exp}/preview").status_code == 410

        # Revoked
        res_rev = create_share(client, f.id, owner_token, {
            "permissions": {"can_view": True, "can_download": False},
        })
        share_id = res_rev.get_json()["shares"][0]["id"]
        token_rev = res_rev.get_json()["shares"][0]["share_token"]
        client.patch(
            f"/api/shares/{share_id}",
            json={"is_revoked": True},
            headers=auth_header(owner_token),
        )
        assert client.get(f"/api/shares/{token_rev}/preview").status_code == 410

    def test_preview_recipient_restriction(
        self, client, image_file, owner_token, recipient, recipient_token
    ):
        f, png_bytes = image_file
        res = create_share(client, f.id, owner_token, {
            "recipient_ids": [str(recipient.id)],
            "permissions": {"can_view": True, "can_download": False},
        })
        token = res.get_json()["shares"][0]["share_token"]

        # Anonymous access blocked
        assert client.get(f"/api/shares/{token}/preview").status_code == 403

        # Authorized recipient allowed
        res_recip = client.get(
            f"/api/shares/{token}/preview",
            headers=auth_header(recipient_token),
        )
        assert res_recip.status_code == 200
        assert res_recip.data == png_bytes

    def test_preview_access_logging(self, client, image_file, owner_token):
        f, _ = image_file
        res = create_share(client, f.id, owner_token, {
            "permissions": {"can_view": True, "can_download": False},
        })
        share_dict = res.get_json()["shares"][0]
        token = share_dict["share_token"]
        share_id = share_dict["id"]

        client.get(f"/api/shares/{token}/preview")

        # AccessLog should have an entry with action="view" and success=True
        log = (
            AccessLog.query.filter_by(share_id=uuid.UUID(share_id), action="view")
            .order_by(AccessLog.timestamp.desc())
            .first()
        )
        assert log is not None
        assert log.success is True

    def test_preview_via_custom_slug(self, client, image_file, owner_token):
        f, png_bytes = image_file
        res = create_share(client, f.id, owner_token, {
            "permissions": {"can_view": True, "can_download": False},
            "custom_slug": "banner-preview",
        })
        assert res.status_code == 201

        preview_res = client.get("/api/shares/banner-preview/preview")
        assert preview_res.status_code == 200
        assert preview_res.data == png_bytes
        assert "inline" in preview_res.headers.get("Content-Disposition", "")

    def test_can_download_false_can_preview_text_file(
        self, client, shared_file, owner_token
    ):
        res = create_share(client, shared_file.id, owner_token, {
            "permissions": {"can_view": True, "can_download": False},
        })
        assert res.status_code == 201
        token = res.get_json()["shares"][0]["share_token"]

        preview_res = client.get(f"/api/shares/{token}/preview")
        assert preview_res.status_code == 200
        assert preview_res.data == b"Hello, secure world!"
        assert preview_res.mimetype == "text/plain"
        assert "inline" in preview_res.headers.get("Content-Disposition", "")
        assert "test.txt" in preview_res.headers.get("Content-Disposition", "")






