"""
Tests for per-user storage quota enforcement, profile reporting, and admin management.
"""

import io
import uuid
import pytest
from app.models import User, File, AccessLog
from app.auth.decorators import generate_access_token


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="function")
def admin_user(app, db):
    with app.app_context():
        u = User(username="admin_quota_user", email="admin_quota@test.com", role="admin")
        u.set_password("AdminPass123!")
        db.session.add(u)
        db.session.commit()
        db.session.refresh(u)
        return u


@pytest.fixture(scope="function")
def admin_token(app, db, admin_user):
    with app.app_context():
        db.session.add(admin_user)
        return generate_access_token(admin_user)


class TestStorageQuotaEnforcement:
    """Tests enforcing user storage quotas during uploads."""

    def test_upload_within_quota_succeeds(self, app, client, db, owner, owner_token):
        """Uploading a file whose size is within the user's storage quota succeeds (201)."""
        with app.app_context():
            user = db.session.get(User, owner.id)
            user.storage_quota_bytes = 10000
            db.session.commit()

        file_content = b"A" * 500  # 500 bytes < 10000 bytes
        res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(file_content), "small.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        assert res.status_code == 201
        data = res.get_json()
        assert "file" in data
        assert data["file"]["size_bytes"] == 500

    def test_upload_exceeding_quota_rejected_with_413(self, app, client, db, owner, owner_token):
        """Uploading a file whose size exceeds the user's storage quota is rejected with 413."""
        with app.app_context():
            user = db.session.get(User, owner.id)
            user.storage_quota_bytes = 1000  # 1000 bytes limit
            db.session.commit()

        oversized_content = b"B" * 1500  # 1500 bytes > 1000 bytes
        res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(oversized_content), "oversized.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        assert res.status_code == 413
        data = res.get_json()
        assert data["error"] == "Storage quota exceeded"
        assert "storage_used_bytes" in data
        assert data["storage_used_bytes"] == 0
        assert data["storage_quota_bytes"] == 1000
        assert data["file_size_bytes"] == 1500

    def test_cumulative_uploads_exceeding_quota_rejected(self, app, client, db, owner, owner_token):
        """Cumulative uploads that push total storage over quota trigger a 413 rejection."""
        with app.app_context():
            user = db.session.get(User, owner.id)
            user.storage_quota_bytes = 1000
            db.session.commit()

        # First upload: 600 bytes (within 1000 quota)
        res1 = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"C" * 600), "part1.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        assert res1.status_code == 201

        # Second upload: 500 bytes (600 + 500 = 1100 > 1000 quota) -> rejected
        res2 = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"D" * 500), "part2.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        assert res2.status_code == 413
        data2 = res2.get_json()
        assert data2["error"] == "Storage quota exceeded"
        assert data2["storage_used_bytes"] == 600
        assert data2["storage_quota_bytes"] == 1000
        assert data2["file_size_bytes"] == 500

    def test_unlimited_quota_allows_arbitrary_upload(self, app, client, db, owner, owner_token):
        """Users with storage_quota_bytes = None have unlimited quota."""
        with app.app_context():
            user = db.session.get(User, owner.id)
            user.storage_quota_bytes = None  # None = unlimited
            db.session.commit()

        content = b"E" * 50000
        res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(content), "large.bin")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        assert res.status_code == 201
        assert res.get_json()["file"]["size_bytes"] == 50000

    def test_version_upload_exceeding_quota_rejected(self, app, client, db, owner, owner_token):
        """Uploading a new file version that exceeds storage quota is rejected with 413."""
        with app.app_context():
            user = db.session.get(User, owner.id)
            user.storage_quota_bytes = 1000
            db.session.commit()

        # Initial upload: 400 bytes
        res1 = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"F" * 400), "doc.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        assert res1.status_code == 201
        file_id = res1.get_json()["file"]["id"]

        # Version upload: 1200 bytes (would replace 400 byte base size, net usage = 1200 > 1000)
        res2 = client.post(
            f"/api/files/{file_id}/versions",
            data={"file": (io.BytesIO(b"G" * 1200), "doc_v2.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        assert res2.status_code == 413
        assert res2.get_json()["error"] == "Storage quota exceeded"


class TestStorageQuotaReporting:
    """Tests verifying current storage usage and quota are exposed in API endpoints."""

    def test_auth_me_exposes_storage_usage_and_quota(self, app, client, db, owner, owner_token):
        """GET /api/auth/me returns storage_used_bytes and storage_quota_bytes."""
        with app.app_context():
            user = db.session.get(User, owner.id)
            user.storage_quota_bytes = 20000
            db.session.commit()

        # Upload a 1234-byte file
        client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"H" * 1234), "usage_test.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )

        res = client.get("/api/auth/me", headers=auth_header(owner_token))
        assert res.status_code == 200
        data = res.get_json()
        assert data["user"]["storage_used_bytes"] == 1234
        assert data["user"]["storage_quota_bytes"] == 20000
        assert data["storage_used_bytes"] == 1234
        assert data["storage_quota_bytes"] == 20000

    def test_list_files_exposes_storage_headers_and_body(self, app, client, db, owner, owner_token):
        """GET /api/files includes X-Storage-Used-Bytes and X-Storage-Quota-Bytes headers and body fields."""
        with app.app_context():
            user = db.session.get(User, owner.id)
            user.storage_quota_bytes = 50000
            db.session.commit()

        # Upload two files: 1000 and 2000 bytes
        client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"1" * 1000), "f1.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"2" * 2000), "f2.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )

        res = client.get("/api/files", headers=auth_header(owner_token))
        assert res.status_code == 200
        assert res.headers.get("X-Storage-Used-Bytes") == "3000"
        assert res.headers.get("X-Storage-Quota-Bytes") == "50000"

        data = res.get_json()
        assert data["storage_used_bytes"] == 3000
        assert data["storage_quota_bytes"] == 50000


class TestAdminQuotaManagement:
    """Tests for PATCH /api/admin/users/<id>/quota."""

    def test_admin_update_quota_bytes_success(self, app, client, db, owner, admin_token):
        """Admin can change a user's quota using storage_quota_bytes."""
        res = client.patch(
            f"/api/admin/users/{owner.id}/quota",
            json={"storage_quota_bytes": 104857600},
            headers=auth_header(admin_token),
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["message"] == "Storage quota updated successfully"
        assert data["storage_quota_bytes"] == 104857600
        assert data["user"]["storage_quota_bytes"] == 104857600

        with app.app_context():
            user = db.session.get(User, owner.id)
            assert user.storage_quota_bytes == 104857600

    def test_admin_update_quota_mb_success(self, app, client, db, owner, admin_token):
        """Admin can change a user's quota using storage_quota_mb."""
        res = client.patch(
            f"/api/admin/users/{owner.id}/quota",
            json={"storage_quota_mb": 25},
            headers=auth_header(admin_token),
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["storage_quota_bytes"] == 25 * 1024 * 1024

        with app.app_context():
            user = db.session.get(User, owner.id)
            assert user.storage_quota_bytes == 25 * 1024 * 1024

    def test_admin_set_unlimited_quota(self, app, client, db, owner, admin_token):
        """Admin can set quota to null (unlimited)."""
        res = client.patch(
            f"/api/admin/users/{owner.id}/quota",
            json={"storage_quota_bytes": None},
            headers=auth_header(admin_token),
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["storage_quota_bytes"] is None

        with app.app_context():
            user = db.session.get(User, owner.id)
            assert user.storage_quota_bytes is None

    def test_admin_quota_increase_unblocks_upload(self, app, client, db, owner, owner_token, admin_token):
        """Increasing quota via admin endpoint allows a previously quota-blocked user to upload."""
        # Restrict quota to 500 bytes
        with app.app_context():
            user = db.session.get(User, owner.id)
            user.storage_quota_bytes = 500
            db.session.commit()

        # Attempt to upload 800 bytes -> fails with 413
        res1 = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"X" * 800), "retry.bin")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        assert res1.status_code == 413

        # Admin increases quota to 2000 bytes
        res2 = client.patch(
            f"/api/admin/users/{owner.id}/quota",
            json={"storage_quota_bytes": 2000},
            headers=auth_header(admin_token),
        )
        assert res2.status_code == 200

        # User retries upload -> succeeds with 201
        res3 = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"X" * 800), "retry.bin")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        assert res3.status_code == 201

    def test_admin_update_quota_negative_rejected(self, client, owner, admin_token):
        """Negative quota values are rejected with 400 Bad Request."""
        res = client.patch(
            f"/api/admin/users/{owner.id}/quota",
            json={"storage_quota_bytes": -100},
            headers=auth_header(admin_token),
        )
        assert res.status_code == 400
        assert "cannot be negative" in res.get_json()["error"]

    def test_admin_update_quota_missing_field_rejected(self, client, owner, admin_token):
        """Payload without quota fields is rejected with 400 Bad Request."""
        res = client.patch(
            f"/api/admin/users/{owner.id}/quota",
            json={},
            headers=auth_header(admin_token),
        )
        assert res.status_code == 400
        assert "is required" in res.get_json()["error"]

    def test_admin_update_quota_user_not_found(self, client, admin_token):
        """Updating quota for nonexistent user returns 404."""
        random_id = uuid.uuid4()
        res = client.patch(
            f"/api/admin/users/{random_id}/quota",
            json={"storage_quota_bytes": 1000},
            headers=auth_header(admin_token),
        )
        assert res.status_code == 404

    def test_non_admin_cannot_update_quota(self, client, owner, owner_token):
        """Regular users receive 403 Forbidden when attempting to update quota."""
        res = client.patch(
            f"/api/admin/users/{owner.id}/quota",
            json={"storage_quota_bytes": 1000},
            headers=auth_header(owner_token),
        )
        assert res.status_code == 403

    def test_admin_quota_update_logged(self, app, client, db, owner, admin_user, admin_token):
        """Quota updates are recorded in the audit log."""
        res = client.patch(
            f"/api/admin/users/{owner.id}/quota",
            json={"storage_quota_bytes": 5000000},
            headers=auth_header(admin_token),
        )
        assert res.status_code == 200

        with app.app_context():
            log = AccessLog.query.filter_by(
                accessed_by=admin_user.id,
                action="admin_update_quota",
            ).first()
            assert log is not None
            assert "5000000 bytes" in log.detail
