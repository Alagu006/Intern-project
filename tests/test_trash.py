"""
Tests for soft-deletion, trash view, file restoration, and retention purge.

Covers:
- DELETE /api/files/<uuid:file_id> sets deleted_at, revokes shares, keeps disk blobs and row.
- Soft-deleted files excluded from GET /api/files and GET /api/files/search by default.
- Soft-deleted files included with ?include_deleted=true.
- GET /api/files/trash returns soft-deleted files owned by current user.
- POST /api/files/<uuid:file_id>/restore clears deleted_at, file becomes visible again, shares remain revoked.
- Restoring non-deleted file returns 400.
- Operations on soft-deleted files (download, thumbnail, patch) rejected.
- User isolation: users cannot see or restore another user's soft-deleted files.
- Background purge (scripts/cleanup_expired_files.py) permanently removes files where deleted_at > TRASH_RETENTION_DAYS.
"""

import io
import os
import uuid
from datetime import datetime, timedelta, timezone
import pytest

from app.extensions import db
from app.models import File, Share
from scripts.cleanup_expired_files import cleanup_expired_files, purge_trash_files


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


class TestSoftDeleteAndRestoreFlow:
    """Tests for soft-delete lifecycle, trash listing, and restoration."""

    def test_soft_delete_appears_in_trash_restore_visible_again(
        self, client, owner, owner_token, app
    ):
        """
        Full lifecycle:
        1. Upload file and create share.
        2. Soft-delete file -> deleted_at set, blob still on disk, share revoked.
        3. Excluded from GET /api/files.
        4. Included in GET /api/files?include_deleted=true.
        5. Appears in GET /api/files/trash.
        6. Restore file -> deleted_at cleared, visible again in GET /api/files,
           not in trash, but previously revoked share remains revoked.
        """
        # 1. Upload file
        up_res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"Confidential draft"), "draft.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        assert up_res.status_code == 201
        file_id = up_res.get_json()["file"]["id"]

        # Create active share
        share_res = client.post(
            f"/api/files/{file_id}/share",
            json={"permissions": {"can_view": True, "can_download": True}},
            headers=auth_header(owner_token),
        )
        assert share_res.status_code == 201
        share_token = share_res.get_json()["shares"][0]["share_token"]

        with app.app_context():
            f = db.session.get(File, uuid.UUID(file_id))
            assert f is not None
            disk_path = f.encrypted_path
            assert os.path.exists(disk_path)
            assert f.deleted_at is None
            assert f.is_deleted is False

        # 2. Soft-delete file
        del_res = client.delete(f"/api/files/{file_id}", headers=auth_header(owner_token))
        assert del_res.status_code == 200
        del_data = del_res.get_json()
        assert del_data["message"] == "File deleted successfully"
        assert del_data["deleted_at"] is not None

        # Verify disk blob and DB row are preserved
        assert os.path.exists(disk_path)
        with app.app_context():
            f_db = db.session.get(File, uuid.UUID(file_id))
            assert f_db is not None
            assert f_db.deleted_at is not None
            assert f_db.is_deleted is True

            # Share is revoked
            share = Share.query.filter_by(share_token=share_token).first()
            assert share.is_revoked is True

        # Accessing share returns 410
        assert client.get(f"/api/shares/{share_token}/access").status_code == 410

        # 3. Excluded from standard file list
        list_res = client.get("/api/files", headers=auth_header(owner_token))
        assert list_res.status_code == 200
        file_ids_in_list = [item["id"] for item in list_res.get_json()["files"]]
        assert file_id not in file_ids_in_list

        # Excluded from search
        search_res = client.get("/api/files/search?q=draft", headers=auth_header(owner_token))
        assert search_res.status_code == 200
        assert file_id not in [item["id"] for item in search_res.get_json()["files"]]

        # 4. Included with ?include_deleted=true
        incl_res = client.get("/api/files?include_deleted=true", headers=auth_header(owner_token))
        assert incl_res.status_code == 200
        incl_ids = [item["id"] for item in incl_res.get_json()["files"]]
        assert file_id in incl_ids

        # 5. Appears in GET /api/files/trash
        trash_res = client.get("/api/files/trash", headers=auth_header(owner_token))
        assert trash_res.status_code == 200
        trash_items = trash_res.get_json()["files"]
        assert any(item["id"] == file_id for item in trash_items)
        trash_entry = next(item for item in trash_items if item["id"] == file_id)
        assert trash_entry["is_deleted"] is True
        assert trash_entry["deleted_at"] is not None

        # 6. Restore file
        restore_res = client.post(
            f"/api/files/{file_id}/restore",
            headers=auth_header(owner_token),
        )
        assert restore_res.status_code == 200
        restored_data = restore_res.get_json()
        assert restored_data["message"] == "File restored successfully"
        assert restored_data["file"]["deleted_at"] is None
        assert restored_data["file"]["is_deleted"] is False

        # Visible in GET /api/files again
        list_again = client.get("/api/files", headers=auth_header(owner_token))
        assert list_again.status_code == 200
        assert file_id in [item["id"] for item in list_again.get_json()["files"]]

        # Removed from trash
        trash_again = client.get("/api/files/trash", headers=auth_header(owner_token))
        assert trash_again.status_code == 200
        assert not any(item["id"] == file_id for item in trash_again.get_json()["files"])

        # Share must NOT be auto-restored (remains revoked)
        with app.app_context():
            share_check = Share.query.filter_by(share_token=share_token).first()
            assert share_check.is_revoked is True

    def test_restore_non_deleted_file_returns_400(self, client, owner_token):
        """Attempting to restore an active (non-soft-deleted) file returns 400."""
        up_res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"Active content"), "active.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = up_res.get_json()["file"]["id"]

        restore_res = client.post(f"/api/files/{file_id}/restore", headers=auth_header(owner_token))
        assert restore_res.status_code == 400
        assert restore_res.get_json()["error"] == "File is not in trash"

    def test_trash_user_isolation(self, client, owner_token, recipient_token):
        """User cannot view or restore files in another user's trash."""
        # Owner soft-deletes a file
        up_res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"Owner secret"), "secret.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = up_res.get_json()["file"]["id"]
        client.delete(f"/api/files/{file_id}", headers=auth_header(owner_token))

        # Recipient's trash is empty
        rec_trash = client.get("/api/files/trash", headers=auth_header(recipient_token))
        assert rec_trash.status_code == 200
        assert not any(item["id"] == file_id for item in rec_trash.get_json()["files"])

        # Recipient cannot restore owner's file
        rec_restore = client.post(f"/api/files/{file_id}/restore", headers=auth_header(recipient_token))
        assert rec_restore.status_code == 403

    def test_operations_on_soft_deleted_file_rejected(self, client, owner_token):
        """Downloading, previewing, or patching a soft-deleted file returns 410 or 400."""
        up_res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"Document data"), "doc.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = up_res.get_json()["file"]["id"]
        client.delete(f"/api/files/{file_id}", headers=auth_header(owner_token))

        # Download -> 410
        dl_res = client.get(f"/api/files/{file_id}/download", headers=auth_header(owner_token))
        assert dl_res.status_code == 410
        assert dl_res.get_json()["error"] == "File is in trash"

        # Patch -> 400
        patch_res = client.patch(
            f"/api/files/{file_id}",
            json={"filename": "renamed.txt"},
            headers=auth_header(owner_token),
        )
        assert patch_res.status_code == 400
        assert patch_res.get_json()["error"] == "Cannot modify file in trash"

        # Share -> 404
        share_res = client.post(
            f"/api/files/{file_id}/share",
            json={"permissions": {"can_view": True}},
            headers=auth_header(owner_token),
        )
        assert share_res.status_code == 404


class TestTrashRetentionPurge:
    """Tests for permanent purge of expired trash files via cleanup script."""

    def test_permanent_purge_after_retention_window(self, client, owner_token, app):
        """
        Files in trash older than TRASH_RETENTION_DAYS (30 days) are permanently deleted
        from DB and disk; files soft-deleted within the retention window are preserved.
        """
        # Upload 2 files
        up1 = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"Old trash item"), "old.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        old_id = up1.get_json()["file"]["id"]

        up2 = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"Recent trash item"), "recent.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        recent_id = up2.get_json()["file"]["id"]

        # Soft-delete both
        client.delete(f"/api/files/{old_id}", headers=auth_header(owner_token))
        client.delete(f"/api/files/{recent_id}", headers=auth_header(owner_token))

        # Backdate old_id to 35 days ago (older than 30 days retention)
        # Backdate recent_id to 5 days ago (within retention)
        now = datetime.now(timezone.utc)
        with app.app_context():
            old_file = db.session.get(File, uuid.UUID(old_id))
            old_blob = old_file.encrypted_path
            old_file.deleted_at = now - timedelta(days=35)

            recent_file = db.session.get(File, uuid.UUID(recent_id))
            recent_blob = recent_file.encrypted_path
            recent_file.deleted_at = now - timedelta(days=5)

            db.session.commit()

        assert os.path.exists(old_blob)
        assert os.path.exists(recent_blob)

        # Run cleanup job
        purged = cleanup_expired_files(app, retention_days=30)
        assert purged >= 1

        # Verify old file is purged completely from disk and DB
        assert not os.path.exists(old_blob)
        with app.app_context():
            assert db.session.get(File, uuid.UUID(old_id)) is None

        # Verify recent file is preserved
        assert os.path.exists(recent_blob)
        with app.app_context():
            f_recent = db.session.get(File, uuid.UUID(recent_id))
            assert f_recent is not None
            assert f_recent.deleted_at is not None

    def test_permanent_delete_query_parameter(self, client, owner_token, app):
        """Passing ?permanent=true immediately and permanently removes file and disk blob."""
        up = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"Instant purge"), "nuke.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = up.get_json()["file"]["id"]

        with app.app_context():
            f = db.session.get(File, uuid.UUID(file_id))
            disk_path = f.encrypted_path
            assert os.path.exists(disk_path)

        del_res = client.delete(f"/api/files/{file_id}?permanent=true", headers=auth_header(owner_token))
        assert del_res.status_code == 200
        assert del_res.get_json()["message"] == "File deleted permanently"

        # Verify completely gone
        assert not os.path.exists(disk_path)
        with app.app_context():
            assert db.session.get(File, uuid.UUID(file_id)) is None
