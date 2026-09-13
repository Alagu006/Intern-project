"""
tests/test_auto_delete.py

Tests for file auto-deletion (auto_delete_at) and the scheduled cleanup job
(scripts/cleanup_expired_files.py).
"""

import io
import os
import uuid
import tempfile
from datetime import datetime, timedelta, timezone
import pytest

from app.extensions import db
from app.models import File, FileVersion, Share, User
from app.auth.decorators import generate_access_token
from app.crypto.file_crypto import encrypt_file
from scripts.cleanup_expired_files import cleanup_expired_files


def auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


class TestAutoDeleteCleanup:
    def test_cleanup_expired_file_removes_blob_and_row(self, app, client, owner, owner_token):
        """
        Seeding an expired file with an active share and encrypted blob on disk.
        Running cleanup_expired_files() must:
        1. Revoke the share.
        2. Delete the encrypted blob from disk.
        3. Delete the file record from the database.
        """
        # 1. Create a dummy encrypted blob on disk
        plaintext = b"Sensitive document content"
        ciphertext, nonce_hex, wrapped_key_hex = encrypt_file(plaintext)

        upload_dir = app.config["UPLOAD_FOLDER"]
        os.makedirs(upload_dir, exist_ok=True)
        blob_id = uuid.uuid4()
        blob_path = os.path.join(upload_dir, f"{blob_id}.enc")
        with open(blob_path, "wb") as f:
            f.write(ciphertext)

        assert os.path.exists(blob_path)

        # 2. Seed File record with expired auto_delete_at
        past_time = datetime.now(timezone.utc) - timedelta(hours=2)
        with app.app_context():
            db.session.add(owner)
            file = File(
                id=blob_id,
                owner_id=owner.id,
                filename="expired_doc.txt",
                mime_type="text/plain",
                size_bytes=len(plaintext),
                encrypted_path=blob_path,
                nonce_hex=nonce_hex,
                wrapped_key_hex=wrapped_key_hex,
                auto_delete_at=past_time,
            )
            db.session.add(file)
            db.session.flush()

            # Create an active share
            share = Share(
                file_id=file.id,
                owner_id=owner.id,
                share_token=Share.generate_token(),
                is_revoked=False,
            )
            db.session.add(share)
            db.session.commit()

            file_id = file.id
            share_id = share.id

        # Verify it exists before cleanup
        with app.app_context():
            f_check = db.session.get(File, file_id)
            assert f_check is not None
            assert f_check.is_expired is True

        # 3. Run cleanup job
        deleted_count = cleanup_expired_files(app)
        assert deleted_count == 1

        # 4. Verify disk blob is deleted
        assert not os.path.exists(blob_path)

        # 5. Verify file record is removed from DB
        with app.app_context():
            assert db.session.get(File, file_id) is None
            # Share is deleted due to cascade or revoked
            s_check = db.session.get(Share, share_id)
            assert s_check is None or s_check.is_revoked is True

        # 6. Verify GET /api/files returns 0 files
        res = client.get("/api/files", headers=auth_header(owner_token))
        assert res.status_code == 200
        assert res.get_json()["total"] == 0

    def test_cleanup_preserves_unexpired_and_permanent_files(self, app, client, owner, owner_token):
        """
        Cleanup must leave files untouched if auto_delete_at is None or in the future.
        """
        upload_dir = app.config["UPLOAD_FOLDER"]
        os.makedirs(upload_dir, exist_ok=True)

        # File 1: Permanent (auto_delete_at is None)
        c1, n1, w1 = encrypt_file(b"Permanent content")
        p1 = os.path.join(upload_dir, f"{uuid.uuid4()}.enc")
        with open(p1, "wb") as f:
            f.write(c1)

        # File 2: Future expiration (auto_delete_at = now + 5 days)
        c2, n2, w2 = encrypt_file(b"Future content")
        p2 = os.path.join(upload_dir, f"{uuid.uuid4()}.enc")
        with open(p2, "wb") as f:
            f.write(c2)

        future_time = datetime.now(timezone.utc) + timedelta(days=5)

        with app.app_context():
            db.session.add(owner)
            f1 = File(
                owner_id=owner.id,
                filename="permanent.txt",
                size_bytes=len(c1),
                encrypted_path=p1,
                nonce_hex=n1,
                wrapped_key_hex=w1,
                auto_delete_at=None,
            )
            f2 = File(
                owner_id=owner.id,
                filename="future.txt",
                size_bytes=len(c2),
                encrypted_path=p2,
                nonce_hex=n2,
                wrapped_key_hex=w2,
                auto_delete_at=future_time,
            )
            db.session.add_all([f1, f2])
            db.session.commit()
            id1, id2 = f1.id, f2.id

        # Run cleanup
        deleted_count = cleanup_expired_files(app)
        assert deleted_count == 0

        # Blobs and DB records must still exist
        assert os.path.exists(p1)
        assert os.path.exists(p2)
        with app.app_context():
            assert db.session.get(File, id1) is not None
            assert db.session.get(File, id2) is not None

        # Clean up disk files
        for p in (p1, p2):
            if os.path.exists(p):
                os.remove(p)

    def test_cleanup_with_versions_removes_all_blobs(self, app, client, owner):
        """
        If an expired file has multiple FileVersion blobs, all blobs must be deleted.
        """
        upload_dir = app.config["UPLOAD_FOLDER"]
        os.makedirs(upload_dir, exist_ok=True)

        c1, n1, w1 = encrypt_file(b"Version 1 content")
        p1 = os.path.join(upload_dir, f"{uuid.uuid4()}_v1.enc")
        with open(p1, "wb") as f:
            f.write(c1)

        c2, n2, w2 = encrypt_file(b"Version 2 content")
        p2 = os.path.join(upload_dir, f"{uuid.uuid4()}_v2.enc")
        with open(p2, "wb") as f:
            f.write(c2)

        past_time = datetime.now(timezone.utc) - timedelta(minutes=10)

        with app.app_context():
            db.session.add(owner)
            parent = File(
                owner_id=owner.id,
                filename="multi_version.txt",
                size_bytes=len(c2),
                encrypted_path=p2,
                nonce_hex=n2,
                wrapped_key_hex=w2,
                auto_delete_at=past_time,
            )
            db.session.add(parent)
            db.session.flush()

            v1 = FileVersion(
                file_id=parent.id,
                version_number=1,
                filename="multi_version.txt",
                size_bytes=len(c1),
                encrypted_path=p1,
                nonce_hex=n1,
                wrapped_key_hex=w1,
            )
            v2 = FileVersion(
                file_id=parent.id,
                version_number=2,
                filename="multi_version.txt",
                size_bytes=len(c2),
                encrypted_path=p2,
                nonce_hex=n2,
                wrapped_key_hex=w2,
            )
            db.session.add_all([v1, v2])
            db.session.commit()
            file_id = parent.id

        assert os.path.exists(p1)
        assert os.path.exists(p2)

        deleted = cleanup_expired_files(app)
        assert deleted == 1

        assert not os.path.exists(p1)
        assert not os.path.exists(p2)
        with app.app_context():
            assert db.session.get(File, file_id) is None


class TestAutoDeleteAPI:
    def test_upload_with_auto_delete_at_iso(self, client, owner_token):
        """
        Verify setting auto_delete_at as ISO timestamp during upload.
        """
        exp_time = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
        res = client.post(
            "/api/files",
            data={
                "file": (io.BytesIO(b"Hello Auto Delete"), "auto_exp.txt"),
                "auto_delete_at": exp_time,
            },
            content_type="multipart/form-data",
            headers=auth_header(owner_token),
        )
        assert res.status_code == 201
        data = res.get_json()["file"]
        assert data["auto_delete_at"] is not None
        assert data["is_expired"] is False

    def test_upload_with_auto_delete_days(self, client, owner_token):
        """
        Verify setting auto_delete_days during upload computes auto_delete_at.
        """
        res = client.post(
            "/api/files",
            data={
                "file": (io.BytesIO(b"Hello Days"), "auto_days.txt"),
                "auto_delete_days": "3",
            },
            content_type="multipart/form-data",
            headers=auth_header(owner_token),
        )
        assert res.status_code == 201
        data = res.get_json()["file"]
        assert data["auto_delete_at"] is not None
        parsed_dt = datetime.fromisoformat(data["auto_delete_at"])
        if parsed_dt.tzinfo is None:
            parsed_dt = parsed_dt.replace(tzinfo=timezone.utc)
        diff = parsed_dt - datetime.now(timezone.utc)
        days_diff = diff.total_seconds() / 86400.0
        assert 2.9 <= days_diff <= 3.1

    def test_upload_with_invalid_auto_delete_rejected(self, client, owner_token):
        """
        Malformed auto_delete parameters on upload return 400.
        """
        res = client.post(
            "/api/files",
            data={
                "file": (io.BytesIO(b"Bad Date"), "bad_date.txt"),
                "auto_delete_at": "invalid-timestamp",
            },
            content_type="multipart/form-data",
            headers=auth_header(owner_token),
        )
        assert res.status_code == 400
        assert "Invalid auto_delete_at format" in res.get_json()["error"]

        res2 = client.post(
            "/api/files",
            data={
                "file": (io.BytesIO(b"Bad Days"), "bad_days.txt"),
                "auto_delete_days": "-2",
            },
            content_type="multipart/form-data",
            headers=auth_header(owner_token),
        )
        assert res2.status_code == 400

    def test_patch_file_auto_delete_lifecycle(self, client, owner_token):
        """
        Test setting, updating, and clearing auto_delete_at via PATCH /api/files/<id>.
        """
        # Upload without expiration
        upload_res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"Lifecycle test"), "lifecycle.txt")},
            content_type="multipart/form-data",
            headers=auth_header(owner_token),
        )
        assert upload_res.status_code == 201
        file_id = upload_res.get_json()["file"]["id"]
        assert upload_res.get_json()["file"]["auto_delete_at"] is None

        # 1. Update with auto_delete_at ISO string
        exp_target = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
        patch_res = client.patch(
            f"/api/files/{file_id}",
            json={"auto_delete_at": exp_target},
            headers=auth_header(owner_token),
        )
        assert patch_res.status_code == 200
        assert patch_res.get_json()["file"]["auto_delete_at"] is not None

        # 2. Clear auto_delete_at by setting null
        patch_clear = client.patch(
            f"/api/files/{file_id}",
            json={"auto_delete_at": None},
            headers=auth_header(owner_token),
        )
        assert patch_clear.status_code == 200
        assert patch_clear.get_json()["file"]["auto_delete_at"] is None

        # 3. Set via auto_delete_days
        patch_days = client.patch(
            f"/api/files/{file_id}",
            json={"auto_delete_days": 14},
            headers=auth_header(owner_token),
        )
        assert patch_days.status_code == 200
        assert patch_days.get_json()["file"]["auto_delete_at"] is not None

        # 4. Invalid auto_delete_at format rejects with 400
        bad_patch = client.patch(
            f"/api/files/{file_id}",
            json={"auto_delete_at": "not-a-valid-datetime"},
            headers=auth_header(owner_token),
        )
        assert bad_patch.status_code == 400
        assert "Invalid auto_delete_at format" in bad_patch.get_json()["error"]
