"""
Unit and integration tests for app/files/routes.py.

Covers:
- File upload success (multipart form-data, encryption at rest, database record creation)
- Rejection of empty file uploads (400 Empty file)
- Rejection of missing file field in form data (400 No file provided)
- Filename sanitization on upload
- Authentication enforcement on upload (401)
- User isolation in list_files (only returns files owned by the authenticated user)
- Listing files for a user with no files returns empty list (200)
- Authentication enforcement on list_files (401)
"""

import io
import os
import uuid
from datetime import datetime, timedelta, timezone
from app.models import File, Share, UploadSession
from app.crypto.file_crypto import decrypt_file
from app.files.routes import _get_upload_staging_dir, cleanup_orphaned_upload_sessions



def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


class TestFileUpload:
    """Tests for POST /api/files endpoint."""

    def test_upload_file_success(self, client, owner, owner_token, app, db):
        """Uploading a valid non-empty file encrypts it, persists it, and returns 201 with file metadata."""
        content = b"Confidential quarterly report contents"
        filename = "quarterly_report.txt"

        res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(content), filename)},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )

        assert res.status_code == 201
        data = res.get_json()
        assert "file" in data
        file_info = data["file"]
        assert file_info["filename"] == filename
        assert file_info["size_bytes"] == len(content)
        assert "id" in file_info

        # Verify DB persistence and envelope encryption
        with app.app_context():
            file_record = db.session.get(File, uuid.UUID(file_info["id"]))
            assert file_record is not None
            assert file_record.filename == filename
            assert file_record.owner_id == owner.id
            assert file_record.size_bytes == len(content)
            assert len(file_record.wrapped_key_hex) == 120
            assert len(file_record.nonce_hex) == 24

            # Verify file decrypts to original plaintext
            decrypted = decrypt_file(
                file_record.encrypted_path,
                file_record.nonce_hex,
                file_record.wrapped_key_hex,
            )
            assert decrypted == content

    def test_upload_empty_file_rejected(self, client, owner_token):
        """Uploading an empty (0 bytes) file returns 400 with 'Empty file' error."""
        res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b""), "empty.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )

        assert res.status_code == 400
        data = res.get_json()
        assert data["error"] == "Empty file"

    def test_upload_missing_file_field_rejected(self, client, owner_token):
        """A POST request missing the 'file' multipart field returns 400 with 'No file provided'."""
        res = client.post(
            "/api/files",
            data={"other_param": "some_value"},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )

        assert res.status_code == 400
        data = res.get_json()
        assert data["error"] == "No file provided"

    def test_upload_unauthorized_rejected(self, client):
        """Uploading without an authorization header returns 401."""
        res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"unauthorized payload"), "test.txt")},
            content_type="multipart/form-data",
        )

        assert res.status_code == 401
        data = res.get_json()
        assert data["error"] == "Missing authentication token"

    def test_upload_sanitizes_filename(self, client, owner_token):
        """Path traversal or dangerous characters in filenames are sanitized using secure_filename."""
        res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"payload"), "../../../evil_traversal.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )

        assert res.status_code == 201
        data = res.get_json()
        assert data["file"]["filename"] == "evil_traversal.txt"


class TestFileList:
    """Tests for GET /api/files endpoint."""

    def test_list_files_only_returns_current_user_files(
        self, client, owner, owner_token, recipient, recipient_token
    ):
        """
        GET /api/files returns only files owned by the authenticated user,
        never exposing files belonging to other users.
        """
        # Owner uploads 2 files
        res1 = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"owner document 1"), "owner_doc1.pdf")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        assert res1.status_code == 201
        owner_file1_id = res1.get_json()["file"]["id"]

        res2 = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"owner document 2"), "owner_doc2.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        assert res2.status_code == 201
        owner_file2_id = res2.get_json()["file"]["id"]

        # Recipient uploads 1 file
        res3 = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"recipient document"), "recipient_doc.txt")},
            headers=auth_header(recipient_token),
            content_type="multipart/form-data",
        )
        assert res3.status_code == 201
        recipient_file_id = res3.get_json()["file"]["id"]

        # 1. Owner lists files -> should receive exactly the 2 owner files
        res_owner = client.get("/api/files", headers=auth_header(owner_token))
        assert res_owner.status_code == 200
        owner_files = res_owner.get_json()["files"]
        assert len(owner_files) == 2
        owner_file_ids = {f["id"] for f in owner_files}
        assert owner_file_ids == {owner_file1_id, owner_file2_id}
        assert recipient_file_id not in owner_file_ids

        # 2. Recipient lists files -> should receive exactly 1 recipient file
        res_recipient = client.get("/api/files", headers=auth_header(recipient_token))
        assert res_recipient.status_code == 200
        recipient_files = res_recipient.get_json()["files"]
        assert len(recipient_files) == 1
        assert recipient_files[0]["id"] == recipient_file_id
        assert recipient_files[0]["filename"] == "recipient_doc.txt"
        assert owner_file1_id not in {f["id"] for f in recipient_files}
        assert owner_file2_id not in {f["id"] for f in recipient_files}

    def test_list_files_empty_for_user_with_no_files(self, client, owner_token):
        """A user who has not uploaded any files receives an empty list."""
        res = client.get("/api/files", headers=auth_header(owner_token))
        assert res.status_code == 200
        data = res.get_json()
        assert data["files"] == []
        assert data["total"] == 0
        assert data["page"] == 1

    def test_list_files_unauthorized_rejected(self, client):
        """GET /api/files without an authorization header returns 401."""
        res = client.get("/api/files")
        assert res.status_code == 401
        data = res.get_json()
        assert data["error"] == "Missing authentication token"


class TestFileDelete:
    """Tests for DELETE /api/files/<uuid:file_id> endpoint."""

    def test_delete_file_success(self, client, owner, owner_token, app, db):
        """Owner can delete file; revokes active shares, deletes disk blob, cascades DB rows."""
        # 1. Upload a file
        content = b"File to be deleted permanently"
        upload_res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(content), "to_delete.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        assert upload_res.status_code == 201
        file_id = upload_res.get_json()["file"]["id"]

        # 2. Create a share for the file
        share_res = client.post(
            f"/api/files/{file_id}/share",
            json={"permissions": {"can_view": True, "can_download": True}},
            headers=auth_header(owner_token),
        )
        assert share_res.status_code == 201
        share_token = share_res.get_json()["shares"][0]["share_token"]

        with app.app_context():
            file_rec = db.session.get(File, uuid.UUID(file_id))
            assert file_rec is not None
            disk_path = file_rec.encrypted_path
            assert os.path.exists(disk_path)

        # 3. Soft delete file
        del_res = client.delete(f"/api/files/{file_id}", headers=auth_header(owner_token))
        assert del_res.status_code == 200
        assert del_res.get_json()["message"] == "File deleted successfully"

        # 4. Verify disk blob is preserved (soft-delete!)
        assert os.path.exists(disk_path)

        # 5. Verify DB record has deleted_at set and shares are revoked
        with app.app_context():
            f_check = db.session.get(File, uuid.UUID(file_id))
            assert f_check is not None
            assert f_check.deleted_at is not None
            shares = Share.query.filter_by(file_id=uuid.UUID(file_id)).all()
            assert len(shares) > 0
            assert all(s.is_revoked for s in shares)

        # 6. Verify accessing share returns 410 (revoked)
        access_res = client.get(f"/api/shares/{share_token}/access")
        assert access_res.status_code == 410

        # 7. Permanent deletion purges blob and DB row
        perm_res = client.delete(f"/api/files/{file_id}?permanent=true", headers=auth_header(owner_token))
        assert perm_res.status_code == 200
        assert not os.path.exists(disk_path)
        with app.app_context():
            assert db.session.get(File, uuid.UUID(file_id)) is None

    def test_delete_file_non_owner_forbidden(
        self, client, owner, owner_token, recipient, recipient_token, app, db
    ):
        """Non-owner attempting to delete a file receives 403 Forbidden."""
        upload_res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"Owner private file"), "owner_doc.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = upload_res.get_json()["file"]["id"]

        del_res = client.delete(f"/api/files/{file_id}", headers=auth_header(recipient_token))
        assert del_res.status_code == 403
        assert del_res.get_json()["error"] == "Forbidden"

        with app.app_context():
            assert db.session.get(File, uuid.UUID(file_id)) is not None

    def test_delete_file_not_found(self, client, owner_token):
        """Deleting a non-existent file ID returns 404."""
        del_res = client.delete(f"/api/files/{uuid.uuid4()}", headers=auth_header(owner_token))
        assert del_res.status_code == 404
        assert del_res.get_json()["error"] == "File not found"

    def test_delete_file_unauthorized(self, client):
        """Deleting without authentication returns 401."""
        del_res = client.delete(f"/api/files/{uuid.uuid4()}")
        assert del_res.status_code == 401
        assert del_res.get_json()["error"] == "Missing authentication token"


class TestFileRename:
    """Tests for PATCH /api/files/<uuid:file_id> endpoint."""

    def test_rename_file_success(self, client, owner, owner_token, app, db):
        """Owner can successfully rename a file; mime_type and size_bytes remain intact."""
        upload_res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"Original contents"), "original_name.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = upload_res.get_json()["file"]["id"]

        patch_res = client.patch(
            f"/api/files/{file_id}",
            json={"filename": "new_annual_report.txt"},
            headers=auth_header(owner_token),
        )
        assert patch_res.status_code == 200
        data = patch_res.get_json()
        assert data["file"]["filename"] == "new_annual_report.txt"
        assert data["file"]["size_bytes"] == len(b"Original contents")

        with app.app_context():
            file_rec = db.session.get(File, uuid.UUID(file_id))
            assert file_rec.filename == "new_annual_report.txt"
            assert file_rec.size_bytes == len(b"Original contents")

    def test_rename_file_sanitizes_filename(self, client, owner, owner_token):
        """Renaming a file with directory traversal or unsafe chars sanitizes the name."""
        upload_res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"Content"), "normal.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = upload_res.get_json()["file"]["id"]

        patch_res = client.patch(
            f"/api/files/{file_id}",
            json={"filename": "../../../safe_renamed.txt"},
            headers=auth_header(owner_token),
        )
        assert patch_res.status_code == 200
        assert patch_res.get_json()["file"]["filename"] == "safe_renamed.txt"

    def test_rename_file_rejects_mime_type_or_size_change(self, client, owner, owner_token):
        """Attempting to modify mime_type or size_bytes via PATCH returns 400."""
        upload_res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"Content"), "doc.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = upload_res.get_json()["file"]["id"]

        # Attempt to change mime_type
        res_mime = client.patch(
            f"/api/files/{file_id}",
            json={"filename": "renamed.txt", "mime_type": "text/html"},
            headers=auth_header(owner_token),
        )
        assert res_mime.status_code == 400
        assert res_mime.get_json()["error"] == "mime_type and size_bytes cannot be modified"

        # Attempt to change size_bytes
        res_size = client.patch(
            f"/api/files/{file_id}",
            json={"filename": "renamed.txt", "size_bytes": 99999},
            headers=auth_header(owner_token),
        )
        assert res_size.status_code == 400
        assert res_size.get_json()["error"] == "mime_type and size_bytes cannot be modified"

    def test_rename_file_empty_filename_rejected(self, client, owner, owner_token):
        """Empty, missing, or purely unsafe filename returns 400."""
        upload_res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"Content"), "doc.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = upload_res.get_json()["file"]["id"]

        # Missing filename
        res_missing = client.patch(
            f"/api/files/{file_id}",
            json={},
            headers=auth_header(owner_token),
        )
        assert res_missing.status_code == 400
        assert res_missing.get_json()["error"] == "Filename is required"

        # Empty string filename
        res_empty = client.patch(
            f"/api/files/{file_id}",
            json={"filename": "   "},
            headers=auth_header(owner_token),
        )
        assert res_empty.status_code == 400
        assert res_empty.get_json()["error"] == "Filename cannot be empty"

        # Dot-only filename (sanitizes to empty)
        res_dots = client.patch(
            f"/api/files/{file_id}",
            json={"filename": "..."},
            headers=auth_header(owner_token),
        )
        assert res_dots.status_code == 400
        assert res_dots.get_json()["error"] == "Invalid filename"

    def test_rename_file_non_owner_forbidden(
        self, client, owner, owner_token, recipient, recipient_token
    ):
        """Non-owner attempting to rename a file receives 403 Forbidden."""
        upload_res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"Content"), "doc.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = upload_res.get_json()["file"]["id"]

        res = client.patch(
            f"/api/files/{file_id}",
            json={"filename": "hijacked.txt"},
            headers=auth_header(recipient_token),
        )
        assert res.status_code == 403
        assert res.get_json()["error"] == "Forbidden"

    def test_rename_file_not_found(self, client, owner_token):
        """Renaming a non-existent file returns 404."""
        res = client.patch(
            f"/api/files/{uuid.uuid4()}",
            json={"filename": "new.txt"},
            headers=auth_header(owner_token),
        )
        assert res.status_code == 404
        assert res.get_json()["error"] == "File not found"

    def test_rename_file_unauthorized(self, client):
        """Renaming without authentication returns 401."""
        res = client.patch(
            f"/api/files/{uuid.uuid4()}",
            json={"filename": "new.txt"},
        )
        assert res.status_code == 401
        assert res.get_json()["error"] == "Missing authentication token"


class TestFileListPaginationSearchAndSort:
    """Tests for pagination, sorting, and search on GET /api/files."""

    def _upload(self, client, token, filename, content=b"sample content"):
        res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(content), filename)},
            headers=auth_header(token),
            content_type="multipart/form-data",
        )
        assert res.status_code == 201
        return res.get_json()["file"]

    def test_list_files_pagination_basic(self, client, owner_token):
        """Verify page, per_page, total, and pages metadata across multiple pages."""
        for i in range(1, 6):
            self._upload(client, owner_token, f"page_file_{i}.txt")

        # Page 1 (2 per page)
        res1 = client.get("/api/files?page=1&per_page=2", headers=auth_header(owner_token))
        assert res1.status_code == 200
        d1 = res1.get_json()
        assert len(d1["files"]) == 2
        assert len(d1["items"]) == 2
        assert d1["total"] == 5
        assert d1["page"] == 1
        assert d1["per_page"] == 2
        assert d1["pages"] == 3

        # Page 2 (2 per page)
        res2 = client.get("/api/files?page=2&per_page=2", headers=auth_header(owner_token))
        assert res2.status_code == 200
        d2 = res2.get_json()
        assert len(d2["files"]) == 2
        assert d2["page"] == 2
        # Ensure page 2 items are distinct from page 1
        p1_ids = {f["id"] for f in d1["files"]}
        p2_ids = {f["id"] for f in d2["files"]}
        assert p1_ids.isdisjoint(p2_ids)

        # Page 3 (1 remainder item)
        res3 = client.get("/api/files?page=3&per_page=2", headers=auth_header(owner_token))
        assert res3.status_code == 200
        d3 = res3.get_json()
        assert len(d3["files"]) == 1
        assert d3["page"] == 3

        # Page 4 (out of range)
        res4 = client.get("/api/files?page=4&per_page=2", headers=auth_header(owner_token))
        assert res4.status_code == 200
        d4 = res4.get_json()
        assert len(d4["files"]) == 0
        assert d4["total"] == 5

    def test_list_files_per_page_capped_at_100(self, client, owner_token):
        """per_page parameter is capped at 100 maximum."""
        self._upload(client, owner_token, "cap_test.txt")
        res = client.get("/api/files?per_page=500", headers=auth_header(owner_token))
        assert res.status_code == 200
        data = res.get_json()
        assert data["per_page"] == 100

    def test_list_files_search_by_filename(self, client, owner_token):
        """Search filters files by case-insensitive filename substring."""
        self._upload(client, owner_token, "budget_2026.xlsx")
        self._upload(client, owner_token, "annual_report_2026.pdf")
        self._upload(client, owner_token, "meeting_notes.txt")

        # Search substring "2026"
        res1 = client.get("/api/files?search=2026", headers=auth_header(owner_token))
        assert res1.status_code == 200
        files1 = res1.get_json()["files"]
        assert len(files1) == 2
        assert {f["filename"] for f in files1} == {"budget_2026.xlsx", "annual_report_2026.pdf"}

        # Case-insensitive substring "BUDGET"
        res2 = client.get("/api/files?search=BUDGET", headers=auth_header(owner_token))
        assert res2.status_code == 200
        files2 = res2.get_json()["files"]
        assert len(files2) == 1
        assert files2[0]["filename"] == "budget_2026.xlsx"

        # Search via 'q' parameter alias
        res3 = client.get("/api/files?q=notes", headers=auth_header(owner_token))
        assert res3.status_code == 200
        files3 = res3.get_json()["files"]
        assert len(files3) == 1
        assert files3[0]["filename"] == "meeting_notes.txt"

        # Search with no matching files
        res4 = client.get("/api/files?search=nonexistent_query", headers=auth_header(owner_token))
        assert res4.status_code == 200
        data4 = res4.get_json()
        assert data4["files"] == []
        assert data4["total"] == 0

    def test_list_files_sort_by_name(self, client, owner_token):
        """Sort by filename ascending (default) and descending."""
        self._upload(client, owner_token, "zebra.txt")
        self._upload(client, owner_token, "apple.txt")
        self._upload(client, owner_token, "banana.txt")

        # Ascending (default for name)
        res_asc = client.get("/api/files?sort=name", headers=auth_header(owner_token))
        assert res_asc.status_code == 200
        names_asc = [f["filename"] for f in res_asc.get_json()["files"]]
        assert names_asc == ["apple.txt", "banana.txt", "zebra.txt"]

        # Descending
        res_desc = client.get("/api/files?sort=name&order=desc", headers=auth_header(owner_token))
        assert res_desc.status_code == 200
        names_desc = [f["filename"] for f in res_desc.get_json()["files"]]
        assert names_desc == ["zebra.txt", "banana.txt", "apple.txt"]

    def test_list_files_sort_by_size(self, client, owner_token):
        """Sort by file size descending (default for size) and ascending."""
        self._upload(client, owner_token, "small.txt", content=b"12345")  # 5 bytes
        self._upload(client, owner_token, "large.txt", content=b"x" * 100)  # 100 bytes
        self._upload(client, owner_token, "medium.txt", content=b"y" * 50)  # 50 bytes

        # Descending (default for size)
        res_desc = client.get("/api/files?sort=size", headers=auth_header(owner_token))
        assert res_desc.status_code == 200
        sizes_desc = [f["size_bytes"] for f in res_desc.get_json()["files"]]
        assert sizes_desc == [100, 50, 5]

        # Ascending
        res_asc = client.get("/api/files?sort=size&order=asc", headers=auth_header(owner_token))
        assert res_asc.status_code == 200
        sizes_asc = [f["size_bytes"] for f in res_asc.get_json()["files"]]
        assert sizes_asc == [5, 50, 100]

    def test_list_files_sort_by_date(self, client, owner_token):
        """Sort by created_at descending (default) and ascending."""
        self._upload(client, owner_token, "first.txt")
        self._upload(client, owner_token, "second.txt")
        self._upload(client, owner_token, "third.txt")

        # Default is date desc
        res_default = client.get("/api/files", headers=auth_header(owner_token))
        assert res_default.status_code == 200
        names_default = [f["filename"] for f in res_default.get_json()["files"]]
        assert names_default == ["third.txt", "second.txt", "first.txt"]

        # Date asc
        res_asc = client.get("/api/files?sort=date&order=asc", headers=auth_header(owner_token))
        assert res_asc.status_code == 200
        names_asc = [f["filename"] for f in res_asc.get_json()["files"]]
        assert names_asc == ["first.txt", "second.txt", "third.txt"]

    def test_list_files_combined_search_sort_and_pagination(self, client, owner_token):
        """Combined test of search filtering, alphabetical sorting, and pagination."""
        self._upload(client, owner_token, "archive_gamma.txt")
        self._upload(client, owner_token, "archive_alpha.txt")
        self._upload(client, owner_token, "archive_beta.txt")
        self._upload(client, owner_token, "unrelated.txt")

        # Search for archive, sort by name asc, page 1 (2 per page)
        res1 = client.get(
            "/api/files?search=archive&sort=name&page=1&per_page=2",
            headers=auth_header(owner_token),
        )
        assert res1.status_code == 200
        d1 = res1.get_json()
        assert d1["total"] == 3
        assert d1["pages"] == 2
        assert [f["filename"] for f in d1["files"]] == ["archive_alpha.txt", "archive_beta.txt"]

        # Page 2
        res2 = client.get(
            "/api/files?search=archive&sort=name&page=2&per_page=2",
            headers=auth_header(owner_token),
        )
        assert res2.status_code == 200
        d2 = res2.get_json()
        assert [f["filename"] for f in d2["files"]] == ["archive_gamma.txt"]


class TestChunkedUpload:
    """Tests for chunked upload endpoints (POST /api/files/uploads, PUT .../chunks/<idx>, POST .../complete)."""

    def test_chunked_upload_multi_chunk_success(self, client, owner, owner_token, app, db):
        """A 3-chunk upload completes successfully, reassembles chunks in order, and encrypts file."""
        chunk0 = b"CHUNK_ZERO_"
        chunk1 = b"CHUNK_ONE_"
        chunk2 = b"CHUNK_TWO"
        expected_content = chunk0 + chunk1 + chunk2
        filename = "large_assembled_file.bin"

        # 1. Start upload session
        res_start = client.post(
            "/api/files/uploads",
            json={
                "filename": filename,
                "mime_type": "application/octet-stream",
                "expected_chunks": 3,
                "total_size_bytes": len(expected_content),
            },
            headers=auth_header(owner_token),
        )
        assert res_start.status_code == 201
        data_start = res_start.get_json()
        assert "upload_id" in data_start
        upload_id = uuid.UUID(data_start["upload_id"])
        session_info = data_start["session"]
        assert session_info["expected_chunks"] == 3
        assert session_info["received_chunks"] == 0
        assert session_info["status"] == "in_progress"

        staging_dir = _get_upload_staging_dir(upload_id)
        assert os.path.exists(staging_dir)

        # 2. Upload chunks in arbitrary order (chunk 1 first, then 0, then 2)
        res_c1 = client.put(
            f"/api/files/uploads/{upload_id}/chunks/1",
            data=chunk1,
            headers={"Content-Type": "application/octet-stream", **auth_header(owner_token)},
        )
        assert res_c1.status_code == 200
        assert res_c1.get_json()["received_chunks"] == 1

        res_c0 = client.put(
            f"/api/files/uploads/{upload_id}/chunks/0",
            data=chunk0,
            headers={"Content-Type": "application/octet-stream", **auth_header(owner_token)},
        )
        assert res_c0.status_code == 200
        assert res_c0.get_json()["received_chunks"] == 2

        res_c2 = client.put(
            f"/api/files/uploads/{upload_id}/chunks/2",
            data=chunk2,
            headers={"Content-Type": "application/octet-stream", **auth_header(owner_token)},
        )
        assert res_c2.status_code == 200
        assert res_c2.get_json()["received_chunks"] == 3

        # Check session status before completion
        res_status = client.get(
            f"/api/files/uploads/{upload_id}",
            headers=auth_header(owner_token),
        )
        assert res_status.status_code == 200
        status_data = res_status.get_json()["session"]
        assert status_data["received_chunks"] == 3
        assert status_data["received_chunk_indices"] == [0, 1, 2]
        assert status_data["missing_chunk_indices"] == []

        # 3. Complete upload
        res_complete = client.post(
            f"/api/files/uploads/{upload_id}/complete",
            json={},
            headers=auth_header(owner_token),
        )
        assert res_complete.status_code == 201
        data_complete = res_complete.get_json()
        assert "file" in data_complete
        file_info = data_complete["file"]
        assert file_info["filename"] == filename
        assert file_info["size_bytes"] == len(expected_content)

        # Verify DB persistence, encryption, and decrypted content
        with app.app_context():
            file_record = db.session.get(File, uuid.UUID(file_info["id"]))
            assert file_record is not None
            assert file_record.owner_id == owner.id
            assert file_record.size_bytes == len(expected_content)

            decrypted = decrypt_file(
                file_record.encrypted_path,
                file_record.nonce_hex,
                file_record.wrapped_key_hex,
            )
            assert decrypted == expected_content

            session_record = db.session.get(UploadSession, upload_id)
            assert session_record.status == "completed"

        # Staging directory should be cleaned up
        assert not os.path.exists(staging_dir)

    def test_chunked_upload_missing_chunk_rejected(self, client, owner_token, app, db):
        """Completion attempt with missing chunks returns 400 and lists missing chunk indices."""
        chunk0 = b"FIRST_PART"
        chunk2 = b"THIRD_PART"

        # 1. Start session for 3 chunks
        res_start = client.post(
            "/api/files/uploads",
            json={
                "filename": "gap_file.txt",
                "expected_chunks": 3,
            },
            headers=auth_header(owner_token),
        )
        assert res_start.status_code == 201
        upload_id = res_start.get_json()["upload_id"]

        # 2. Upload chunk 0 and chunk 2 (chunk 1 is missing)
        res_c0 = client.put(
            f"/api/files/uploads/{upload_id}/chunks/0",
            data=chunk0,
            headers=auth_header(owner_token),
        )
        assert res_c0.status_code == 200

        res_c2 = client.put(
            f"/api/files/uploads/{upload_id}/chunks/2",
            data=chunk2,
            headers=auth_header(owner_token),
        )
        assert res_c2.status_code == 200

        # 3. Attempt completion before uploading chunk 1
        res_complete_fail = client.post(
            f"/api/files/uploads/{upload_id}/complete",
            json={},
            headers=auth_header(owner_token),
        )
        assert res_complete_fail.status_code == 400
        data_fail = res_complete_fail.get_json()
        assert data_fail["error"] == "Missing chunks"
        assert data_fail["missing_chunks"] == [1]

        # Verify session is still in_progress in DB
        with app.app_context():
            session_rec = db.session.get(UploadSession, uuid.UUID(upload_id))
            assert session_rec.status == "in_progress"

        # 4. Supply the missing chunk 1
        chunk1 = b"MIDDLE_PART"
        res_c1 = client.put(
            f"/api/files/uploads/{upload_id}/chunks/1",
            data=chunk1,
            headers=auth_header(owner_token),
        )
        assert res_c1.status_code == 200

        # 5. Complete successfully now that all chunks are present
        res_complete_ok = client.post(
            f"/api/files/uploads/{upload_id}/complete",
            json={},
            headers=auth_header(owner_token),
        )
        assert res_complete_ok.status_code == 201
        file_id = res_complete_ok.get_json()["file"]["id"]

        with app.app_context():
            file_rec = db.session.get(File, uuid.UUID(file_id))
            decrypted = decrypt_file(
                file_rec.encrypted_path,
                file_rec.nonce_hex,
                file_rec.wrapped_key_hex,
            )
            assert decrypted == chunk0 + chunk1 + chunk2

    def test_chunked_upload_invalid_chunk_index(self, client, owner_token):
        """Chunk index >= expected_chunks returns 400."""
        res_start = client.post(
            "/api/files/uploads",
            json={"filename": "bound_test.txt", "expected_chunks": 2},
            headers=auth_header(owner_token),
        )
        assert res_start.status_code == 201
        upload_id = res_start.get_json()["upload_id"]

        # Index 2 is out of range for expected_chunks = 2 (valid indices: 0, 1)
        res_bad = client.put(
            f"/api/files/uploads/{upload_id}/chunks/2",
            data=b"illegal chunk",
            headers=auth_header(owner_token),
        )
        assert res_bad.status_code == 400
        assert "Invalid chunk index" in res_bad.get_json()["error"]

    def test_chunked_upload_empty_chunk_rejected(self, client, owner_token):
        """Uploading an empty chunk returns 400 Empty chunk."""
        res_start = client.post(
            "/api/files/uploads",
            json={"filename": "empty_chunk.txt", "expected_chunks": 2},
            headers=auth_header(owner_token),
        )
        upload_id = res_start.get_json()["upload_id"]

        res_empty = client.put(
            f"/api/files/uploads/{upload_id}/chunks/0",
            data=b"",
            headers=auth_header(owner_token),
        )
        assert res_empty.status_code == 400
        assert res_empty.get_json()["error"] == "Empty chunk"

    def test_chunked_upload_unauthorized_and_forbidden(self, client, owner_token, recipient_token):
        """Unauthenticated requests return 401 and non-owner access returns 403."""
        # Unauthenticated session creation
        res_unauth = client.post("/api/files/uploads", json={"expected_chunks": 2})
        assert res_unauth.status_code == 401

        # Create session as owner
        res_start = client.post(
            "/api/files/uploads",
            json={"expected_chunks": 2},
            headers=auth_header(owner_token),
        )
        upload_id = res_start.get_json()["upload_id"]

        # Recipient attempts to upload chunk
        res_forbid_chunk = client.put(
            f"/api/files/uploads/{upload_id}/chunks/0",
            data=b"chunk data",
            headers=auth_header(recipient_token),
        )
        assert res_forbid_chunk.status_code == 403

        # Recipient attempts to complete session
        res_forbid_complete = client.post(
            f"/api/files/uploads/{upload_id}/complete",
            json={},
            headers=auth_header(recipient_token),
        )
        assert res_forbid_complete.status_code == 403

        # Recipient attempts to get session status
        res_forbid_get = client.get(
            f"/api/files/uploads/{upload_id}",
            headers=auth_header(recipient_token),
        )
        assert res_forbid_get.status_code == 403

    def test_chunked_upload_session_not_found(self, client, owner_token):
        """Operations on non-existent upload_id return 404."""
        random_id = uuid.uuid4()
        res_chunk = client.put(
            f"/api/files/uploads/{random_id}/chunks/0",
            data=b"data",
            headers=auth_header(owner_token),
        )
        assert res_chunk.status_code == 404

        res_comp = client.post(
            f"/api/files/uploads/{random_id}/complete",
            headers=auth_header(owner_token),
        )
        assert res_comp.status_code == 404

        res_get = client.get(
            f"/api/files/uploads/{random_id}",
            headers=auth_header(owner_token),
        )
        assert res_get.status_code == 404

    def test_chunked_upload_already_completed_rejected(self, client, owner_token):
        """Actions on already completed session return 400."""
        res_start = client.post(
            "/api/files/uploads",
            json={"filename": "once.txt", "expected_chunks": 1},
            headers=auth_header(owner_token),
        )
        upload_id = res_start.get_json()["upload_id"]

        # Upload chunk 0
        client.put(
            f"/api/files/uploads/{upload_id}/chunks/0",
            data=b"hello single chunk",
            headers=auth_header(owner_token),
        )

        # Complete
        res_done = client.post(
            f"/api/files/uploads/{upload_id}/complete",
            headers=auth_header(owner_token),
        )
        assert res_done.status_code == 201

        # Attempt to upload another chunk to completed session
        res_rechunk = client.put(
            f"/api/files/uploads/{upload_id}/chunks/0",
            data=b"another chunk",
            headers=auth_header(owner_token),
        )
        assert res_rechunk.status_code == 400
        assert res_rechunk.get_json()["error"] == "Upload session already completed"

        # Attempt to complete again
        res_recomp = client.post(
            f"/api/files/uploads/{upload_id}/complete",
            headers=auth_header(owner_token),
        )
        assert res_recomp.status_code == 400
        assert res_recomp.get_json()["error"] == "Upload session already completed"

    def test_chunked_upload_with_form_data(self, client, owner_token):
        """Chunks uploaded as multipart/form-data with a file field are handled properly."""
        res_start = client.post(
            "/api/files/uploads",
            json={"filename": "form_chunk.txt", "expected_chunks": 1},
            headers=auth_header(owner_token),
        )
        upload_id = res_start.get_json()["upload_id"]

        chunk_data = b"Data sent as form-data"
        res_put = client.put(
            f"/api/files/uploads/{upload_id}/chunks/0",
            data={"chunk": (io.BytesIO(chunk_data), "chunk0.part")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        assert res_put.status_code == 200

        res_complete = client.post(
            f"/api/files/uploads/{upload_id}/complete",
            headers=auth_header(owner_token),
        )
        assert res_complete.status_code == 201

    def test_cleanup_orphaned_sessions(self, client, owner, app, db):
        """Expired in_progress upload sessions are cleaned up by cleanup_orphaned_upload_sessions."""
        with app.app_context():
            # Create an old session created 48 hours ago
            old_id = uuid.uuid4()
            old_staging_dir = _get_upload_staging_dir(old_id)
            dummy_chunk = os.path.join(old_staging_dir, "chunk_0.part")
            with open(dummy_chunk, "wb") as f:
                f.write(b"old orphaned chunk")

            old_session = UploadSession(
                id=old_id,
                owner_id=owner.id,
                filename="old_abandoned.bin",
                expected_chunks=2,
                received_chunks=1,
                status="in_progress",
                created_at=datetime.now(timezone.utc) - timedelta(hours=48),
            )
            db.session.add(old_session)
            db.session.commit()

            assert os.path.exists(old_staging_dir)

            # Run cleanup with max_age_hours=24
            cleaned_count = cleanup_orphaned_upload_sessions(max_age_hours=24)
            assert cleaned_count >= 1

            # Verify session record is removed and staging dir deleted
            session_refreshed = db.session.get(UploadSession, old_id)
            assert session_refreshed is None
            assert not os.path.exists(old_staging_dir)


class TestFileSearch:
    """Tests for GET /api/files/search endpoint."""

    def test_search_files_by_filename_and_tag(self, client, owner_token, recipient_token):
        """Search matches filename substring or tag name substring and is owner-scoped."""
        # 1. Seed owner files with various names and tags
        # File 1: filename matches 'budget', tag is 'finance'
        res1 = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"Alpha budget sheet"), "alpha_budget.pdf"), "tags": "finance,annual"},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        assert res1.status_code == 201
        f1_id = res1.get_json()["file"]["id"]

        # File 2: filename is 'project_spec.docx', tag matches 'budget'
        res2 = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"Project specification"), "project_spec.docx"), "tags": "budget,specs"},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        assert res2.status_code == 201
        f2_id = res2.get_json()["file"]["id"]

        # File 3: filename is 'meeting_notes.txt', tag is 'engineering'
        res3 = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"Team notes"), "meeting_notes.txt"), "tags": "engineering"},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        assert res3.status_code == 201
        f3_id = res3.get_json()["file"]["id"]

        # 2. Seed recipient file with 'budget' in filename and tag (to verify owner isolation)
        res_rec = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"Other budget"), "other_budget.pdf"), "tags": "budget"},
            headers=auth_header(recipient_token),
            content_type="multipart/form-data",
        )
        assert res_rec.status_code == 201
        f_rec_id = res_rec.get_json()["file"]["id"]

        # 3. Query for 'budget' as owner:
        # Should match f1 (by filename) and f2 (by tag 'budget'), but NOT f3 or f_rec
        res_search_budget = client.get("/api/files/search?q=budget", headers=auth_header(owner_token))
        assert res_search_budget.status_code == 200
        data_budget = res_search_budget.get_json()
        assert data_budget["total"] == 2
        assert data_budget["query"] == "budget"
        matched_ids = {f["id"] for f in data_budget["files"]}
        assert matched_ids == {f1_id, f2_id}
        assert f3_id not in matched_ids
        assert f_rec_id not in matched_ids

        # 4. Case-insensitive search: 'BUDGET'
        res_upper = client.get("/api/files/search?q=BUDGET", headers=auth_header(owner_token))
        assert res_upper.status_code == 200
        assert {f["id"] for f in res_upper.get_json()["files"]} == {f1_id, f2_id}

        # 5. Query for tag-only: 'engineering'
        res_search_eng = client.get("/api/files/search?q=engineering", headers=auth_header(owner_token))
        assert res_search_eng.status_code == 200
        eng_data = res_search_eng.get_json()
        assert eng_data["total"] == 1
        assert eng_data["files"][0]["id"] == f3_id

        # 6. Query for filename-only: 'project'
        res_search_proj = client.get("/api/files/search?q=project", headers=auth_header(owner_token))
        assert res_search_proj.status_code == 200
        proj_data = res_search_proj.get_json()
        assert proj_data["total"] == 1
        assert proj_data["files"][0]["id"] == f2_id

        # 7. Query with no matches
        res_no_match = client.get("/api/files/search?q=nonexistentquery", headers=auth_header(owner_token))
        assert res_no_match.status_code == 200
        assert res_no_match.get_json()["total"] == 0
        assert res_no_match.get_json()["files"] == []

        # 8. Empty query returns empty results
        res_empty = client.get("/api/files/search?q=", headers=auth_header(owner_token))
        assert res_empty.status_code == 200
        assert res_empty.get_json()["total"] == 0
        assert res_empty.get_json()["files"] == []

        res_no_q = client.get("/api/files/search", headers=auth_header(owner_token))
        assert res_no_q.status_code == 200
        assert res_no_q.get_json()["total"] == 0

        # 9. Recipient search is isolated to recipient's files
        res_rec_search = client.get("/api/files/search?q=budget", headers=auth_header(recipient_token))
        assert res_rec_search.status_code == 200
        rec_data = res_rec_search.get_json()
        assert rec_data["total"] == 1
        assert rec_data["files"][0]["id"] == f_rec_id

    def test_search_files_auth_required(self, client):
        """GET /api/files/search requires JWT authentication."""
        res = client.get("/api/files/search?q=budget")
        assert res.status_code == 401

    def test_search_files_pagination_and_sorting(self, client, owner_token):
        """Pagination and sorting work properly with search results."""
        # Seed 3 files matching 'report'
        for i in range(3):
            client.post(
                "/api/files",
                data={"file": (io.BytesIO(f"Report {i}".encode()), f"report_{i}.txt"), "tags": "reports"},
                headers=auth_header(owner_token),
                content_type="multipart/form-data",
            )

        # Page 1, per_page 2
        res_p1 = client.get("/api/files/search?q=report&page=1&per_page=2&sort=name&order=asc", headers=auth_header(owner_token))
        assert res_p1.status_code == 200
        data_p1 = res_p1.get_json()
        assert data_p1["total"] == 3
        assert len(data_p1["files"]) == 2
        assert data_p1["files"][0]["filename"] == "report_0.txt"
        assert data_p1["files"][1]["filename"] == "report_1.txt"

        # Page 2, per_page 2
        res_p2 = client.get("/api/files/search?q=report&page=2&per_page=2&sort=name&order=asc", headers=auth_header(owner_token))
        assert res_p2.status_code == 200
        data_p2 = res_p2.get_json()
        assert len(data_p2["files"]) == 1
        assert data_p2["files"][0]["filename"] == "report_2.txt"


class TestBulkFileOperations:
    """Tests for POST /api/files/bulk/delete, /bulk/move, and /bulk/tag endpoints."""

    def test_bulk_delete_all_valid(self, client, owner, owner_token, app, db):
        """Deleting multiple valid files revokes shares, deletes disk blobs, and removes rows."""
        # 1. Create 3 files
        file_ids = []
        for i in range(3):
            res = client.post(
                "/api/files",
                data={"file": (io.BytesIO(f"File content {i}".encode()), f"bulk_del_{i}.txt")},
                headers=auth_header(owner_token),
                content_type="multipart/form-data",
            )
            assert res.status_code == 201
            file_ids.append(res.get_json()["file"]["id"])

        # 2. Create a share for the first file
        share_res = client.post(
            f"/api/files/{file_ids[0]}/share",
            json={"permissions": {"can_view": True, "can_download": True}},
            headers=auth_header(owner_token),
        )
        assert share_res.status_code == 201
        share_token = share_res.get_json()["shares"][0]["share_token"]

        # 3. Perform bulk delete
        bulk_res = client.post(
            "/api/files/bulk/delete",
            json={"file_ids": file_ids},
            headers=auth_header(owner_token),
        )
        assert bulk_res.status_code == 200
        data = bulk_res.get_json()
        assert set(data["succeeded"]) == set(file_ids)
        assert data["failed"] == []
        assert data["total"] == 3
        assert data["success_count"] == 3
        assert data["failure_count"] == 0

        # 4. Verify files are gone from DB and share access returns 404
        with app.app_context():
            for fid in file_ids:
                assert db.session.get(File, uuid.UUID(fid)) is None

        access_res = client.get(f"/api/shares/{share_token}/access")
        assert access_res.status_code == 404

    def test_bulk_delete_mixed_batch_preserves_other_user_files(self, client, owner, owner_token, recipient, recipient_token, app, db):
        """
        In a mixed batch of file IDs:
        - Files owned by current user are deleted
        - Files owned by another user are silently skipped and reported as 'File not found'
        - Non-existent UUIDs are reported as 'File not found'
        - Another user's file is NOT deleted and remains intact on disk and DB
        """
        # 1. Owner creates 2 files
        owner_file_ids = []
        for i in range(2):
            res = client.post(
                "/api/files",
                data={"file": (io.BytesIO(f"Owner content {i}".encode()), f"owner_bulk_{i}.txt")},
                headers=auth_header(owner_token),
                content_type="multipart/form-data",
            )
            assert res.status_code == 201
            owner_file_ids.append(res.get_json()["file"]["id"])

        # 2. Recipient creates 1 file
        rec_res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"Recipient private data"), "recipient_secret.txt")},
            headers=auth_header(recipient_token),
            content_type="multipart/form-data",
        )
        assert rec_res.status_code == 201
        recipient_file_id = rec_res.get_json()["file"]["id"]

        fake_id = str(uuid.uuid4())

        # 3. Owner attempts bulk delete on mixed batch [Owner_0, Recipient_File, Owner_1, Fake_ID]
        mixed_batch = [owner_file_ids[0], recipient_file_id, owner_file_ids[1], fake_id]
        bulk_res = client.post(
            "/api/files/bulk/delete",
            json={"file_ids": mixed_batch},
            headers=auth_header(owner_token),
        )
        assert bulk_res.status_code == 200
        data = bulk_res.get_json()

        # Owner's files succeeded
        assert set(data["succeeded"]) == set(owner_file_ids)
        assert data["success_count"] == 2
        assert data["failure_count"] == 2

        # Failures report 'File not found' without leaking recipient's ownership
        failed_entries = {f["id"]: f["error"] for f in data["failed"]}
        assert recipient_file_id in failed_entries
        assert failed_entries[recipient_file_id] == "File not found"
        assert fake_id in failed_entries
        assert failed_entries[fake_id] == "File not found"

        # 4. Verify in DB: owner's files are deleted, recipient's file is intact
        with app.app_context():
            assert db.session.get(File, uuid.UUID(owner_file_ids[0])) is None
            assert db.session.get(File, uuid.UUID(owner_file_ids[1])) is None
            rec_file = db.session.get(File, uuid.UUID(recipient_file_id))
            assert rec_file is not None
            assert rec_file.owner_id == recipient.id
            assert os.path.exists(rec_file.encrypted_path)

    def test_bulk_move_files_success_and_to_root(self, client, owner_token, app, db):
        """Bulk move files into a folder, and subsequently back to root."""
        # Create folder
        folder_res = client.post(
            "/api/folders",
            json={"name": "Bulk Target Folder"},
            headers=auth_header(owner_token),
        )
        assert folder_res.status_code == 201
        folder_id = folder_res.get_json()["folder"]["id"]

        # Create 2 files
        file_ids = []
        for i in range(2):
            res = client.post(
                "/api/files",
                data={"file": (io.BytesIO(f"Data {i}".encode()), f"move_{i}.txt")},
                headers=auth_header(owner_token),
                content_type="multipart/form-data",
            )
            assert res.status_code == 201
            file_ids.append(res.get_json()["file"]["id"])

        # 1. Bulk move into folder
        move_res = client.post(
            "/api/files/bulk/move",
            json={"file_ids": file_ids, "folder_id": folder_id},
            headers=auth_header(owner_token),
        )
        assert move_res.status_code == 200
        data = move_res.get_json()
        assert set(data["succeeded"]) == set(file_ids)
        assert data["failed"] == []

        # Verify in DB
        with app.app_context():
            for fid in file_ids:
                f = db.session.get(File, uuid.UUID(fid))
                assert str(f.folder_id) == folder_id

        # 2. Bulk move back to root (folder_id=null)
        root_res = client.post(
            "/api/files/bulk/move",
            json={"file_ids": file_ids, "folder_id": None},
            headers=auth_header(owner_token),
        )
        assert root_res.status_code == 200
        root_data = root_res.get_json()
        assert set(root_data["succeeded"]) == set(file_ids)
        assert root_data["folder_id"] is None

        with app.app_context():
            for fid in file_ids:
                f = db.session.get(File, uuid.UUID(fid))
                assert f.folder_id is None

    def test_bulk_move_mixed_batch_with_other_user_file(self, client, owner_token, recipient_token, app, db):
        """Bulk move silently skips files belonging to another user and reports 'File not found'."""
        # Owner folder
        folder_res = client.post(
            "/api/folders",
            json={"name": "Owner Project"},
            headers=auth_header(owner_token),
        )
        folder_id = folder_res.get_json()["folder"]["id"]

        # Owner file
        f1_res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"Owner file"), "owner_mov.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        f1_id = f1_res.get_json()["file"]["id"]

        # Recipient file
        f2_res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"Recipient file"), "rec_mov.txt")},
            headers=auth_header(recipient_token),
            content_type="multipart/form-data",
        )
        f2_id = f2_res.get_json()["file"]["id"]

        # Move both
        move_res = client.post(
            "/api/files/bulk/move",
            json={"file_ids": [f1_id, f2_id], "folder_id": folder_id},
            headers=auth_header(owner_token),
        )
        assert move_res.status_code == 200
        data = move_res.get_json()
        assert data["succeeded"] == [f1_id]
        assert len(data["failed"]) == 1
        assert data["failed"][0]["id"] == f2_id
        assert data["failed"][0]["error"] == "File not found"

        with app.app_context():
            f1 = db.session.get(File, uuid.UUID(f1_id))
            assert str(f1.folder_id) == folder_id
            f2 = db.session.get(File, uuid.UUID(f2_id))
            assert f2.folder_id is None  # Untouched

    def test_bulk_move_folder_validation(self, client, owner_token, recipient_token):
        """Bulk move rejects non-existent folders (404) and other users' folders (403)."""
        # 1. Other user's folder
        rec_folder = client.post(
            "/api/folders",
            json={"name": "Recipient Folder"},
            headers=auth_header(recipient_token),
        ).get_json()["folder"]["id"]

        res_forbidden = client.post(
            "/api/files/bulk/move",
            json={"file_ids": [], "folder_id": rec_folder},
            headers=auth_header(owner_token),
        )
        assert res_forbidden.status_code == 403

        # 2. Non-existent folder
        res_404 = client.post(
            "/api/files/bulk/move",
            json={"file_ids": [], "folder_id": str(uuid.uuid4())},
            headers=auth_header(owner_token),
        )
        assert res_404.status_code == 404

        # 3. Invalid folder_id format
        res_400 = client.post(
            "/api/files/bulk/move",
            json={"file_ids": [], "folder_id": "not-a-uuid"},
            headers=auth_header(owner_token),
        )
        assert res_400.status_code == 400

    def test_bulk_tag_add_replace_and_remove(self, client, owner_token, app, db):
        """Bulk tag supports add, replace, and remove actions across multiple files."""
        # Create 2 files
        file_ids = []
        for i in range(2):
            res = client.post(
                "/api/files",
                data={"file": (io.BytesIO(f"Content {i}".encode()), f"tag_{i}.txt")},
                headers=auth_header(owner_token),
                content_type="multipart/form-data",
            )
            file_ids.append(res.get_json()["file"]["id"])

        # 1. Add tags
        add_res = client.post(
            "/api/files/bulk/tag",
            json={"file_ids": file_ids, "tags": ["alpha", "beta"], "action": "add"},
            headers=auth_header(owner_token),
        )
        assert add_res.status_code == 200
        assert set(add_res.get_json()["succeeded"]) == set(file_ids)

        with app.app_context():
            for fid in file_ids:
                f = db.session.get(File, uuid.UUID(fid))
                assert {t.name for t in f.tags} == {"alpha", "beta"}

        # 2. Replace tags
        rep_res = client.post(
            "/api/files/bulk/tag",
            json={"file_ids": file_ids, "tags": ["gamma"], "action": "replace"},
            headers=auth_header(owner_token),
        )
        assert rep_res.status_code == 200

        with app.app_context():
            for fid in file_ids:
                f = db.session.get(File, uuid.UUID(fid))
                assert {t.name for t in f.tags} == {"gamma"}

        # 3. Remove tag
        rem_res = client.post(
            "/api/files/bulk/tag",
            json={"file_ids": file_ids, "tags": ["gamma"], "action": "remove"},
            headers=auth_header(owner_token),
        )
        assert rem_res.status_code == 200

        with app.app_context():
            for fid in file_ids:
                f = db.session.get(File, uuid.UUID(fid))
                assert {t.name for t in f.tags} == set()

    def test_bulk_tag_mixed_batch_with_other_user_file(self, client, owner_token, recipient_token, app, db):
        """Bulk tag skips other users' files and reports 'File not found'."""
        f1_id = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"Owner file"), "owner_tag.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        ).get_json()["file"]["id"]

        f2_id = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"Recipient file"), "rec_tag.txt")},
            headers=auth_header(recipient_token),
            content_type="multipart/form-data",
        ).get_json()["file"]["id"]

        res = client.post(
            "/api/files/bulk/tag",
            json={"file_ids": [f1_id, f2_id], "tags": ["shared-label"]},
            headers=auth_header(owner_token),
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["succeeded"] == [f1_id]
        assert len(data["failed"]) == 1
        assert data["failed"][0]["id"] == f2_id
        assert data["failed"][0]["error"] == "File not found"

        with app.app_context():
            f1 = db.session.get(File, uuid.UUID(f1_id))
            assert any(t.name == "shared-label" for t in f1.tags)
            f2 = db.session.get(File, uuid.UUID(f2_id))
            assert len(f2.tags) == 0

    def test_bulk_validation_and_auth(self, client, owner_token):
        """Bulk endpoints reject unauthenticated calls and invalid payload shapes."""
        # Unauthenticated
        assert client.post("/api/files/bulk/delete", json={"file_ids": []}).status_code == 401
        assert client.post("/api/files/bulk/move", json={"file_ids": []}).status_code == 401
        assert client.post("/api/files/bulk/tag", json={"file_ids": []}).status_code == 401

        # Missing file_ids
        assert client.post("/api/files/bulk/delete", json={}, headers=auth_header(owner_token)).status_code == 400
        assert client.post("/api/files/bulk/move", json={"folder_id": None}, headers=auth_header(owner_token)).status_code == 400
        assert client.post("/api/files/bulk/tag", json={"tags": ["a"]}, headers=auth_header(owner_token)).status_code == 400

        # Invalid file ID format inside list
        res_del = client.post(
            "/api/files/bulk/delete",
            json={"file_ids": ["invalid-uuid-format"]},
            headers=auth_header(owner_token),
        )
        assert res_del.status_code == 200
        assert res_del.get_json()["failed"][0]["error"] == "Invalid file ID format"



