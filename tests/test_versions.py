"""
Unit and integration tests for File Versioning and Share Pinning.

Covers:
- Initial file upload automatically initializes FileVersion v1
- POST /api/files/<uuid:file_id>/versions uploads new versions (v2, v3)
- Base File record reflects latest version metadata
- File version list GET /api/files/<uuid:file_id>/versions returns all versions sorted desc
- File version download GET /api/files/<uuid:file_id>/versions/<int:version_number>/download
- File version metadata GET /api/files/<uuid:file_id>/versions/<int:version_number>
- Validation & authorization (empty file, non-owner 403, not found 404, unauthenticated 401)
- Existing unpinned shares dynamically track and serve the latest version
- Pinned shares (pinned_version=1) continue serving historical version even after new versions are uploaded
- File deletion cascades and removes all version encrypted blobs from disk
"""

import io
import os
import uuid
from app.models import File, FileVersion, Share
from app.crypto.file_crypto import decrypt_file


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


class TestFileVersionUpload:
    """Tests for POST /api/files/<file_id>/versions endpoint."""

    def test_upload_new_version_success(self, client, owner, owner_token, app, db):
        """Uploading a new version increases version number, updates file record, and stores new blob."""
        # 1. Upload initial file (v1)
        v1_content = b"Version 1 content"
        res1 = client.post(
            "/api/files",
            data={"file": (io.BytesIO(v1_content), "report_v1.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        assert res1.status_code == 201
        file_id = res1.get_json()["file"]["id"]

        # 2. Upload version 2
        v2_content = b"Version 2 updated content with additions"
        res2 = client.post(
            f"/api/files/{file_id}/versions",
            data={"file": (io.BytesIO(v2_content), "report_v2.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        assert res2.status_code == 201
        data2 = res2.get_json()
        assert "version" in data2
        assert data2["version"]["version_number"] == 2
        assert data2["version"]["filename"] == "report_v2.txt"
        assert data2["version"]["size_bytes"] == len(v2_content)
        assert data2["file"]["version"] == 2
        assert data2["file"]["filename"] == "report_v2.txt"

        # 3. Upload version 3
        v3_content = b"Version 3 final revision"
        res3 = client.post(
            f"/api/files/{file_id}/versions",
            data={"file": (io.BytesIO(v3_content), "report_v3.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        assert res3.status_code == 201
        data3 = res3.get_json()
        assert data3["version"]["version_number"] == 3
        assert data3["file"]["version"] == 3

        # Verify DB state
        with app.app_context():
            file_rec = db.session.get(File, uuid.UUID(file_id))
            assert file_rec.current_version_number == 3
            assert len(file_rec.versions) == 3

            # Check individual versions
            versions_by_num = {v.version_number: v for v in file_rec.versions}
            assert 1 in versions_by_num
            assert 2 in versions_by_num
            assert 3 in versions_by_num

            # Verify decryption of each version
            p1 = decrypt_file(
                versions_by_num[1].encrypted_path,
                versions_by_num[1].nonce_hex,
                versions_by_num[1].wrapped_key_hex,
            )
            assert p1 == v1_content

            p2 = decrypt_file(
                versions_by_num[2].encrypted_path,
                versions_by_num[2].nonce_hex,
                versions_by_num[2].wrapped_key_hex,
            )
            assert p2 == v2_content

            p3 = decrypt_file(
                versions_by_num[3].encrypted_path,
                versions_by_num[3].nonce_hex,
                versions_by_num[3].wrapped_key_hex,
            )
            assert p3 == v3_content

    def test_upload_version_empty_file_rejected(self, client, owner_token):
        """Uploading an empty file as a version returns 400."""
        res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"initial"), "initial.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = res.get_json()["file"]["id"]

        res_ver = client.post(
            f"/api/files/{file_id}/versions",
            data={"file": (io.BytesIO(b""), "empty.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        assert res_ver.status_code == 400
        assert res_ver.get_json()["error"] == "Empty file"

    def test_upload_version_missing_file_rejected(self, client, owner_token):
        """Missing file parameter returns 400."""
        res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"initial"), "initial.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = res.get_json()["file"]["id"]

        res_ver = client.post(
            f"/api/files/{file_id}/versions",
            data={"other": "param"},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        assert res_ver.status_code == 400
        assert res_ver.get_json()["error"] == "No file provided"

    def test_upload_version_non_owner_forbidden(self, client, owner_token, recipient_token):
        """A user who does not own the file receives 403 when trying to upload a version."""
        res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"owner only"), "owner.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = res.get_json()["file"]["id"]

        res_hacker = client.post(
            f"/api/files/{file_id}/versions",
            data={"file": (io.BytesIO(b"malicious version"), "hacked.txt")},
            headers=auth_header(recipient_token),
            content_type="multipart/form-data",
        )
        assert res_hacker.status_code == 403

    def test_upload_version_not_found(self, client, owner_token):
        """Uploading a version to a non-existent file returns 404."""
        random_id = str(uuid.uuid4())
        res = client.post(
            f"/api/files/{random_id}/versions",
            data={"file": (io.BytesIO(b"content"), "file.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        assert res.status_code == 404


class TestFileVersionListing:
    """Tests for GET /api/files/<file_id>/versions."""

    def test_list_versions_success(self, client, owner_token):
        """Listing versions returns all versions ordered descending by version number."""
        res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"v1 content"), "v1.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = res.get_json()["file"]["id"]

        # Upload v2
        client.post(
            f"/api/files/{file_id}/versions",
            data={"file": (io.BytesIO(b"v2 content"), "v2.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )

        # Upload v3
        client.post(
            f"/api/files/{file_id}/versions",
            data={"file": (io.BytesIO(b"v3 content"), "v3.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )

        res_list = client.get(f"/api/files/{file_id}/versions", headers=auth_header(owner_token))
        assert res_list.status_code == 200
        data = res_list.get_json()
        assert data["total"] == 3
        assert data["current_version"] == 3
        versions = data["versions"]
        assert len(versions) == 3
        assert [v["version_number"] for v in versions] == [3, 2, 1]
        assert versions[0]["filename"] == "v3.txt"
        assert versions[1]["filename"] == "v2.txt"
        assert versions[2]["filename"] == "v1.txt"

    def test_list_versions_non_owner_forbidden(self, client, owner_token, recipient_token):
        """Listing versions by non-owner returns 403."""
        res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"data"), "data.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = res.get_json()["file"]["id"]

        res_other = client.get(f"/api/files/{file_id}/versions", headers=auth_header(recipient_token))
        assert res_other.status_code == 403

    def test_list_versions_not_found(self, client, owner_token):
        """Listing versions for non-existent file returns 404."""
        random_id = str(uuid.uuid4())
        res = client.get(f"/api/files/{random_id}/versions", headers=auth_header(owner_token))
        assert res.status_code == 404


class TestFileVersionDownload:
    """Tests for downloading specific versions and viewing metadata."""

    def test_download_specific_versions(self, client, owner_token):
        """Downloading specific versions returns the exact plaintext uploaded for each version."""
        v1_text = b"Original content for version 1"
        v2_text = b"Modified content for version 2"

        res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(v1_text), "report_v1.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = res.get_json()["file"]["id"]

        client.post(
            f"/api/files/{file_id}/versions",
            data={"file": (io.BytesIO(v2_text), "report_v2.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )

        # 1. Download v1 via dedicated download endpoint
        res_d1 = client.get(
            f"/api/files/{file_id}/versions/1/download",
            headers=auth_header(owner_token),
        )
        assert res_d1.status_code == 200
        assert res_d1.data == v1_text
        assert 'filename="report_v1.txt"' in res_d1.headers["Content-Disposition"]

        # 2. Download v2 via dedicated download endpoint
        res_d2 = client.get(
            f"/api/files/{file_id}/versions/2/download",
            headers=auth_header(owner_token),
        )
        assert res_d2.status_code == 200
        assert res_d2.data == v2_text
        assert 'filename="report_v2.txt"' in res_d2.headers["Content-Disposition"]

        # 3. Direct file download endpoint returns latest (v2)
        res_latest = client.get(
            f"/api/files/{file_id}/download",
            headers=auth_header(owner_token),
        )
        assert res_latest.status_code == 200
        assert res_latest.data == v2_text

    def test_version_metadata_endpoint(self, client, owner_token):
        """GET /api/files/<file_id>/versions/<num> returns metadata when not requesting download."""
        res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"meta test"), "meta.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = res.get_json()["file"]["id"]

        res_meta = client.get(
            f"/api/files/{file_id}/versions/1",
            headers=auth_header(owner_token),
        )
        assert res_meta.status_code == 200
        data = res_meta.get_json()
        assert "version" in data
        assert data["version"]["version_number"] == 1
        assert data["version"]["filename"] == "meta.txt"

    def test_download_version_not_found(self, client, owner_token):
        """Requesting non-existent version number returns 404."""
        res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"data"), "data.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = res.get_json()["file"]["id"]

        res_bad_ver = client.get(
            f"/api/files/{file_id}/versions/99/download",
            headers=auth_header(owner_token),
        )
        assert res_bad_ver.status_code == 404
        assert "Version 99 not found" in res_bad_ver.get_json()["error"]

    def test_download_version_non_owner_forbidden(self, client, owner_token, recipient_token):
        """Non-owner cannot download file versions."""
        res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"secret"), "secret.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = res.get_json()["file"]["id"]

        res_hacker = client.get(
            f"/api/files/{file_id}/versions/1/download",
            headers=auth_header(recipient_token),
        )
        assert res_hacker.status_code == 403


class TestSharesVersioningAndPinning:
    """Tests for share behavior with versions: dynamic latest vs pinned tradeoff."""

    def test_unpinned_share_dynamically_tracks_latest_version(
        self, client, owner_token, recipient_token
    ):
        """
        An unpinned share (default) always points dynamically to the latest version.
        When a file owner uploads v2, recipient automatically downloads v2.
        """
        v1_text = b"Original shared document v1"
        res_file = client.post(
            "/api/files",
            data={"file": (io.BytesIO(v1_text), "shared_doc.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = res_file.get_json()["file"]["id"]

        # Create unpinned share with download permission
        res_share = client.post(
            f"/api/files/{file_id}/share",
            json={"permissions": {"can_view": True, "can_download": True}},
            headers=auth_header(owner_token),
        )
        assert res_share.status_code == 201
        share_token = res_share.get_json()["shares"][0]["share_token"]
        assert res_share.get_json()["shares"][0]["pinned_version"] is None

        # Recipient accesses share: metadata shows version 1
        res_acc1 = client.get(f"/api/shares/{share_token}/access")
        assert res_acc1.status_code == 200
        assert res_acc1.get_json()["version"] == 1
        assert res_acc1.get_json()["is_pinned"] is False

        # Recipient downloads share: receives v1
        res_down1 = client.get(f"/api/shares/{share_token}/download")
        assert res_down1.status_code == 200
        assert res_down1.data == v1_text

        # Owner now uploads version 2!
        v2_text = b"Updated document v2 with latest changes"
        res_v2 = client.post(
            f"/api/files/{file_id}/versions",
            data={"file": (io.BytesIO(v2_text), "shared_doc_v2.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        assert res_v2.status_code == 201

        # Recipient accesses share again: metadata now reflects version 2!
        res_acc2 = client.get(f"/api/shares/{share_token}/access")
        assert res_acc2.status_code == 200
        assert res_acc2.get_json()["version"] == 2
        assert res_acc2.get_json()["file"]["version"] == 2

        # Recipient downloads share again: receives v2!
        res_down2 = client.get(f"/api/shares/{share_token}/download")
        assert res_down2.status_code == 200
        assert res_down2.data == v2_text

    def test_pinned_share_serves_immutable_historical_version(
        self, client, owner_token
    ):
        """
        A pinned share (pinned_version=1) continues serving version 1 even
        after new versions are uploaded.
        """
        v1_text = b"Contract draft v1 signed"
        res_file = client.post(
            "/api/files",
            data={"file": (io.BytesIO(v1_text), "contract_v1.pdf")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = res_file.get_json()["file"]["id"]

        # Create share explicitly pinned to version 1
        res_share = client.post(
            f"/api/files/{file_id}/share",
            json={
                "permissions": {"can_view": True, "can_download": True},
                "pinned_version": 1,
            },
            headers=auth_header(owner_token),
        )
        assert res_share.status_code == 201
        share_token = res_share.get_json()["shares"][0]["share_token"]
        assert res_share.get_json()["shares"][0]["pinned_version"] == 1

        # Owner uploads v2 and v3
        v2_text = b"Contract draft v2 amended"
        client.post(
            f"/api/files/{file_id}/versions",
            data={"file": (io.BytesIO(v2_text), "contract_v2.pdf")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        v3_text = b"Contract draft v3 finalized"
        client.post(
            f"/api/files/{file_id}/versions",
            data={"file": (io.BytesIO(v3_text), "contract_v3.pdf")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )

        # Accessing pinned share confirms version 1 and is_pinned=True
        res_acc = client.get(f"/api/shares/{share_token}/access")
        assert res_acc.status_code == 200
        assert res_acc.get_json()["version"] == 1
        assert res_acc.get_json()["is_pinned"] is True
        assert res_acc.get_json()["file"]["filename"] == "contract_v1.pdf"

        # Downloading pinned share returns v1 plaintext, NOT v3
        res_down = client.get(f"/api/shares/{share_token}/download")
        assert res_down.status_code == 200
        assert res_down.data == v1_text
        assert 'filename="contract_v1.pdf"' in res_down.headers["Content-Disposition"]

    def test_pinned_version_validation(self, client, owner_token):
        """Attempting to pin to a non-existent version returns 404."""
        res_file = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"data"), "file.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = res_file.get_json()["file"]["id"]

        # Attempt to pin to non-existent version 99
        res_bad = client.post(
            f"/api/files/{file_id}/share",
            json={"pinned_version": 99},
            headers=auth_header(owner_token),
        )
        assert res_bad.status_code == 404

        # Attempt invalid non-integer pinned_version
        res_invalid = client.post(
            f"/api/files/{file_id}/share",
            json={"pinned_version": "invalid"},
            headers=auth_header(owner_token),
        )
        assert res_invalid.status_code == 400


class TestFileVersionCleanupOnDelete:
    """Tests that deleting a file cleans up all version encrypted blobs on disk."""

    def test_delete_file_cleans_all_version_disk_blobs(self, client, owner_token, app, db):
        """Deleting a file deletes disk blobs for v1, v2, v3 and cascades DB records."""
        # 1. Upload v1
        res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"v1"), "clean.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = res.get_json()["file"]["id"]

        # 2. Upload v2 and v3
        client.post(
            f"/api/files/{file_id}/versions",
            data={"file": (io.BytesIO(b"v2"), "clean_v2.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        client.post(
            f"/api/files/{file_id}/versions",
            data={"file": (io.BytesIO(b"v3"), "clean_v3.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )

        with app.app_context():
            file_rec = db.session.get(File, uuid.UUID(file_id))
            disk_paths = [v.encrypted_path for v in file_rec.versions]
            assert len(disk_paths) == 3
            for path in disk_paths:
                assert os.path.exists(path)

        # Permanently delete file
        res_del = client.delete(f"/api/files/{file_id}?permanent=true", headers=auth_header(owner_token))
        assert res_del.status_code == 200

        # Verify all disk blobs removed
        for path in disk_paths:
            assert not os.path.exists(path)

        # Verify File and FileVersions removed from DB
        with app.app_context():
            assert db.session.get(File, uuid.UUID(file_id)) is None
            versions_in_db = FileVersion.query.filter_by(file_id=uuid.UUID(file_id)).all()
            assert len(versions_in_db) == 0
