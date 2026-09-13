"""
Unit and integration tests for ClamAV malware scanning on file uploads.

Covers:
- Scanning disabled by default (SCAN_UPLOADS=False): clamd client never invoked, upload succeeds (201).
- Clean file upload when SCAN_UPLOADS=True: mock clamd returns OK, upload succeeds (201).
- Infected file upload when SCAN_UPLOADS=True: mock clamd returns FOUND, upload rejected with HTTP 422.
- Infected version upload when SCAN_UPLOADS=True: version upload rejected with HTTP 422.
- Graceful failure when ClamAV daemon is unreachable: connection errors caught, upload succeeds (201).
- Direct unit tests for scan_file_for_malware helper function.
"""

import io
import uuid
from unittest.mock import patch, MagicMock
import clamd
from app.models import File
from app.files.scanner import scan_file_for_malware


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


class TestClamAVMalwareScanning:
    """Integration tests for ClamAV scanning in upload endpoints."""

    def test_upload_file_scan_disabled_by_default(self, client, owner_token):
        """When SCAN_UPLOADS is False (default), clamd client is never contacted and upload succeeds."""
        with patch("clamd.ClamdNetworkSocket") as mock_clamd:
            res = client.post(
                "/api/files",
                data={"file": (io.BytesIO(b"harmless document content"), "harmless.txt")},
                headers=auth_header(owner_token),
                content_type="multipart/form-data",
            )
            assert res.status_code == 201
            # ClamAV socket should not have been initialized
            mock_clamd.assert_not_called()

    def test_upload_file_scan_clean_succeeds(self, client, owner_token, app):
        """When SCAN_UPLOADS is True and ClamAV returns OK, file upload proceeds and returns 201."""
        app.config["SCAN_UPLOADS"] = True
        try:
            mock_socket_instance = MagicMock()
            mock_socket_instance.instream.return_value = {"stream": ("OK", None)}

            with patch("clamd.ClamdNetworkSocket", return_value=mock_socket_instance):
                res = client.post(
                    "/api/files",
                    data={"file": (io.BytesIO(b"clean document content"), "clean.pdf")},
                    headers=auth_header(owner_token),
                    content_type="multipart/form-data",
                )
                assert res.status_code == 201
                data = res.get_json()
                assert "file" in data
                assert data["file"]["filename"] == "clean.pdf"
                mock_socket_instance.instream.assert_called_once()
        finally:
            app.config["SCAN_UPLOADS"] = False

    def test_upload_file_scan_infected_rejected_with_422(self, client, owner_token, app, db):
        """When SCAN_UPLOADS is True and ClamAV detects malware, file upload is rejected with 422."""
        app.config["SCAN_UPLOADS"] = True
        try:
            mock_socket_instance = MagicMock()
            mock_socket_instance.instream.return_value = {
                "stream": ("FOUND", "Win.Test.EICAR_HDB-1")
            }

            with patch("clamd.ClamdNetworkSocket", return_value=mock_socket_instance):
                res = client.post(
                    "/api/files",
                    data={"file": (io.BytesIO(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"), "eicar.com")},
                    headers=auth_header(owner_token),
                    content_type="multipart/form-data",
                )
                assert res.status_code == 422
                data = res.get_json()
                assert data["error"] == "Malware detected"
                assert "Win.Test.EICAR_HDB-1" in data["message"]
                assert data["virus"] == "Win.Test.EICAR_HDB-1"

                # Verify file was never persisted to the database
                with app.app_context():
                    persisted = File.query.filter_by(filename="eicar.com").first()
                    assert persisted is None
        finally:
            app.config["SCAN_UPLOADS"] = False

    def test_upload_version_scan_infected_rejected_with_422(self, client, owner_token, app, db):
        """When uploading a new file version that is infected, it is rejected with 422 and version is not saved."""
        # 1. Upload initial clean version (v1)
        res1 = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"original clean version"), "doc.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        assert res1.status_code == 201
        file_id = res1.get_json()["file"]["id"]

        # 2. Attempt to upload infected version 2
        app.config["SCAN_UPLOADS"] = True
        try:
            mock_socket_instance = MagicMock()
            mock_socket_instance.instream.return_value = {
                "stream": ("FOUND", "Trojan.Generic.KD")
            }

            with patch("clamd.ClamdNetworkSocket", return_value=mock_socket_instance):
                res2 = client.post(
                    f"/api/files/{file_id}/versions",
                    data={"file": (io.BytesIO(b"malicious payload"), "doc_v2.txt")},
                    headers=auth_header(owner_token),
                    content_type="multipart/form-data",
                )
                assert res2.status_code == 422
                data = res2.get_json()
                assert data["error"] == "Malware detected"
                assert data["virus"] == "Trojan.Generic.KD"

                # Verify file remains at version 1 in DB
                with app.app_context():
                    file_rec = db.session.get(File, uuid.UUID(file_id))
                    assert file_rec.current_version_number == 1
                    assert len(file_rec.versions) == 1
        finally:
            app.config["SCAN_UPLOADS"] = False

    def test_upload_file_daemon_unavailable_fails_gracefully(self, client, owner_token, app):
        """When SCAN_UPLOADS is True but ClamAV daemon is unreachable, the scan fails gracefully (201)."""
        app.config["SCAN_UPLOADS"] = True
        try:
            mock_socket_instance = MagicMock()
            mock_socket_instance.instream.side_effect = clamd.ConnectionError("Connection refused")

            with patch("clamd.ClamdNetworkSocket", return_value=mock_socket_instance):
                res = client.post(
                    "/api/files",
                    data={"file": (io.BytesIO(b"document while scanner down"), "fallback.txt")},
                    headers=auth_header(owner_token),
                    content_type="multipart/form-data",
                )
                # Fails gracefully so service does not break
                assert res.status_code == 201
                data = res.get_json()
                assert data["file"]["filename"] == "fallback.txt"
        finally:
            app.config["SCAN_UPLOADS"] = False


class TestScannerHelperUnit:
    """Unit tests for scan_file_for_malware helper function."""

    def test_scanner_disabled_returns_clean(self, app):
        with app.app_context():
            app.config["SCAN_UPLOADS"] = False
            is_clean, virus = scan_file_for_malware(b"some content")
            assert is_clean is True
            assert virus is None

    def test_scanner_clean_result(self, app):
        with app.app_context():
            app.config["SCAN_UPLOADS"] = True
            mock_client = MagicMock()
            mock_client.instream.return_value = {"stream": ("OK", None)}

            is_clean, virus = scan_file_for_malware(b"clean content", client=mock_client)
            assert is_clean is True
            assert virus is None

    def test_scanner_infected_result(self, app):
        with app.app_context():
            app.config["SCAN_UPLOADS"] = True
            mock_client = MagicMock()
            mock_client.instream.return_value = {"stream": ("FOUND", "Eicar-Test-Signature")}

            is_clean, virus = scan_file_for_malware(b"infected content", client=mock_client)
            assert is_clean is False
            assert virus == "Eicar-Test-Signature"

    def test_scanner_exception_fails_gracefully(self, app):
        with app.app_context():
            app.config["SCAN_UPLOADS"] = True
            mock_client = MagicMock()
            mock_client.instream.side_effect = clamd.ClamdError("Generic scan error")

            is_clean, virus = scan_file_for_malware(b"any content", client=mock_client)
            assert is_clean is True
            assert virus is None
