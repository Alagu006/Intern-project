import hashlib
import hmac
import io
import json
import uuid
from unittest import mock
import pytest
import requests

from app.models import User, File, Share, Webhook
from app.auth.decorators import generate_access_token
from app.webhooks.dispatcher import (
    compute_webhook_signature,
    wait_for_active_webhooks,
    EVENT_SHARE_DOWNLOADED,
    EVENT_SHARE_REVOKED,
)
from tests.conftest import make_user, make_file


def auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="function")
def user1(db):
    return make_user(db.session, "hookuser1", "hook1@example.com")


@pytest.fixture(scope="function")
def user1_token(user1):
    return generate_access_token(user1)


@pytest.fixture(scope="function")
def user2(db):
    return make_user(db.session, "hookuser2", "hook2@example.com")


@pytest.fixture(scope="function")
def user2_token(user2):
    return generate_access_token(user2)


@pytest.fixture(scope="function")
def share_setup(app, client, db, user1, user1_token):
    """Creates a file owned by user1 and an open share."""
    with app.app_context():
        f = make_file(app, db.session, user1)
        res = client.post(
            f"/api/files/{f.id}/share",
            json={"permissions": {"can_view": True, "can_download": True}},
            headers=auth_header(user1_token),
        )
        assert res.status_code == 201
        share_data = res.get_json()["shares"][0]
        return f, share_data


class TestWebhookCRUD:
    """Tests for Webhook management endpoints under /api/webhooks."""

    def test_create_webhook_with_custom_secret(self, client, user1_token):
        payload = {
            "url": "https://example.com/webhooks/listener",
            "secret": "my-secure-webhook-secret-12345",
            "event_types": ["share.downloaded", "share.revoked"],
            "is_active": True,
        }
        res = client.post("/api/webhooks", json=payload, headers=auth_header(user1_token))
        assert res.status_code == 201
        data = res.get_json()
        assert "webhook" in data
        wh = data["webhook"]
        assert wh["url"] == payload["url"]
        assert wh["secret"] == payload["secret"]
        assert set(wh["event_types"]) == {"share.downloaded", "share.revoked"}
        assert wh["is_active"] is True
        assert wh["id"] is not None
        assert wh["created_at"] is not None

    def test_create_webhook_auto_generated_secret(self, client, user1_token):
        payload = {
            "url": "https://example.com/service/hooks",
        }
        res = client.post("/api/webhooks", json=payload, headers=auth_header(user1_token))
        assert res.status_code == 201
        wh = res.get_json()["webhook"]
        assert wh["url"] == payload["url"]
        # Generated secret must be 32 bytes hex = 64 characters
        assert len(wh["secret"]) == 64
        assert set(wh["event_types"]) == {EVENT_SHARE_DOWNLOADED, EVENT_SHARE_REVOKED}
        assert wh["is_active"] is True

    def test_create_webhook_invalid_url_rejected(self, client, user1_token):
        invalid_urls = [
            "",
            "not-a-url",
            "ftp://files.example.com/webhook",
            "javascript:alert(1)",
            12345,
        ]
        for url in invalid_urls:
            res = client.post(
                "/api/webhooks",
                json={"url": url},
                headers=auth_header(user1_token),
            )
            assert res.status_code == 400
            assert "Invalid URL" in res.get_json()["error"]

    def test_create_webhook_invalid_event_types_rejected(self, client, user1_token):
        bad_payloads = [
            {"url": "https://example.com/h", "event_types": "not-a-list"},
            {"url": "https://example.com/h", "event_types": []},
            {"url": "https://example.com/h", "event_types": ["invalid.event.name"]},
        ]
        for p in bad_payloads:
            res = client.post("/api/webhooks", json=p, headers=auth_header(user1_token))
            assert res.status_code == 400

    def test_list_webhooks_user_isolation(self, client, user1_token, user2_token):
        # Create webhook for user 1
        res1 = client.post(
            "/api/webhooks",
            json={"url": "https://example.com/user1/webhook"},
            headers=auth_header(user1_token),
        )
        assert res1.status_code == 201

        # Create webhook for user 2
        res2 = client.post(
            "/api/webhooks",
            json={"url": "https://example.com/user2/webhook"},
            headers=auth_header(user2_token),
        )
        assert res2.status_code == 201

        # User 1 list
        list1 = client.get("/api/webhooks", headers=auth_header(user1_token))
        assert list1.status_code == 200
        urls1 = [w["url"] for w in list1.get_json()["webhooks"]]
        assert "https://example.com/user1/webhook" in urls1
        assert "https://example.com/user2/webhook" not in urls1

        # User 2 list
        list2 = client.get("/api/webhooks", headers=auth_header(user2_token))
        assert list2.status_code == 200
        urls2 = [w["url"] for w in list2.get_json()["webhooks"]]
        assert "https://example.com/user2/webhook" in urls2
        assert "https://example.com/user1/webhook" not in urls2

    def test_get_webhook_by_id(self, client, user1_token, user2_token):
        create_res = client.post(
            "/api/webhooks",
            json={"url": "https://example.com/hook"},
            headers=auth_header(user1_token),
        )
        assert create_res.status_code == 201
        wh_id = create_res.get_json()["webhook"]["id"]

        # Owner can retrieve
        get_res = client.get(f"/api/webhooks/{wh_id}", headers=auth_header(user1_token))
        assert get_res.status_code == 200
        assert get_res.get_json()["webhook"]["id"] == wh_id

        # Other user receives 403 Forbidden
        other_res = client.get(f"/api/webhooks/{wh_id}", headers=auth_header(user2_token))
        assert other_res.status_code == 403

        # Non-existent ID returns 404
        missing_res = client.get(f"/api/webhooks/{uuid.uuid4()}", headers=auth_header(user1_token))
        assert missing_res.status_code == 404

    def test_update_webhook(self, client, user1_token):
        create_res = client.post(
            "/api/webhooks",
            json={"url": "https://example.com/old/hook"},
            headers=auth_header(user1_token),
        )
        assert create_res.status_code == 201
        wh_id = create_res.get_json()["webhook"]["id"]

        patch_res = client.patch(
            f"/api/webhooks/{wh_id}",
            json={
                "url": "https://example.com/new/hook",
                "secret": "updated-secret-12345",
                "event_types": ["share.revoked"],
                "is_active": False,
            },
            headers=auth_header(user1_token),
        )
        assert patch_res.status_code == 200
        wh = patch_res.get_json()["webhook"]
        assert wh["url"] == "https://example.com/new/hook"
        assert wh["secret"] == "updated-secret-12345"
        assert wh["event_types"] == ["share.revoked"]
        assert wh["is_active"] is False

    def test_delete_webhook(self, client, user1_token):
        create_res = client.post(
            "/api/webhooks",
            json={"url": "https://example.com/del/hook"},
            headers=auth_header(user1_token),
        )
        assert create_res.status_code == 201
        wh_id = create_res.get_json()["webhook"]["id"]

        del_res = client.delete(f"/api/webhooks/{wh_id}", headers=auth_header(user1_token))
        assert del_res.status_code == 200
        assert del_res.get_json()["message"] == "Webhook deleted"

        # Verifying it no longer exists
        get_res = client.get(f"/api/webhooks/{wh_id}", headers=auth_header(user1_token))
        assert get_res.status_code == 404

    def test_unauthenticated_requests_rejected(self, client):
        assert client.get("/api/webhooks").status_code == 401
        assert client.post("/api/webhooks", json={}).status_code == 401
        assert client.get(f"/api/webhooks/{uuid.uuid4()}").status_code == 401
        assert client.patch(f"/api/webhooks/{uuid.uuid4()}").status_code == 401
        assert client.delete(f"/api/webhooks/{uuid.uuid4()}").status_code == 401


class TestWebhookSSRFProtection:
    """Tests for Server-Side Request Forgery (SSRF) and DNS-rebinding protection."""

    def test_webhook_url_pointing_at_loopback_rejected(self, client, user1_token):
        """URLs pointing to 127.0.0.1 or IPv6 loopback must be rejected with 400."""
        loopback_urls = [
            "http://127.0.0.1/webhook",
            "http://127.0.0.1:8080/events",
            "https://127.0.0.1:8443/hook",
            "http://[::1]/webhook",
        ]
        for url in loopback_urls:
            res = client.post("/api/webhooks", json={"url": url}, headers=auth_header(user1_token))
            assert res.status_code == 400
            assert "Invalid URL" in res.get_json()["error"]
            assert "forbidden IP" in res.get_json()["error"]

    def test_webhook_url_pointing_at_link_local_metadata_rejected(self, client, user1_token):
        """URLs pointing to 169.254.169.254 (cloud metadata) or link-local IPv6 must be rejected."""
        metadata_urls = [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254:8080/hook",
            "http://[fe80::1]/hook",
        ]
        for url in metadata_urls:
            res = client.post("/api/webhooks", json={"url": url}, headers=auth_header(user1_token))
            assert res.status_code == 400
            assert "Invalid URL" in res.get_json()["error"]

    def test_webhook_url_pointing_at_rfc1918_private_ips_rejected(self, client, user1_token):
        """URLs pointing directly to RFC 1918 private IPs (10.0.0.5, 192.168.x, 172.16.x) must be rejected."""
        private_urls = [
            "http://10.0.0.5/api",
            "http://10.0.0.5:8000/events",
            "http://192.168.1.1/hook",
            "https://172.16.0.100/webhook",
        ]
        for url in private_urls:
            res = client.post("/api/webhooks", json={"url": url}, headers=auth_header(user1_token))
            assert res.status_code == 400
            assert "Invalid URL" in res.get_json()["error"]

    def test_webhook_url_pointing_at_hostname_resolving_to_private_ip_rejected(self, client, user1_token):
        """Hostnames that resolve via DNS to a private or loopback IP must be rejected."""
        # 1. localhost resolves to loopback
        res = client.post(
            "/api/webhooks",
            json={"url": "http://localhost/webhook"},
            headers=auth_header(user1_token),
        )
        assert res.status_code == 400
        assert "Invalid URL" in res.get_json()["error"]

        # 2. Mock a domain that resolves to an RFC 1918 private IP
        with mock.patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("10.50.1.2", 80))]):
            res2 = client.post(
                "/api/webhooks",
                json={"url": "https://intranet.company.corp/webhook"},
                headers=auth_header(user1_token),
            )
            assert res2.status_code == 400
            assert "Invalid URL" in res2.get_json()["error"]
            assert "forbidden IP" in res2.get_json()["error"]

    def test_webhook_url_pointing_at_public_https_accepted(self, client, user1_token):
        """A normal public HTTPS URL is accepted and successfully creates a webhook."""
        with mock.patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.216.34", 443))]):
            res = client.post(
                "/api/webhooks",
                json={"url": "https://valid.public-service.com/webhook"},
                headers=auth_header(user1_token),
            )
            assert res.status_code == 201
            data = res.get_json()
            assert data["webhook"]["url"] == "https://valid.public-service.com/webhook"

    def test_webhook_url_blocked_ports_rejected(self, client, user1_token):
        """URLs specifying explicit internal service/database ports are rejected."""
        blocked_port_urls = [
            "http://example.com:22/ssh",
            "http://example.com:3306/mysql",
            "http://example.com:5432/postgres",
            "http://example.com:6379/redis",
            "http://example.com:3310/clamav",
        ]
        for url in blocked_port_urls:
            res = client.post("/api/webhooks", json={"url": url}, headers=auth_header(user1_token))
            assert res.status_code == 400
            assert "Invalid URL" in res.get_json()["error"]
            assert "blocked for security" in res.get_json()["error"]

    def test_dispatch_time_dns_rebinding_blocked(self, client, user1_token, share_setup):
        """
        If a hostname resolved to a public IP at creation time, but resolves to a
        private IP at dispatch time (DNS-rebinding attack), dispatch must be blocked
        and requests.post must NOT be called.
        """
        _, share_data = share_setup
        token = share_data["share_token"]
        target_url = "https://rebind-test.attacker.com/events"

        # 1. Allow creation with initial public resolution
        with mock.patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.216.34", 443))]):
            create_res = client.post(
                "/api/webhooks",
                json={"url": target_url, "event_types": ["share.downloaded"]},
                headers=auth_header(user1_token),
            )
            assert create_res.status_code == 201

        mock_resp = mock.MagicMock()
        mock_resp.status_code = 200

        # 2. At dispatch time, simulate DNS rebinding to a private IP (10.0.0.5)
        with mock.patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("10.0.0.5", 443))]):
            with mock.patch("requests.post", return_value=mock_resp) as mock_post:
                dl_res = client.get(f"/api/shares/{token}/download")
                assert dl_res.status_code == 200

                wait_for_active_webhooks()
                # requests.post must NOT be called because SSRF re-validation blocked it!
                mock_post.assert_not_called()

    def test_dispatch_passes_allow_redirects_false(self):
        """
        Outbound requests.post call must specify allow_redirects=False to prevent
        redirect-based SSRF.
        """
        from app.webhooks.dispatcher import _send_webhook

        with mock.patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.216.34", 443))]):
            with mock.patch("requests.post") as mock_post:
                mock_post.return_value.status_code = 200
                success = _send_webhook(
                    url="https://example.com/hook",
                    secret="test-secret",
                    payload_bytes=b'{"event":"test"}',
                    event_type="share.downloaded",
                )
                assert success is True
                assert mock_post.called
                _, kwargs = mock_post.call_args
                assert kwargs.get("allow_redirects") is False


class TestWebhookDispatchingAndSigning:
    """Tests for outbound webhook event dispatching and HMAC-SHA256 signature verification."""

    def test_share_download_triggers_signed_webhook(self, client, user1, user1_token, share_setup):
        _, share_data = share_setup
        token = share_data["share_token"]
        share_id = share_data["id"]

        target_url = "https://example.com/analytics/events"
        target_secret = "super-secret-hmac-signing-key-987"

        # Register webhook for user 1
        create_res = client.post(
            "/api/webhooks",
            json={
                "url": target_url,
                "secret": target_secret,
                "event_types": ["share.downloaded"],
            },
            headers=auth_header(user1_token),
        )
        assert create_res.status_code == 201

        mock_resp = mock.MagicMock()
        mock_resp.status_code = 200

        with mock.patch("requests.post", return_value=mock_resp) as mock_post:
            # Recipient downloads the share
            dl_res = client.get(f"/api/shares/{token}/download")
            assert dl_res.status_code == 200

            # Wait for background thread delivery
            wait_for_active_webhooks()

            assert mock_post.called
            assert mock_post.call_count == 1

            called_url = mock_post.call_args[0][0]
            called_kwargs = mock_post.call_args[1]

            assert called_url == target_url
            body_bytes = called_kwargs["data"]
            headers = called_kwargs["headers"]

            # Validate Content-Type
            assert headers["Content-Type"] == "application/json"
            assert headers["X-Event-Type"] == "share.downloaded"

            # Validate HMAC-SHA256 Signature
            expected_sig = hmac.new(
                target_secret.encode("utf-8"),
                body_bytes,
                hashlib.sha256,
            ).hexdigest()

            assert headers["X-Signature"] == expected_sig
            assert headers["X-Hub-Signature-256"] == f"sha256={expected_sig}"

            # Parse JSON body and verify structure
            payload = json.loads(body_bytes.decode("utf-8"))
            assert payload["event"] == "share.downloaded"
            assert "timestamp" in payload
            assert payload["data"]["share_id"] == share_id
            assert payload["data"]["filename"] == "test.txt"

    def test_share_revoked_by_delete_endpoint(self, client, user1_token, share_setup):
        _, share_data = share_setup
        share_id = share_data["id"]

        target_url = "https://example.com/zapier/catch/123/abc"
        target_secret = "zapier-secret-key-456"

        client.post(
            "/api/webhooks",
            json={
                "url": target_url,
                "secret": target_secret,
                "event_types": ["share.revoked"],
            },
            headers=auth_header(user1_token),
        )

        mock_resp = mock.MagicMock()
        mock_resp.status_code = 200

        with mock.patch("requests.post", return_value=mock_resp) as mock_post:
            # Delete share
            del_res = client.delete(f"/api/shares/{share_id}", headers=auth_header(user1_token))
            assert del_res.status_code == 200

            wait_for_active_webhooks()

            assert mock_post.called
            called_url = mock_post.call_args[0][0]
            called_kwargs = mock_post.call_args[1]

            assert called_url == target_url
            body_bytes = called_kwargs["data"]
            headers = called_kwargs["headers"]

            expected_sig = compute_webhook_signature(target_secret, body_bytes)
            assert headers["X-Signature"] == expected_sig

            payload = json.loads(body_bytes.decode("utf-8"))
            assert payload["event"] == "share.revoked"
            assert payload["data"]["share_id"] == share_id
            assert "revoked_at" in payload["data"]

    def test_share_revoked_by_patch_endpoint(self, client, user1_token, share_setup):
        _, share_data = share_setup
        share_id = share_data["id"]

        target_url = "https://example.com/slack/webhook"
        target_secret = "slack-secret-789"

        create_res = client.post(
            "/api/webhooks",
            json={
                "url": target_url,
                "secret": target_secret,
                "event_types": ["share.revoked"],
            },
            headers=auth_header(user1_token),
        )
        assert create_res.status_code == 201

        mock_resp = mock.MagicMock()
        mock_resp.status_code = 200

        with mock.patch("requests.post", return_value=mock_resp) as mock_post:
            # Patch share to revoked
            patch_res = client.patch(
                f"/api/shares/{share_id}",
                json={"is_revoked": True},
                headers=auth_header(user1_token),
            )
            assert patch_res.status_code == 200

            wait_for_active_webhooks()

            assert mock_post.called
            body_bytes = mock_post.call_args[1]["data"]
            payload = json.loads(body_bytes.decode("utf-8"))
            assert payload["event"] == "share.revoked"
            assert payload["data"]["share_id"] == share_id

    def test_inactive_webhook_receives_no_events(self, client, user1_token, share_setup):
        _, share_data = share_setup
        token = share_data["share_token"]

        client.post(
            "/api/webhooks",
            json={
                "url": "https://example.com/inactive/hook",
                "is_active": False,
                "event_types": ["share.downloaded"],
            },
            headers=auth_header(user1_token),
        )

        with mock.patch("requests.post") as mock_post:
            dl_res = client.get(f"/api/shares/{token}/download")
            assert dl_res.status_code == 200

            wait_for_active_webhooks()
            mock_post.assert_not_called()

    def test_unsubscribed_event_receives_no_events(self, client, user1_token, share_setup):
        _, share_data = share_setup
        token = share_data["share_token"]

        # Only subscribed to share.revoked
        client.post(
            "/api/webhooks",
            json={
                "url": "https://example.com/revoked/hook",
                "event_types": ["share.revoked"],
            },
            headers=auth_header(user1_token),
        )

        with mock.patch("requests.post") as mock_post:
            # Trigger download
            dl_res = client.get(f"/api/shares/{token}/download")
            assert dl_res.status_code == 200

            wait_for_active_webhooks()
            mock_post.assert_not_called()

    def test_delivery_failure_does_not_block_or_fail_api(self, client, user1_token, share_setup):
        _, share_data = share_setup
        token = share_data["share_token"]
        share_id = share_data["id"]

        client.post(
            "/api/webhooks",
            json={
                "url": "https://example.com/failing/dead",
                "event_types": ["share.downloaded", "share.revoked"],
            },
            headers=auth_header(user1_token),
        )

        with mock.patch(
            "requests.post",
            side_effect=requests.exceptions.ConnectTimeout("Connection timed out"),
        ):
            # Download must still succeed
            dl_res = client.get(f"/api/shares/{token}/download")
            assert dl_res.status_code == 200

            # Revocation must still succeed
            del_res = client.delete(f"/api/shares/{share_id}", headers=auth_header(user1_token))
            assert del_res.status_code == 200

            wait_for_active_webhooks()
