"""
Tests for the in-app notification system:
- Notification creation on share view and download
- Notification listing, ordering, pagination, and unread filtering
- Marking notifications as read
- Authorization and user isolation
"""

import io
import uuid
import pytest
from app.models import User, File, Share, Notification
from app.auth.decorators import generate_access_token


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="function")
def share_with_download(app, client, db, owner, owner_token):
    """Creates a file and a downloadable share."""
    with app.app_context():
        # Upload a file
        upload_res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"Notification test file content"), "notify_doc.pdf")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        assert upload_res.status_code == 201
        file_id = upload_res.get_json()["file"]["id"]

        # Create share
        share_res = client.post(
            f"/api/files/{file_id}/share",
            json={"permissions": {"can_view": True, "can_download": True}},
            headers=auth_header(owner_token),
        )
        assert share_res.status_code == 201
        share_data = share_res.get_json()["shares"][0]
        return share_data


class TestNotificationCreation:
    """Tests that accessing or downloading a shared file generates notifications for the owner."""

    def test_download_creates_notification_for_owner(self, app, client, db, owner, share_with_download):
        """Downloading a shared file creates a 'share_download' notification for the share's owner."""
        token = share_with_download["share_token"]
        share_id = share_with_download["id"]

        # Recipient/anonymous client downloads the file
        dl_res = client.get(f"/api/shares/{token}/download")
        assert dl_res.status_code == 200

        # Verify notification in database
        with app.app_context():
            notifs = Notification.query.filter_by(
                user_id=owner.id,
                type="share_download",
                related_share_id=uuid.UUID(share_id),
            ).all()
            assert len(notifs) == 1
            n = notifs[0]
            assert n.read_at is None
            assert "downloaded" in n.message
            assert "notify_doc.pdf" in n.message

    def test_view_creates_notification_for_owner(self, app, client, db, owner, share_with_download):
        """Accessing a shared file creates a 'share_view' notification for the owner."""
        token = share_with_download["share_token"]
        share_id = share_with_download["id"]

        # Access share metadata
        res = client.get(f"/api/shares/{token}/access")
        assert res.status_code == 200

        # Verify notification
        with app.app_context():
            notifs = Notification.query.filter_by(
                user_id=owner.id,
                type="share_view",
                related_share_id=uuid.UUID(share_id),
            ).all()
            assert len(notifs) >= 1
            assert "viewed" in notifs[0].message

    def test_failed_access_does_not_create_notification(self, app, client, db, owner, owner_token):
        """Failed accesses (e.g. wrong password) do not generate notifications."""
        # Create a password-protected share
        upload_res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"Secret content"), "secret.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = upload_res.get_json()["file"]["id"]
        share_res = client.post(
            f"/api/files/{file_id}/share",
            json={
                "permissions": {"can_view": True, "can_download": True},
                "password": "CorrectPassword123!",
            },
            headers=auth_header(owner_token),
        )
        token = share_res.get_json()["shares"][0]["share_token"]

        # Attempt download without grant -> rejected with 401
        res = client.get(f"/api/shares/{token}/download")
        assert res.status_code == 401

        # Confirm no download notification created
        with app.app_context():
            notifs = Notification.query.filter_by(
                user_id=owner.id,
                type="share_download",
            ).all()
            assert len(notifs) == 0


class TestNotificationEndpoints:
    """Tests for GET /api/notifications and PATCH /api/notifications/<id>/read."""

    def test_list_notifications_paginated_newest_first(self, app, client, db, owner, owner_token):
        """GET /api/notifications lists the current user's notifications newest first with pagination."""
        with app.app_context():
            n1 = Notification(user_id=owner.id, type="info", message="Old notification")
            n2 = Notification(user_id=owner.id, type="info", message="Mid notification")
            n3 = Notification(user_id=owner.id, type="info", message="New notification")
            db.session.add_all([n1, n2, n3])
            db.session.commit()

        res = client.get("/api/notifications?page=1&per_page=2", headers=auth_header(owner_token))
        assert res.status_code == 200
        data = res.get_json()
        assert data["total"] == 3
        assert data["page"] == 1
        assert data["per_page"] == 2
        assert data["pages"] == 2
        assert len(data["notifications"]) == 2
        # Newest first
        assert data["notifications"][0]["message"] == "New notification"
        assert data["notifications"][1]["message"] == "Mid notification"

    def test_list_notifications_user_isolation(self, app, client, db, owner, recipient, recipient_token):
        """Users can only see their own notifications, not other users'."""
        with app.app_context():
            n_owner = Notification(user_id=owner.id, type="owner_alert", message="For owner only")
            db.session.add(n_owner)
            db.session.commit()

        res = client.get("/api/notifications", headers=auth_header(recipient_token))
        assert res.status_code == 200
        data = res.get_json()
        assert data["total"] == 0
        assert len(data["notifications"]) == 0

    def test_filter_unread_notifications(self, app, client, db, owner, owner_token):
        """GET /api/notifications?unread=true filters out read notifications."""
        from datetime import datetime, timezone
        with app.app_context():
            n_unread = Notification(user_id=owner.id, type="alert", message="Still unread")
            n_read = Notification(
                user_id=owner.id,
                type="alert",
                message="Already read",
                read_at=datetime.now(timezone.utc),
            )
            db.session.add_all([n_unread, n_read])
            db.session.commit()

        res = client.get("/api/notifications?unread=true", headers=auth_header(owner_token))
        assert res.status_code == 200
        data = res.get_json()
        assert data["total"] == 1
        assert data["notifications"][0]["message"] == "Still unread"
        assert data["unread_count"] == 1

    def test_mark_notification_as_read(self, app, client, db, owner, owner_token):
        """PATCH /api/notifications/<id>/read marks a notification as read and sets read_at timestamp."""
        with app.app_context():
            n = Notification(user_id=owner.id, type="share_download", message="File downloaded")
            db.session.add(n)
            db.session.commit()
            notif_id = str(n.id)

        res = client.patch(f"/api/notifications/{notif_id}/read", headers=auth_header(owner_token))
        assert res.status_code == 200
        data = res.get_json()
        assert data["message"] == "Notification marked as read"
        assert data["notification"]["is_read"] is True
        assert data["notification"]["read_at"] is not None

        # Verify in database
        with app.app_context():
            saved = db.session.get(Notification, uuid.UUID(notif_id))
            assert saved.read_at is not None

    def test_mark_notification_read_forbidden_for_other_users(self, app, client, db, owner, recipient_token):
        """A user cannot mark another user's notification as read (returns 403)."""
        with app.app_context():
            n = Notification(user_id=owner.id, type="alert", message="Owner's private alert")
            db.session.add(n)
            db.session.commit()
            notif_id = str(n.id)

        res = client.patch(f"/api/notifications/{notif_id}/read", headers=auth_header(recipient_token))
        assert res.status_code == 403
        assert "Forbidden" in res.get_json()["error"]

    def test_mark_notification_read_not_found(self, client, owner_token):
        """Marking a nonexistent notification as read returns 404."""
        random_id = uuid.uuid4()
        res = client.patch(f"/api/notifications/{random_id}/read", headers=auth_header(owner_token))
        assert res.status_code == 404

    def test_notifications_unauthenticated_rejected(self, client):
        """Accessing notifications without authentication returns 401."""
        res1 = client.get("/api/notifications")
        assert res1.status_code == 401

        res2 = client.patch(f"/api/notifications/{uuid.uuid4()}/read")
        assert res2.status_code == 401
