"""
Tests for GET /api/files/<uuid:file_id>/analytics.

Covers:
- Aggregate statistics across all shares of a file:
  - total_views
  - total_downloads
  - unique_accessors (distinct user IDs for authenticated users; distinct IP addresses for anonymous shares)
  - 30-day time-series buckets (count, views, downloads per day for the last 30 days)
- Multi-share aggregation: logs from multiple shares of the same file aggregate correctly.
- Deduplication: same user or same anonymous IP accessing multiple times / multiple shares deduplicates.
- Failed attempts (success=False) are excluded from view/download/accessor counts.
- Older logs (>30 days ago) are included in all-time counts, but omitted from the 30-day daily time-series.
- Empty state: file with no shares/access logs returns 0s and 30 empty daily slots.
- User isolation & permissions:
  - Non-owner receives 403 Forbidden.
  - Unauthenticated caller receives 401 Unauthorized.
  - Nonexistent file UUID receives 404 Not Found.
- File isolation: logs on shares belonging to other files do not leak into analytics.
"""

import io
import uuid
from datetime import datetime, timedelta, timezone
import pytest

from app.extensions import db
from app.models import File, Share, AccessLog


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


class TestFileAnalyticsEndpoint:
    """Test suite for GET /api/files/<file_id>/analytics."""

    def test_file_analytics_aggregates_across_multiple_shares_and_days(
        self, client, owner, owner_token, recipient, recipient_token, app
    ):
        """
        Verify seeding AccessLog rows across different days and shares:
        - Views and downloads aggregate across shares.
        - Deduplication works for authenticated users and anonymous IPs.
        - 30-day daily time-series has appropriate daily counts.
        """
        now = datetime.now(timezone.utc)

        # 1. Upload a file
        up_res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"Quarterly Financial Report"), "report.pdf")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        assert up_res.status_code == 201
        file_id = up_res.get_json()["file"]["id"]

        # 2. Create two shares for this file
        s1_res = client.post(
            f"/api/files/{file_id}/share",
            json={"permissions": {"can_view": True, "can_download": True}},
            headers=auth_header(owner_token),
        )
        assert s1_res.status_code == 201
        share1_id = uuid.UUID(s1_res.get_json()["shares"][0]["id"])

        s2_res = client.post(
            f"/api/files/{file_id}/share",
            json={"permissions": {"can_view": True, "can_download": True}},
            headers=auth_header(owner_token),
        )
        assert s2_res.status_code == 201
        share2_id = uuid.UUID(s2_res.get_json()["shares"][0]["id"])

        # 3. Seed AccessLog entries across different days & shares
        # Accessors:
        # - Recipient user (authenticated, user_id=recipient.id)
        # - Anonymous IP 1 ("198.51.100.1")
        # - Anonymous IP 2 ("198.51.100.2")
        with app.app_context():
            logs = [
                # Share 1: 5 days ago - Recipient views and downloads
                AccessLog(
                    share_id=share1_id,
                    accessed_by=recipient.id,
                    ip_address="198.51.100.50",
                    action="view",
                    success=True,
                    timestamp=now - timedelta(days=5),
                ),
                AccessLog(
                    share_id=share1_id,
                    accessed_by=recipient.id,
                    ip_address="198.51.100.50",
                    action="download",
                    success=True,
                    timestamp=now - timedelta(days=5),
                ),
                # Share 1: 2 days ago - Anonymous IP 1 views
                AccessLog(
                    share_id=share1_id,
                    accessed_by=None,
                    ip_address="198.51.100.1",
                    action="view",
                    success=True,
                    timestamp=now - timedelta(days=2),
                ),
                # Share 2: 2 days ago - Recipient views again (same user across shares)
                AccessLog(
                    share_id=share2_id,
                    accessed_by=recipient.id,
                    ip_address="198.51.100.99",
                    action="view",
                    success=True,
                    timestamp=now - timedelta(days=2),
                ),
                # Share 2: 1 day ago - Anonymous IP 1 downloads (same IP across shares)
                AccessLog(
                    share_id=share2_id,
                    accessed_by=None,
                    ip_address="198.51.100.1",
                    action="download",
                    success=True,
                    timestamp=now - timedelta(days=1),
                ),
                # Share 2: Today - Anonymous IP 2 views
                AccessLog(
                    share_id=share2_id,
                    accessed_by=None,
                    ip_address="198.51.100.2",
                    action="view",
                    success=True,
                    timestamp=now,
                ),
                # Share 2: Today - Failed view attempt (wrong password / invalid grant)
                AccessLog(
                    share_id=share2_id,
                    accessed_by=None,
                    ip_address="198.51.100.3",
                    action="view",
                    success=False,
                    detail="Wrong password",
                    timestamp=now,
                ),
            ]
            db.session.add_all(logs)
            db.session.commit()

        # 4. Request analytics as the file owner
        res = client.get(
            f"/api/files/{file_id}/analytics",
            headers=auth_header(owner_token),
        )
        assert res.status_code == 200
        data = res.get_json()

        # Check aggregate counts:
        # Successful views:
        # 1 (Recipient s1) + 1 (IP1 s1) + 1 (Recipient s2) + 1 (IP2 s2) = 4
        # Failed view is excluded.
        assert data["total_views"] == 4

        # Successful downloads:
        # 1 (Recipient s1) + 1 (IP1 s2) = 2
        assert data["total_downloads"] == 2

        # Unique accessors:
        # Recipient (distinct user_id)
        # IP 198.51.100.1 (distinct anonymous IP)
        # IP 198.51.100.2 (distinct anonymous IP)
        # (Failed IP 198.51.100.3 is excluded)
        # Total unique accessors = 3
        assert data["unique_accessors"] == 3

        # Check time series
        time_series = data["time_series"]
        assert len(time_series) == 30

        # Construct date strings for expected days
        today_str = now.date().isoformat()
        day_1_str = (now.date() - timedelta(days=1)).isoformat()
        day_2_str = (now.date() - timedelta(days=2)).isoformat()
        day_5_str = (now.date() - timedelta(days=5)).isoformat()

        ts_by_date = {item["date"]: item for item in time_series}

        # 5 days ago: 1 view + 1 download = 2 count
        assert day_5_str in ts_by_date
        assert ts_by_date[day_5_str]["views"] == 1
        assert ts_by_date[day_5_str]["downloads"] == 1
        assert ts_by_date[day_5_str]["count"] == 2

        # 2 days ago: 2 views (IP1 on s1, Recipient on s2) = 2 count
        assert day_2_str in ts_by_date
        assert ts_by_date[day_2_str]["views"] == 2
        assert ts_by_date[day_2_str]["downloads"] == 0
        assert ts_by_date[day_2_str]["count"] == 2

        # 1 day ago: 1 download (IP1 on s2) = 1 count
        assert day_1_str in ts_by_date
        assert ts_by_date[day_1_str]["views"] == 0
        assert ts_by_date[day_1_str]["downloads"] == 1
        assert ts_by_date[day_1_str]["count"] == 1

        # Today: 1 view (IP2 on s2, failed view excluded) = 1 count
        assert today_str in ts_by_date
        assert ts_by_date[today_str]["views"] == 1
        assert ts_by_date[today_str]["downloads"] == 0
        assert ts_by_date[today_str]["count"] == 1

    def test_file_analytics_empty_when_no_shares_or_logs(self, client, owner, owner_token):
        """A freshly uploaded file with no shares has 0 stats and 30 empty daily slots."""
        up_res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"Fresh content"), "fresh.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        assert up_res.status_code == 201
        file_id = up_res.get_json()["file"]["id"]

        res = client.get(
            f"/api/files/{file_id}/analytics",
            headers=auth_header(owner_token),
        )
        assert res.status_code == 200
        data = res.get_json()

        assert data["file_id"] == file_id
        assert data["total_views"] == 0
        assert data["total_downloads"] == 0
        assert data["unique_accessors"] == 0
        assert len(data["time_series"]) == 30
        assert all(day["count"] == 0 for day in data["time_series"])
        assert all(day["views"] == 0 for day in data["time_series"])
        assert all(day["downloads"] == 0 for day in data["time_series"])

    def test_file_analytics_handles_old_logs_outside_30_days(
        self, client, owner, owner_token, app
    ):
        """
        Logs older than 30 days are included in all-time total_views and unique_accessors,
        but are omitted from the 30-day time-series buckets.
        """
        now = datetime.now(timezone.utc)

        up_res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"Old archive data"), "archive.dat")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = up_res.get_json()["file"]["id"]

        share_res = client.post(
            f"/api/files/{file_id}/share",
            json={"permissions": {"can_view": True, "can_download": True}},
            headers=auth_header(owner_token),
        )
        share_id = uuid.UUID(share_res.get_json()["shares"][0]["id"])

        with app.app_context():
            # Log from 45 days ago
            log_old = AccessLog(
                share_id=share_id,
                accessed_by=None,
                ip_address="203.0.113.45",
                action="view",
                success=True,
                timestamp=now - timedelta(days=45),
            )
            # Log from 10 days ago
            log_recent = AccessLog(
                share_id=share_id,
                accessed_by=None,
                ip_address="203.0.113.10",
                action="download",
                success=True,
                timestamp=now - timedelta(days=10),
            )
            db.session.add_all([log_old, log_recent])
            db.session.commit()

        res = client.get(
            f"/api/files/{file_id}/analytics",
            headers=auth_header(owner_token),
        )
        assert res.status_code == 200
        data = res.get_json()

        assert data["total_views"] == 1
        assert data["total_downloads"] == 1
        assert data["unique_accessors"] == 2

        # In the 30-day time series, only the 10-day-old log should be present
        time_series = data["time_series"]
        assert len(time_series) == 30
        total_bucketed_counts = sum(d["count"] for d in time_series)
        assert total_bucketed_counts == 1

        day_10_str = (now.date() - timedelta(days=10)).isoformat()
        day_10_entry = next((d for d in time_series if d["date"] == day_10_str), None)
        assert day_10_entry is not None
        assert day_10_entry["downloads"] == 1
        assert day_10_entry["views"] == 0
        assert day_10_entry["count"] == 1

    def test_file_analytics_isolation_between_files(
        self, client, owner, owner_token, app
    ):
        """Ensure AccessLog entries for File A's shares do not leak into File B's analytics."""
        now = datetime.now(timezone.utc)

        # File A
        up_a = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"File A"), "a.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_a_id = up_a.get_json()["file"]["id"]
        sh_a = client.post(
            f"/api/files/{file_a_id}/share",
            json={"permissions": {"can_view": True, "can_download": True}},
            headers=auth_header(owner_token),
        )
        share_a_id = uuid.UUID(sh_a.get_json()["shares"][0]["id"])

        # File B
        up_b = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"File B"), "b.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_b_id = up_b.get_json()["file"]["id"]
        sh_b = client.post(
            f"/api/files/{file_b_id}/share",
            json={"permissions": {"can_view": True, "can_download": True}},
            headers=auth_header(owner_token),
        )
        share_b_id = uuid.UUID(sh_b.get_json()["shares"][0]["id"])

        # Seed 3 views on Share A and 1 view on Share B
        with app.app_context():
            db.session.add_all([
                AccessLog(share_id=share_a_id, accessed_by=None, ip_address="10.0.0.1", action="view", success=True, timestamp=now),
                AccessLog(share_id=share_a_id, accessed_by=None, ip_address="10.0.0.2", action="view", success=True, timestamp=now),
                AccessLog(share_id=share_a_id, accessed_by=None, ip_address="10.0.0.3", action="view", success=True, timestamp=now),
                AccessLog(share_id=share_b_id, accessed_by=None, ip_address="10.0.0.9", action="view", success=True, timestamp=now),
            ])
            db.session.commit()

        # Query File A
        res_a = client.get(f"/api/files/{file_a_id}/analytics", headers=auth_header(owner_token))
        assert res_a.status_code == 200
        data_a = res_a.get_json()
        assert data_a["total_views"] == 3
        assert data_a["unique_accessors"] == 3

        # Query File B
        res_b = client.get(f"/api/files/{file_b_id}/analytics", headers=auth_header(owner_token))
        assert res_b.status_code == 200
        data_b = res_b.get_json()
        assert data_b["total_views"] == 1
        assert data_b["unique_accessors"] == 1

    def test_file_analytics_unauthorized_and_forbidden(
        self, client, owner, owner_token, recipient, recipient_token
    ):
        """Non-owners receive 403 Forbidden; unauthenticated callers receive 401 Unauthorized."""
        up_res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"Secret Document"), "secret.doc")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = up_res.get_json()["file"]["id"]

        # 1. Unauthenticated request -> 401
        unauth_res = client.get(f"/api/files/{file_id}/analytics")
        assert unauth_res.status_code == 401

        # 2. Non-owner authenticated request -> 403
        forbidden_res = client.get(
            f"/api/files/{file_id}/analytics",
            headers=auth_header(recipient_token),
        )
        assert forbidden_res.status_code == 403

    def test_file_analytics_nonexistent_file_returns_404(self, client, owner_token):
        """Requesting analytics for an invalid or non-existent file UUID returns 404."""
        random_uuid = str(uuid.uuid4())
        res = client.get(
            f"/api/files/{random_uuid}/analytics",
            headers=auth_header(owner_token),
        )
        assert res.status_code == 404
