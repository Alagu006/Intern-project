"""
Unit tests for Module 6: Admin Dashboard & User Management

Covers:
- Role enforcement (non-admin gets 403)
- Disable/enable user functionality
- User listing with filters
- Storage statistics
- Audit log viewing and export
- System statistics
- Chart data generation
"""

import pytest
from datetime import datetime, timedelta, timezone
from app.extensions import db
from app.models import User, File, Share, AccessLog


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def make_admin_user(db_session, username, email):
    """Create an admin user."""
    u = User(username=username, email=email, role="admin")
    u.set_password("Admin1234!")
    db_session.add(u)
    db_session.commit()
    return u


def make_regular_user(db_session, username, email):
    """Create a regular user."""
    u = User(username=username, email=email, role="user")
    u.set_password("User1234!")
    db_session.add(u)
    db_session.commit()
    return u


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="function")
def admin_user(app, db):
    with app.app_context():
        user = make_admin_user(db.session, "admin", "admin@test.com")
        db.session.refresh(user)
        return user


@pytest.fixture(scope="function")
def regular_user(app, db):
    with app.app_context():
        user = make_regular_user(db.session, "regular", "regular@test.com")
        db.session.refresh(user)
        return user


@pytest.fixture(scope="function")
def admin_token(app, db, admin_user):
    with app.app_context():
        from app.auth.decorators import generate_access_token
        db.session.add(admin_user)
        return generate_access_token(admin_user)


@pytest.fixture(scope="function")
def user_token(app, db, regular_user):
    with app.app_context():
        from app.auth.decorators import generate_access_token
        db.session.add(regular_user)
        return generate_access_token(regular_user)


# ---------------------------------------------------------------------------
# 1. Role Enforcement
# ---------------------------------------------------------------------------

class TestRoleEnforcement:
    def test_non_admin_cannot_access_admin_endpoints(self, client, user_token):
        """Regular users should get 403 on all /api/admin/* endpoints."""
        endpoints = [
            "/api/admin/users",
            "/api/admin/files",
            "/api/admin/storage",
            "/api/admin/audit-logs",
            "/api/admin/stats/summary",
            "/api/admin/stats/charts",
        ]
        
        for endpoint in endpoints:
            res = client.get(endpoint, headers=auth_header(user_token))
            assert res.status_code == 403
            assert "admin" in res.get_json()["error"].lower()
    
    def test_admin_can_access_admin_endpoints(self, client, admin_token):
        """Admin users should be able to access admin endpoints."""
        res = client.get("/api/admin/users", headers=auth_header(admin_token))
        assert res.status_code == 200
    
    def test_no_token_returns_401(self, client):
        """Requests without JWT should return 401."""
        res = client.get("/api/admin/users")
        assert res.status_code == 401


# ---------------------------------------------------------------------------
# 2. User Management
# ---------------------------------------------------------------------------

class TestUserManagement:
    def test_list_users(self, client, admin_token, regular_user):
        """Admin can list all users."""
        res = client.get("/api/admin/users", headers=auth_header(admin_token))
        assert res.status_code == 200
        data = res.get_json()
        assert "items" in data
        assert "total" in data
        assert data["total"] >= 2  # at least admin and regular user
    
    def test_search_users_by_username(self, client, admin_token):
        """Search users by username."""
        res = client.get(
            "/api/admin/users?search=admin",
            headers=auth_header(admin_token)
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["total"] >= 1
        assert any("admin" in item["username"].lower() for item in data["items"])
    
    def test_filter_users_by_role(self, client, admin_token):
        """Filter users by role."""
        res = client.get(
            "/api/admin/users?role=admin",
            headers=auth_header(admin_token)
        )
        assert res.status_code == 200
        data = res.get_json()
        assert all(item["role"] == "admin" for item in data["items"])
    
    def test_get_user_detail(self, app, client, admin_token, regular_user):
        """Admin can view detailed user info."""
        res = client.get(
            f"/api/admin/users/{regular_user.id}",
            headers=auth_header(admin_token)
        )
        assert res.status_code == 200
        data = res.get_json()
        assert "user" in data
        assert "stats" in data
        assert data["user"]["id"] == str(regular_user.id)
        assert "file_count" in data["stats"]
        assert "storage_used_bytes" in data["stats"]
    
    def test_disable_user(self, app, client, admin_token, db):
        """Admin can disable a user account."""
        with app.app_context():
            # Create a user to disable
            test_user = make_regular_user(db.session, "todisable", "todisable@test.com")
            user_id = test_user.id
        
        res = client.patch(
            f"/api/admin/users/{user_id}/disable",
            headers=auth_header(admin_token)
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["user"]["is_active"] is False
        assert data["user"]["disabled_at"] is not None
    
    def test_enable_user(self, app, client, admin_token, db):
        """Admin can re-enable a disabled user."""
        with app.app_context():
            # Create and disable a user
            test_user = make_regular_user(db.session, "toenable", "toenable@test.com")
            test_user.is_active = False
            test_user.disabled_at = datetime.now(timezone.utc)
            db.session.commit()
            user_id = test_user.id
        
        res = client.patch(
            f"/api/admin/users/{user_id}/enable",
            headers=auth_header(admin_token)
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["user"]["is_active"] is True
        assert data["user"]["disabled_at"] is None
    
    def test_cannot_disable_own_account(self, app, client, admin_token, admin_user):
        """Admin cannot disable their own account."""
        res = client.patch(
            f"/api/admin/users/{admin_user.id}/disable",
            headers=auth_header(admin_token)
        )
        assert res.status_code == 400
        assert "cannot disable your own" in res.get_json()["error"].lower()
    
    def test_disabled_user_cannot_login(self, app, client, db):
        """Disabled users should be unable to log in."""
        with app.app_context():
            # Create and disable a user
            test_user = make_regular_user(db.session, "disabled_login", "disabled@test.com")
            test_user.is_active = False
            db.session.commit()
        
        res = client.post(
            "/api/auth/login",
            json={"email": "disabled@test.com", "password": "User1234!"}
        )
        assert res.status_code == 403
        assert "disabled" in res.get_json()["error"].lower()


# ---------------------------------------------------------------------------
# 3. File Management
# ---------------------------------------------------------------------------

class TestFileManagement:
    def test_list_all_files(self, client, admin_token):
        """Admin can list all files system-wide."""
        res = client.get("/api/admin/files", headers=auth_header(admin_token))
        assert res.status_code == 200
        data = res.get_json()
        assert "items" in data
        assert "total" in data
    
    def test_files_include_owner_info(self, app, client, admin_token, regular_user, db):
        """File listings should include owner information."""
        # Create a test file
        with app.app_context():
            from app.crypto.file_crypto import encrypt_file
            import tempfile
            
            plaintext = b"Test file content"
            ciphertext, nonce_hex, wrapped_key_hex = encrypt_file(plaintext)
            
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".enc")
            tmp.write(ciphertext)
            tmp.close()
            
            test_file = File(
                owner_id=regular_user.id,
                filename="admin_test.txt",
                mime_type="text/plain",
                size_bytes=len(plaintext),
                encrypted_path=tmp.name,
                nonce_hex=nonce_hex,
                wrapped_key_hex=wrapped_key_hex,
            )
            db.session.add(test_file)
            db.session.commit()
        
        res = client.get("/api/admin/files", headers=auth_header(admin_token))
        assert res.status_code == 200
        data = res.get_json()
        
        # Check that files have owner info
        if data["total"] > 0:
            assert "owner" in data["items"][0]
            assert "username" in data["items"][0]["owner"]


# ---------------------------------------------------------------------------
# 4. Storage Statistics
# ---------------------------------------------------------------------------

class TestStorageStatistics:
    def test_get_storage_usage(self, client, admin_token):
        """Admin can view storage usage statistics."""
        res = client.get("/api/admin/storage", headers=auth_header(admin_token))
        assert res.status_code == 200
        data = res.get_json()
        assert "total_storage_bytes" in data
        assert "top_users" in data
        assert "storage_by_type" in data
        assert isinstance(data["total_storage_bytes"], int)
        assert isinstance(data["top_users"], list)
        assert isinstance(data["storage_by_type"], list)


# ---------------------------------------------------------------------------
# 5. Audit Logs
# ---------------------------------------------------------------------------

class TestAuditLogs:
    def test_view_audit_logs(self, client, admin_token):
        """Admin can view audit logs."""
        res = client.get("/api/admin/audit-logs", headers=auth_header(admin_token))
        assert res.status_code == 200
        data = res.get_json()
        assert "items" in data
        assert "total" in data
    
    def test_filter_audit_logs_by_action(self, app, client, admin_token, regular_user, db):
        """Filter audit logs by action type."""
        # Create a test log entry
        with app.app_context():
            log = AccessLog(
                share_id=None,
                accessed_by=regular_user.id,
                ip_address="192.168.1.100",
                action="test_action",
                success=True,
            )
            db.session.add(log)
            db.session.commit()
        
        res = client.get(
            "/api/admin/audit-logs?action=test_action",
            headers=auth_header(admin_token)
        )
        assert res.status_code == 200
        data = res.get_json()
        if data["total"] > 0:
            assert all(item["action"] == "test_action" for item in data["items"])
    
    def test_export_audit_logs_csv(self, client, admin_token):
        """Admin can export audit logs as CSV."""
        res = client.get(
            "/api/admin/audit-logs/export",
            headers=auth_header(admin_token)
        )
        assert res.status_code == 200
        assert res.content_type == "text/csv; charset=utf-8"
        assert "audit_logs_" in res.headers["Content-Disposition"]
        
        # Check CSV content
        csv_content = res.data.decode("utf-8")
        assert "ID,Share ID,Accessed By" in csv_content  # Header
    
    def test_csv_formula_injection_prevention(self, app, client, admin_token, regular_user, db):
        """CSV export should sanitize dangerous formulas."""
        with app.app_context():
            # Create a log with potential formula injection
            log = AccessLog(
                share_id=None,
                accessed_by=regular_user.id,
                ip_address="192.168.1.100",
                action="=HYPERLINK",  # Starts with =
                success=True,
                detail="+malicious",  # Starts with +
            )
            db.session.add(log)
            db.session.commit()
        
        res = client.get(
            "/api/admin/audit-logs/export",
            headers=auth_header(admin_token)
        )
        assert res.status_code == 200
        csv_content = res.data.decode("utf-8")
        
        # Check that dangerous chars are prefixed with '
        assert "'=HYPERLINK" in csv_content or "HYPERLINK" not in csv_content
        assert "'+malicious" in csv_content or "+malicious" not in csv_content


# ---------------------------------------------------------------------------
# 6. System Statistics
# ---------------------------------------------------------------------------

class TestSystemStatistics:
    def test_get_summary_stats(self, client, admin_token):
        """Admin can view system summary statistics."""
        res = client.get(
            "/api/admin/stats/summary",
            headers=auth_header(admin_token)
        )
        assert res.status_code == 200
        data = res.get_json()
        
        required_fields = [
            "total_users",
            "total_files",
            "uploads_today",
            "downloads_today",
            "shared_files_count",
            "failed_login_attempts_today",
        ]
        
        for field in required_fields:
            assert field in data
            assert isinstance(data[field], int)
    
    def test_get_chart_data_uploads(self, client, admin_token):
        """Admin can get uploads chart data."""
        res = client.get(
            "/api/admin/stats/charts?metric=uploads&range=7d",
            headers=auth_header(admin_token)
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["metric"] == "uploads"
        assert data["range"] == "7d"
        assert "data" in data
        assert len(data["data"]) == 7  # 7 days
        assert all("date" in item and "value" in item for item in data["data"])
    
    def test_get_chart_data_downloads(self, client, admin_token):
        """Admin can get downloads chart data."""
        res = client.get(
            "/api/admin/stats/charts?metric=downloads&range=30d",
            headers=auth_header(admin_token)
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["metric"] == "downloads"
        assert data["range"] == "30d"
        assert len(data["data"]) == 30
    
    def test_get_chart_data_storage(self, client, admin_token):
        """Admin can get storage usage chart data."""
        res = client.get(
            "/api/admin/stats/charts?metric=storage&range=7d",
            headers=auth_header(admin_token)
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["metric"] == "storage"
        assert "data" in data
    
    def test_get_chart_data_activity(self, client, admin_token):
        """Admin can get user activity chart data."""
        res = client.get(
            "/api/admin/stats/charts?metric=activity&range=7d",
            headers=auth_header(admin_token)
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["metric"] == "activity"
        assert "data" in data
    
    def test_invalid_metric_returns_400(self, client, admin_token):
        """Invalid metric should return 400."""
        res = client.get(
            "/api/admin/stats/charts?metric=invalid",
            headers=auth_header(admin_token)
        )
        assert res.status_code == 400


# ---------------------------------------------------------------------------
# 7. Admin Action Logging
# ---------------------------------------------------------------------------

class TestAdminActionLogging:
    def test_disable_action_is_logged(self, app, client, admin_token, db):
        """Disabling a user should create an audit log entry."""
        with app.app_context():
            test_user = make_regular_user(db.session, "logtest", "logtest@test.com")
            user_id = test_user.id
            
            # Get initial log count
            initial_count = AccessLog.query.filter_by(action="admin_disable_user").count()
        
        # Disable the user
        client.patch(
            f"/api/admin/users/{user_id}/disable",
            headers=auth_header(admin_token)
        )
        
        with app.app_context():
            # Check that log was created
            new_count = AccessLog.query.filter_by(action="admin_disable_user").count()
            assert new_count > initial_count
    
    def test_export_action_is_logged(self, app, client, admin_token, db):
        """Exporting logs should create an audit log entry."""
        with app.app_context():
            initial_count = AccessLog.query.filter_by(action="admin_export_logs").count()
        
        # Export logs
        client.get(
            "/api/admin/audit-logs/export",
            headers=auth_header(admin_token)
        )
        
        with app.app_context():
            new_count = AccessLog.query.filter_by(action="admin_export_logs").count()
            assert new_count > initial_count
