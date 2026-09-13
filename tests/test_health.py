from unittest.mock import patch
import pytest
from sqlalchemy.exc import OperationalError


class TestHealthCheck:
    """Tests for GET /health and /healthz readiness/liveness endpoints."""

    def test_health_check_healthy(self, client):
        """When the database is reachable, /health returns 200 and status ok."""
        res = client.get("/health")
        assert res.status_code == 200
        data = res.get_json()
        assert data["status"] == "ok"
        assert data["database"] == "ok"

    def test_healthz_alias_healthy(self, client):
        """Kubernetes-style /healthz endpoint works identically."""
        res = client.get("/healthz")
        assert res.status_code == 200
        data = res.get_json()
        assert data["status"] == "ok"
        assert data["database"] == "ok"

    def test_health_check_no_auth_required(self, client):
        """Health check endpoint requires no Authorization header."""
        res = client.get("/health")
        assert res.status_code == 200

    def test_health_check_unhealthy_on_db_failure(self, client):
        """When DB connectivity fails, /health returns 503 and status error."""
        with patch("app.extensions.db.session.execute", side_effect=OperationalError("connection refused", {}, None)):
            res = client.get("/health")
            assert res.status_code == 503
            data = res.get_json()
            assert data["status"] == "error"
            assert data["database"] == "unavailable"
            assert "connection refused" in data["message"]

    def test_health_check_unhealthy_on_generic_exception(self, client):
        """Generic unexpected exceptions during health check also return 503."""
        with patch("app.extensions.db.session.execute", side_effect=RuntimeError("Unexpected DB driver crash")):
            res = client.get("/health")
            assert res.status_code == 503
            data = res.get_json()
            assert data["status"] == "error"
            assert data["database"] == "unavailable"
            assert "Unexpected DB driver crash" in data["message"]
