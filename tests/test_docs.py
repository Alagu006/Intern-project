import pytest
from app import create_app
from app.config import Config, TestingConfig


class TestApiDocs:
    """Tests for Swagger UI (/api/docs) and raw spec (/api/openapi.yaml)."""

    def test_config_defaults(self):
        """Verify ENABLE_API_DOCS defaults to False in production config and True in TestingConfig."""
        assert Config.ENABLE_API_DOCS is False or Config.DEBUG is True
        assert TestingConfig.ENABLE_API_DOCS is True

    def test_swagger_ui_served_when_enabled(self, client):
        """GET /api/docs serves HTML with Swagger UI configured for /api/openapi.yaml."""
        res = client.get("/api/docs")
        assert res.status_code == 200
        assert "text/html" in res.headers.get("Content-Type", "")
        html = res.get_data(as_text=True)
        assert "SwaggerUIBundle" in html
        assert "/api/openapi.yaml" in html
        assert "swagger-ui-dist" in html

    def test_openapi_yaml_served_when_enabled(self, client):
        """GET /api/openapi.yaml serves raw spec with YAML mimetype."""
        res = client.get("/api/openapi.yaml")
        assert res.status_code == 200
        content_type = res.headers.get("Content-Type", "")
        assert "yaml" in content_type.lower()
        body = res.get_data(as_text=True)
        assert "openapi:" in body
        assert "Secure File Sharing API" in body

    def test_docs_routes_unauthenticated(self, client):
        """Neither /api/docs nor /api/openapi.yaml requires authentication."""
        res1 = client.get("/api/docs")
        assert res1.status_code == 200
        res2 = client.get("/api/openapi.yaml")
        assert res2.status_code == 200

    def test_docs_disabled_returns_404(self, client):
        """When ENABLE_API_DOCS is False and DEBUG is False, routes return 404."""
        app = client.application
        orig_enable = app.config.get("ENABLE_API_DOCS")
        orig_debug = app.config.get("DEBUG")
        try:
            app.config["ENABLE_API_DOCS"] = False
            app.config["DEBUG"] = False

            res1 = client.get("/api/docs")
            assert res1.status_code == 404
            assert res1.get_json()["error"] == "API documentation is disabled"

            res2 = client.get("/api/openapi.yaml")
            assert res2.status_code == 404
            assert res2.get_json()["error"] == "API documentation is disabled"
        finally:
            app.config["ENABLE_API_DOCS"] = orig_enable
            app.config["DEBUG"] = orig_debug

    def test_docs_enabled_via_debug_flag(self, client):
        """When ENABLE_API_DOCS is False but DEBUG is True, docs routes remain accessible."""
        app = client.application
        orig_enable = app.config.get("ENABLE_API_DOCS")
        orig_debug = app.config.get("DEBUG")
        try:
            app.config["ENABLE_API_DOCS"] = False
            app.config["DEBUG"] = True

            res = client.get("/api/docs")
            assert res.status_code == 200
            assert "SwaggerUIBundle" in res.get_data(as_text=True)

            res_yaml = client.get("/api/openapi.yaml")
            assert res_yaml.status_code == 200
        finally:
            app.config["ENABLE_API_DOCS"] = orig_enable
            app.config["DEBUG"] = orig_debug
