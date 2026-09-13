import pytest
from app import create_app
from app.config import Config


class TestCorsConfiguration:
    def test_default_allowed_origins_config(self):
        """Verify ALLOWED_ORIGINS defaults to a safe local URL and never wildcard *."""
        assert "ALLOWED_ORIGINS" in dir(Config)
        assert "*" not in Config.ALLOWED_ORIGINS
        assert "http://localhost:3000" in Config.ALLOWED_ORIGINS

    def test_cors_headers_on_allowed_origin(self, client):
        """Requests from allowed origin receive Access-Control-Allow-Origin and credentials."""
        res = client.get("/api/auth/me", headers={"Origin": "http://localhost:3000"})
        assert res.headers.get("Access-Control-Allow-Origin") == "http://localhost:3000"
        assert res.headers.get("Access-Control-Allow-Credentials") == "true"

    def test_cors_headers_absent_on_disallowed_origin(self, client):
        """Requests from disallowed origin do not receive Access-Control-Allow-Origin."""
        res = client.get("/api/auth/me", headers={"Origin": "http://malicious-attacker.com"})
        assert res.headers.get("Access-Control-Allow-Origin") is None

    def test_options_preflight_allowed_origin(self, client):
        """Preflight OPTIONS from allowed origin returns status 200 and CORS headers."""
        res = client.options(
            "/api/auth/login",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Authorization, Content-Type",
            },
        )
        assert res.status_code == 200
        assert res.headers.get("Access-Control-Allow-Origin") == "http://localhost:3000"
        assert res.headers.get("Access-Control-Allow-Credentials") == "true"
        allow_methods = res.headers.get("Access-Control-Allow-Methods", "")
        assert "POST" in allow_methods
        allow_headers = res.headers.get("Access-Control-Allow-Headers", "")
        assert "authorization" in allow_headers.lower()

    def test_options_preflight_disallowed_origin(self, client):
        """Preflight OPTIONS from disallowed origin does not receive CORS allow origin."""
        res = client.options(
            "/api/auth/login",
            headers={
                "Origin": "http://untrusted-domain.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Authorization, Content-Type",
            },
        )
        assert res.headers.get("Access-Control-Allow-Origin") is None

    def test_multiple_comma_separated_origins(self):
        """Multiple origins configured via comma-separated string are properly supported."""
        custom_origins = "http://localhost:3000, https://app.example.com, https://portal.example.com"
        app = create_app({
            "TESTING": True,
            "ALLOWED_ORIGINS": custom_origins,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "RATELIMIT_ENABLED": False,
            "MASTER_KEK": "dGVzdC1tYXN0ZXIta2VrLTMyLWJ5dGVzLWxlbmd0aCE=",
        })
        client = app.test_client()

        # Check app.example.com
        res1 = client.get("/api/auth/me", headers={"Origin": "https://app.example.com"})
        assert res1.headers.get("Access-Control-Allow-Origin") == "https://app.example.com"
        assert res1.headers.get("Access-Control-Allow-Credentials") == "true"

        # Check portal.example.com
        res2 = client.get("/api/auth/me", headers={"Origin": "https://portal.example.com"})
        assert res2.headers.get("Access-Control-Allow-Origin") == "https://portal.example.com"

        # Check http://localhost:3000
        res3 = client.get("/api/auth/me", headers={"Origin": "http://localhost:3000"})
        assert res3.headers.get("Access-Control-Allow-Origin") == "http://localhost:3000"

        # Check unapproved origin
        res4 = client.get("/api/auth/me", headers={"Origin": "https://evil.com"})
        assert res4.headers.get("Access-Control-Allow-Origin") is None
