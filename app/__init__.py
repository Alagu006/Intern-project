from flask import Flask, jsonify
from flask_cors import CORS
from flask_limiter.errors import RateLimitExceeded
from werkzeug.exceptions import RequestEntityTooLarge
from sqlalchemy import text
from app.config import Config, TestingConfig
from app.extensions import db, migrate, limiter, cors


def create_app(config=None):
    app = Flask(__name__)

    if config == "testing":
        app.config.from_object(TestingConfig)
    elif isinstance(config, type):
        app.config.from_object(config)
    elif isinstance(config, dict):
        base_config = TestingConfig if config.get("TESTING", True) else Config
        app.config.from_object(base_config)
        app.config.update(config)
    else:
        app.config.from_object(Config)

    # Startup validation: verify secure secret keys in non-testing environments
    if config != "testing" and not app.config.get("TESTING"):
        secret_key = app.config.get("SECRET_KEY")
        jwt_secret_key = app.config.get("JWT_SECRET_KEY")
        master_kek = app.config.get("MASTER_KEK")

        insecure_vars = []
        if not secret_key or secret_key == "change-me-in-production":
            insecure_vars.append("SECRET_KEY")
        if not jwt_secret_key or jwt_secret_key == "jwt-secret-change-me":
            insecure_vars.append("JWT_SECRET_KEY")
        if master_kek == "change-me-in-production-master-kek":
            insecure_vars.append("MASTER_KEK")
        elif master_kek:
            try:
                import base64
                if len(base64.b64decode(master_kek)) != 32:
                    insecure_vars.append("MASTER_KEK (must be 32 bytes base64-encoded)")
            except Exception:
                insecure_vars.append("MASTER_KEK (invalid base64)")

        if insecure_vars:
            names = ", ".join(insecure_vars)
            raise RuntimeError(
                f"Insecure startup configuration: {names} must be explicitly set to secure values "
                f"in non-testing environments and cannot use default placeholder strings ('change-me-in-production', 'jwt-secret-change-me', 'change-me-in-production-master-kek'). "
                f"Please set the SECRET_KEY, JWT_SECRET_KEY, and MASTER_KEK environment variables before starting the application."
            )

    # Init extensions
    db.init_app(app)
    migrate.init_app(app, db)
    limiter.init_app(app)

    # Initialize CORS
    allowed_origins = app.config.get("ALLOWED_ORIGINS", ["http://localhost:3000"])
    if isinstance(allowed_origins, str):
        allowed_origins = [
            origin.strip()
            for origin in allowed_origins.split(",")
            if origin.strip()
        ]
    cors.init_app(app, origins=allowed_origins, supports_credentials=True)

    # Global rate limit error handler (return 429 with clear JSON error)
    @app.errorhandler(RateLimitExceeded)
    @app.errorhandler(429)
    def ratelimit_handler(e):
        resp = jsonify({
            "error": "Rate limit exceeded",
            "message": str(getattr(e, "description", "Too many requests, please try again later.")),
        })
        resp.status_code = 429
        if hasattr(e, "get_headers"):
            for k, v in e.get_headers():
                if k.lower() != "content-type":
                    resp.headers[k] = v
        return resp

    # Global 413 Request Entity Too Large error handler (return clear JSON error)
    @app.errorhandler(RequestEntityTooLarge)
    @app.errorhandler(413)
    def request_entity_too_large(e):
        resp = jsonify({
            "error": "Request entity too large",
            "message": str(getattr(e, "description", "The uploaded file exceeds the maximum allowed size.")),
        })
        resp.status_code = 413
        return resp

    # Health check endpoints for load balancers and orchestrators
    @app.route("/health", methods=["GET"])
    @app.route("/healthz", methods=["GET"])
    @limiter.exempt
    def health_check():
        try:
            db.session.execute(text("SELECT 1"))
            return jsonify({"status": "ok", "database": "ok"}), 200
        except Exception as e:
            return jsonify({
                "status": "error",
                "database": "unavailable",
                "message": str(e),
            }), 503

    # Register models so Alembic/Flask-Migrate sees them
    with app.app_context():
        from app.models import User, File, FileVersion, Share, AccessLog, Folder, Tag, file_tags, Notification, PersonalAccessToken, UploadSession, Webhook  # noqa: F401

    # Register blueprints
    from app.auth.routes import bp as auth_bp
    from app.files.routes import bp as files_bp
    from app.shares.routes import bp as shares_bp
    from app.admin.routes import bp as admin_bp  # Module 6
    from app.docs import bp as docs_bp
    from app.folders.routes import bp as folders_bp
    from app.tags.routes import bp as tags_bp
    from app.notifications.routes import bp as notifications_bp
    from app.webhooks.routes import bp as webhooks_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(shares_bp)
    app.register_blueprint(admin_bp)  # Module 6
    app.register_blueprint(docs_bp)
    app.register_blueprint(folders_bp)
    app.register_blueprint(tags_bp)
    app.register_blueprint(notifications_bp)
    app.register_blueprint(webhooks_bp)

    return app
