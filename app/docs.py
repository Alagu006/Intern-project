"""
Interactive API documentation routes (Swagger UI and OpenAPI specification).
"""

import os
from flask import Blueprint, current_app, Response, jsonify, render_template_string

bp = Blueprint("docs", __name__, url_prefix="/api")

SWAGGER_UI_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Secure File Share API - Documentation</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
    <link rel="icon" type="image/png" href="https://unpkg.com/swagger-ui-dist@5/favicon-32x32.png" sizes="32x32" />
    <style>
        html { box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }
        *, *:before, *:after { box-sizing: inherit; }
        body { margin: 0; background: #fafafa; font-family: sans-serif; }
        .topbar { display: none; }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js" charset="UTF-8"></script>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-standalone-preset.js" charset="UTF-8"></script>
    <script>
    window.onload = function() {
        window.ui = SwaggerUIBundle({
            url: "{{ spec_url }}",
            dom_id: '#swagger-ui',
            deepLinking: true,
            presets: [
                SwaggerUIBundle.presets.apis,
                SwaggerUIStandalonePreset
            ],
            plugins: [
                SwaggerUIBundle.plugins.DownloadUrl
            ],
            layout: "BaseLayout"
        });
    };
    </script>
</body>
</html>
"""


def _is_docs_enabled():
    """Check if API documentation routes are enabled in the current environment."""
    return bool(
        current_app.config.get("ENABLE_API_DOCS")
        or current_app.config.get("DEBUG")
    )


def _resolve_spec_path():
    """Locate openapi.yaml across relative project root and cwd."""
    candidate_paths = [
        os.path.abspath(os.path.join(current_app.root_path, "..", "openapi.yaml")),
        os.path.abspath(os.path.join(current_app.root_path, "openapi.yaml")),
        os.path.abspath(os.path.join(os.getcwd(), "openapi.yaml")),
    ]
    for path in candidate_paths:
        if os.path.isfile(path):
            return path
    return None


@bp.route("/openapi.yaml", methods=["GET"])
def get_openapi_spec():
    """
    Serve the raw OpenAPI YAML specification.
    Returns 404 if disabled by config or file missing.
    """
    if not _is_docs_enabled():
        return jsonify({"error": "API documentation is disabled"}), 404

    spec_path = _resolve_spec_path()
    if not spec_path:
        return jsonify({"error": "OpenAPI specification not found"}), 404

    with open(spec_path, "r", encoding="utf-8") as f:
        spec_content = f.read()

    return Response(spec_content, mimetype="application/yaml; charset=utf-8")


@bp.route("/docs", methods=["GET"])
def get_swagger_ui():
    """
    Serve interactive Swagger UI web interface configured to load /api/openapi.yaml.
    Returns 404 if disabled by config.
    """
    if not _is_docs_enabled():
        return jsonify({"error": "API documentation is disabled"}), 404

    return render_template_string(
        SWAGGER_UI_HTML,
        spec_url="/api/openapi.yaml",
    ), 200
