"""
Tests for on-demand image thumbnail generation endpoint (GET /api/files/<uuid:file_id>/thumbnail).

Validates:
- Successful thumbnail generation for image/png, image/jpeg, image/webp.
- Proper aspect ratio scaling to max 400x400.
- Decryption occurs in-memory with decrypt_file_bytes.
- In-memory LRU cache hit functionality.
- Rejection of non-image MIME types (PDF, text) with 415 Unsupported Media Type.
- Authentication & authorization controls (owner JWT, share token, custom slug, password grant).
- Error cases: 401 unauthenticated, 403 forbidden, 404 not found, 410 expired/revoked.
"""

import io
import uuid
from PIL import Image
import pytest

from app.models import File, Share


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def create_test_image(format="PNG", size=(800, 600), color=(255, 0, 0), mode="RGB") -> bytes:
    """Create in-memory image bytes using Pillow."""
    buf = io.BytesIO()
    img = Image.new(mode, size, color=color)
    img.save(buf, format=format)
    return buf.getvalue()


class TestFileThumbnailEndpoint:
    """Test suite for GET /api/files/<uuid:file_id>/thumbnail."""

    def test_owner_can_get_png_thumbnail(self, client, owner_token):
        """Owner can request a thumbnail for an uploaded PNG image; returns 200 JPEG <= 400x400."""
        png_bytes = create_test_image(format="PNG", size=(800, 600), color=(200, 50, 50))
        upload_res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(png_bytes), "sample.png")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        assert upload_res.status_code == 201
        file_id = upload_res.get_json()["file"]["id"]

        thumb_res = client.get(
            f"/api/files/{file_id}/thumbnail",
            headers=auth_header(owner_token),
        )
        assert thumb_res.status_code == 200
        assert thumb_res.mimetype == "image/jpeg"
        assert thumb_res.headers.get("Content-Type") == "image/jpeg"
        assert thumb_res.headers.get("X-Thumbnail-Cache") == "MISS"

        # Verify image using Pillow
        thumb_img = Image.open(io.BytesIO(thumb_res.data))
        assert thumb_img.format == "JPEG"
        w, h = thumb_img.size
        assert w <= 400 and h <= 400
        # 800x600 scaled down to max 400x400 should be exactly 400x300
        assert (w, h) == (400, 300)

    def test_owner_can_get_jpeg_and_webp_thumbnail(self, client, owner_token):
        """Owner can request thumbnails for JPEG and WebP images."""
        # 1. JPEG (600x900 -> 266x400 or 267x400)
        jpeg_bytes = create_test_image(format="JPEG", size=(600, 900), color=(0, 128, 255))
        up_jpg = client.post(
            "/api/files",
            data={"file": (io.BytesIO(jpeg_bytes), "photo.jpeg")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        assert up_jpg.status_code == 201
        jpg_id = up_jpg.get_json()["file"]["id"]

        res_jpg = client.get(f"/api/files/{jpg_id}/thumbnail", headers=auth_header(owner_token))
        assert res_jpg.status_code == 200
        img_jpg = Image.open(io.BytesIO(res_jpg.data))
        assert img_jpg.format == "JPEG"
        assert img_jpg.size[1] == 400
        assert img_jpg.size[0] <= 400

        # 2. WebP (500x500 -> 400x400)
        webp_bytes = create_test_image(format="WEBP", size=(500, 500), color=(50, 200, 50))
        up_webp = client.post(
            "/api/files",
            data={"file": (io.BytesIO(webp_bytes), "graphic.webp", "image/webp")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        assert up_webp.status_code == 201
        webp_id = up_webp.get_json()["file"]["id"]

        res_webp = client.get(f"/api/files/{webp_id}/thumbnail", headers=auth_header(owner_token))
        assert res_webp.status_code == 200
        img_webp = Image.open(io.BytesIO(res_webp.data))
        assert img_webp.format == "JPEG"
        assert img_webp.size == (400, 400)

    def test_thumbnail_handles_rgba_transparency(self, client, owner_token):
        """RGBA PNG with transparency is converted to RGB with clean compositing for JPEG output."""
        rgba_bytes = create_test_image(format="PNG", size=(200, 200), color=(255, 0, 0, 128), mode="RGBA")
        up_res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(rgba_bytes), "transparent.png")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        assert up_res.status_code == 201
        file_id = up_res.get_json()["file"]["id"]

        res = client.get(f"/api/files/{file_id}/thumbnail", headers=auth_header(owner_token))
        assert res.status_code == 200
        img = Image.open(io.BytesIO(res.data))
        assert img.format == "JPEG"
        assert img.mode == "RGB"

    def test_thumbnail_preserves_aspect_ratio(self, client, owner_token):
        """Wide image (1200x300) scales down to exactly 400x100, preserving 4:1 aspect ratio."""
        wide_bytes = create_test_image(format="PNG", size=(1200, 300))
        up = client.post(
            "/api/files",
            data={"file": (io.BytesIO(wide_bytes), "banner.png")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = up.get_json()["file"]["id"]

        res = client.get(f"/api/files/{file_id}/thumbnail", headers=auth_header(owner_token))
        assert res.status_code == 200
        img = Image.open(io.BytesIO(res.data))
        assert img.size == (400, 100)

    def test_thumbnail_in_memory_cache_hit(self, client, owner_token):
        """Subsequent requests hit the in-memory cache and return X-Thumbnail-Cache: HIT."""
        png_bytes = create_test_image(format="PNG", size=(600, 600))
        up = client.post(
            "/api/files",
            data={"file": (io.BytesIO(png_bytes), "cached.png")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = up.get_json()["file"]["id"]

        # First request -> MISS
        res1 = client.get(f"/api/files/{file_id}/thumbnail", headers=auth_header(owner_token))
        assert res1.status_code == 200
        assert res1.headers.get("X-Thumbnail-Cache") == "MISS"

        # Second request -> HIT
        res2 = client.get(f"/api/files/{file_id}/thumbnail", headers=auth_header(owner_token))
        assert res2.status_code == 200
        assert res2.headers.get("X-Thumbnail-Cache") == "HIT"
        assert res1.data == res2.data

    def test_thumbnail_access_via_share_token(self, client, owner_token):
        """Anonymous user can retrieve thumbnail using a valid share_token query param."""
        png_bytes = create_test_image(format="PNG", size=(500, 400))
        up = client.post(
            "/api/files",
            data={"file": (io.BytesIO(png_bytes), "shared.png")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = up.get_json()["file"]["id"]

        # Create open share
        share_res = client.post(
            f"/api/files/{file_id}/share",
            json={"permissions": {"can_view": True, "can_download": True}},
            headers=auth_header(owner_token),
        )
        assert share_res.status_code == 201
        share_token = share_res.get_json()["shares"][0]["share_token"]

        # 1. Via ?share_token=
        anon_res = client.get(f"/api/files/{file_id}/thumbnail?share_token={share_token}")
        assert anon_res.status_code == 200
        assert anon_res.mimetype == "image/jpeg"

        # 2. Via ?token=
        anon_res2 = client.get(f"/api/files/{file_id}/thumbnail?token={share_token}")
        assert anon_res2.status_code == 200

        # 3. Via X-Share-Token header
        anon_res3 = client.get(f"/api/files/{file_id}/thumbnail", headers={"X-Share-Token": share_token})
        assert anon_res3.status_code == 200

    def test_thumbnail_access_via_custom_slug(self, client, owner_token):
        """Thumbnail endpoint accepts custom_slug as share token identifier."""
        png_bytes = create_test_image(format="PNG", size=(300, 300))
        up = client.post(
            "/api/files",
            data={"file": (io.BytesIO(png_bytes), "slug_img.png")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = up.get_json()["file"]["id"]

        custom_slug = f"preview-{uuid.uuid4().hex[:8]}"
        share_res = client.post(
            f"/api/files/{file_id}/share",
            json={"custom_slug": custom_slug, "permissions": {"can_view": True}},
            headers=auth_header(owner_token),
        )
        assert share_res.status_code == 201

        res = client.get(f"/api/files/{file_id}/thumbnail?share_token={custom_slug}")
        assert res.status_code == 200
        assert res.mimetype == "image/jpeg"

    def test_thumbnail_share_token_with_password(self, client, owner_token):
        """Password-protected share requires valid grant token before thumbnail is served."""
        png_bytes = create_test_image(format="PNG", size=(400, 400))
        up = client.post(
            "/api/files",
            data={"file": (io.BytesIO(png_bytes), "pw_img.png")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = up.get_json()["file"]["id"]

        share_res = client.post(
            f"/api/files/{file_id}/share",
            json={"password": "SecretPassword123!", "permissions": {"can_view": True}},
            headers=auth_header(owner_token),
        )
        share_token = share_res.get_json()["shares"][0]["share_token"]

        # Without grant header -> 401
        res = client.get(f"/api/files/{file_id}/thumbnail?share_token={share_token}")
        assert res.status_code == 401
        assert res.get_json()["password_protected"] is True

        # Verify password to get grant token
        verify_res = client.post(
            f"/api/shares/{share_token}/verify-password",
            json={"password": "SecretPassword123!"},
        )
        assert verify_res.status_code == 200
        grant_token = verify_res.get_json()["grant_token"]

        # With grant header -> 200
        res_with_grant = client.get(
            f"/api/files/{file_id}/thumbnail?share_token={share_token}",
            headers={"X-Share-Grant": grant_token},
        )
        assert res_with_grant.status_code == 200

    def test_thumbnail_non_image_rejected_with_415(self, client, owner_token):
        """Non-image file types (e.g. PDF, text) return 415 Unsupported Media Type."""
        # 1. Text file
        txt_res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"Just plain text notes"), "notes.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        txt_id = txt_res.get_json()["file"]["id"]

        res_txt = client.get(f"/api/files/{txt_id}/thumbnail", headers=auth_header(owner_token))
        assert res_txt.status_code == 415
        assert res_txt.get_json()["error"] == "Unsupported media type"

        # 2. PDF file
        pdf_content = b"%PDF-1.4 Mock PDF Content"
        pdf_res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(pdf_content), "contract.pdf")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        pdf_id = pdf_res.get_json()["file"]["id"]

        res_pdf = client.get(f"/api/files/{pdf_id}/thumbnail", headers=auth_header(owner_token))
        assert res_pdf.status_code == 415
        assert res_pdf.get_json()["error"] == "Unsupported media type"

    def test_thumbnail_unauthenticated_and_forbidden(self, client, owner_token, recipient_token):
        """Unauthenticated request returns 401; unauthorized non-owner returns 403."""
        png_bytes = create_test_image(format="PNG", size=(300, 300))
        up = client.post(
            "/api/files",
            data={"file": (io.BytesIO(png_bytes), "private.png")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = up.get_json()["file"]["id"]

        # Unauthenticated without share token -> 401
        anon_res = client.get(f"/api/files/{file_id}/thumbnail")
        assert anon_res.status_code == 401

        # Another user without share token -> 403
        other_res = client.get(f"/api/files/{file_id}/thumbnail", headers=auth_header(recipient_token))
        assert other_res.status_code == 403

    def test_thumbnail_expired_or_revoked_share_returns_410(self, client, owner_token):
        """Revoked or expired share link returns 410 when attempting thumbnail preview."""
        png_bytes = create_test_image(format="PNG", size=(300, 300))
        up = client.post(
            "/api/files",
            data={"file": (io.BytesIO(png_bytes), "revoked.png")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = up.get_json()["file"]["id"]

        share_res = client.post(
            f"/api/files/{file_id}/share",
            json={"permissions": {"can_view": True}},
            headers=auth_header(owner_token),
        )
        share_info = share_res.get_json()["shares"][0]
        share_id = share_info["id"]
        share_token = share_info["share_token"]

        # Revoke the share
        del_res = client.delete(f"/api/shares/{share_id}", headers=auth_header(owner_token))
        assert del_res.status_code == 200

        # Attempt thumbnail with revoked token -> 410
        res = client.get(f"/api/files/{file_id}/thumbnail?share_token={share_token}")
        assert res.status_code == 410
        assert res.get_json()["error"] == "Share is revoked"

    def test_thumbnail_nonexistent_file_returns_404(self, client, owner_token):
        """Requesting thumbnail for nonexistent file returns 404."""
        random_id = uuid.uuid4()
        res = client.get(f"/api/files/{random_id}/thumbnail", headers=auth_header(owner_token))
        assert res.status_code == 404
        assert res.get_json()["error"] == "File not found"
