"""
On-demand image thumbnail generation and in-memory caching.

Decrypted plaintext and generated thumbnails are strictly stored in-memory,
preventing plaintext leakage onto disk.
"""

import io
import os
import time
import mimetypes
import threading
from collections import OrderedDict
from PIL import Image

# Register webp in standard mimetypes table in case OS lacks it
mimetypes.add_type("image/webp", ".webp")

# Supported raster image MIME types
ALLOWED_IMAGE_MIMETYPES = {
    "image/png",
    "image/jpeg",
    "image/jpg",
    "image/webp",
}

ALLOWED_IMAGE_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
}


def is_supported_image(mime_type: str | None, filename: str = "") -> bool:
    """Return True if MIME type or file extension corresponds to a supported raster image."""
    if mime_type and mime_type.lower() in ALLOWED_IMAGE_MIMETYPES:
        return True
    if filename:
        ext = os.path.splitext(filename)[1].lower()
        if ext in ALLOWED_IMAGE_EXTENSIONS:
            return True
    return False


# NOTE / FOLLOW-UP:
# Currently only raster image formats (image/png, image/jpeg, image/webp) are supported.
# First-page preview rendering for PDFs (e.g. using pypdfium2 / pdf2image with poppler)
# and office documents (e.g. DOCX / PPTX preview extractors) is planned as a follow-up
# enhancement.


class InMemoryThumbnailCache:
    """
    A lightweight, thread-safe, in-process LRU cache with TTL expiration.
    Decrypted plaintext and thumbnail bytes are NEVER persisted to disk, avoiding
    storing unencrypted assets alongside ciphertext.
    """

    def __init__(self, max_size: int = 128, ttl_seconds: float = 300.0):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._cache: OrderedDict[str, tuple[float, bytes]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str) -> bytes | None:
        with self._lock:
            if key not in self._cache:
                return None
            created_at, data = self._cache[key]
            if time.monotonic() - created_at > self.ttl_seconds:
                # Expired
                del self._cache[key]
                return None
            # Move to end (most recently used)
            self._cache.move_to_end(key)
            return data

    def set(self, key: str, data: bytes) -> None:
        with self._lock:
            now = time.monotonic()
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = (now, data)
            # Evict LRU if exceeds max_size
            while len(self._cache) > self.max_size:
                self._cache.popitem(last=False)

    def invalidate(self, key: str) -> None:
        with self._lock:
            self._cache.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()


# Global in-process cache instance
thumbnail_cache = InMemoryThumbnailCache(max_size=128, ttl_seconds=300.0)


def generate_thumbnail_bytes(plaintext: bytes, max_size: tuple[int, int] = (400, 400)) -> bytes:
    """
    Generate a resized JPEG thumbnail (up to max_size, preserving aspect ratio).
    Properly handles transparency in PNG/WebP images by compositing over a white background.
    """
    with Image.open(io.BytesIO(plaintext)) as img:
        # Normalize color mode for JPEG conversion (JPEG cannot store alpha channel)
        if img.mode in ("RGBA", "LA") or (img.mode == "P" and "transparency" in img.info):
            img = img.convert("RGBA")
            background = Image.new("RGB", img.size, (255, 255, 255))
            background.paste(img, mask=img.split()[3])
            img = background
        elif img.mode != "RGB":
            img = img.convert("RGB")

        # Resize preserving aspect ratio (max 400x400)
        img.thumbnail(max_size, Image.Resampling.LANCZOS)

        out = io.BytesIO()
        img.save(out, format="JPEG", quality=85, optimize=True)
        return out.getvalue()
