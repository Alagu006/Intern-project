"""
AES-256-GCM file encryption / decryption with Envelope Encryption.

Encrypt path  : encrypt_file(plaintext_bytes) -> (ciphertext, nonce_hex, wrapped_key_hex)
Decrypt       : decrypt_file(encrypted_path, nonce_hex, wrapped_key_hex) -> plaintext_bytes

Envelope Encryption Design:
- Data Encryption Key (DEK): A 256-bit (32-byte) random AES key generated per file.
- Key Encryption Key (KEK): A 256-bit server-side master key loaded from the MASTER_KEK
  environment variable (base64-encoded).
- DEK Wrapping: The DEK is encrypted with AES-256-GCM using the KEK before being stored
  in the database (wrapped_key_hex column: 12-byte KEK nonce + 32-byte DEK ciphertext + 16-byte tag = 60 bytes / 120 hex chars).
- DEK Unwrapping: The wrapped DEK is decrypted in-memory using the KEK on download.

NOTE: This server-side static KEK envelope encryption is a stopgap measure against
offline database compromises (e.g. database dumps, backup leaks, SQL injection).
Production systems should ultimately use a dedicated Key Management Service (KMS)
such as AWS KMS, Google Cloud KMS, or HashiCorp Vault for HSM backing, fine-grained
access policies, and automated key rotation.
"""

import os
import base64
import binascii
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import has_app_context, current_app


def get_master_kek() -> bytes:
    """
    Retrieve and validate the Master Key Encryption Key (KEK).

    Loads from Flask current_app.config['MASTER_KEK'] when in an application context,
    or falls back to the MASTER_KEK environment variable.
    The key must be 32 bytes (256 bits), Base64-encoded.
    """
    raw_kek = None
    if has_app_context():
        raw_kek = current_app.config.get("MASTER_KEK")

    if not raw_kek:
        raw_kek = os.environ.get("MASTER_KEK")

    if not raw_kek and "PYTEST_CURRENT_TEST" in os.environ:
        from app.config import TestingConfig
        raw_kek = TestingConfig.MASTER_KEK

    if not raw_kek:
        raise RuntimeError(
            "MASTER_KEK is not configured. Please set the MASTER_KEK environment variable "
            "with a 32-byte Base64-encoded key."
        )

    try:
        kek_bytes = base64.b64decode(raw_kek)
    except Exception as exc:
        raise ValueError(f"MASTER_KEK is not valid Base64: {exc}") from exc

    if len(kek_bytes) != 32:
        raise ValueError(
            f"MASTER_KEK must be exactly 32 bytes (256 bits), got {len(kek_bytes)} bytes."
        )

    return kek_bytes


def generate_file_key() -> bytes:
    """Generate a 256-bit (32-byte) random AES Data Encryption Key (DEK)."""
    return os.urandom(32)


def wrap_key(dek: bytes, kek: bytes | None = None) -> str:
    """
    Wrap a per-file DEK using AES-256-GCM under the KEK.

    Parameters
    ----------
    dek : bytes
        The 32-byte plaintext Data Encryption Key to wrap.
    kek : bytes, optional
        The 32-byte Key Encryption Key. If omitted, fetched via get_master_kek().

    Returns
    -------
    wrapped_key_hex : str
        Hex string of (12-byte KEK nonce + 48-byte ciphertext and tag) = 120 hex chars.
    """
    if kek is None:
        kek = get_master_kek()

    if len(dek) != 32:
        raise ValueError(f"DEK must be exactly 32 bytes, got {len(dek)} bytes.")

    kek_nonce = os.urandom(12)
    aesgcm = AESGCM(kek)
    wrapped_dek = aesgcm.encrypt(kek_nonce, dek, None)
    return (kek_nonce + wrapped_dek).hex()


def unwrap_key(wrapped_key_hex: str, kek: bytes | None = None) -> bytes:
    """
    Unwrap a per-file DEK using AES-256-GCM under the KEK.

    Parameters
    ----------
    wrapped_key_hex : str
        The wrapped key hex string stored in the database.
    kek : bytes, optional
        The 32-byte Key Encryption Key. If omitted, fetched via get_master_kek().

    Returns
    -------
    dek : bytes
        The decrypted 32-byte Data Encryption Key.
    """
    raw = binascii.unhexlify(wrapped_key_hex)

    # Backwards-compatibility fallback: if raw bytes are 32 bytes (64 hex chars),
    # this is an un-wrapped legacy DEK.
    if len(raw) == 32:
        return raw

    if len(raw) < 28:
        raise ValueError("Invalid wrapped key: payload too short.")

    if kek is None:
        kek = get_master_kek()

    kek_nonce = raw[:12]
    wrapped_dek = raw[12:]

    aesgcm = AESGCM(kek)
    return aesgcm.decrypt(kek_nonce, wrapped_dek, None)


def encrypt_file(
    plaintext: bytes,
    key: bytes | None = None,
    kek: bytes | None = None,
) -> tuple[bytes, str, str]:
    """
    Encrypt *plaintext* with AES-256-GCM using a per-file DEK, then wrap the DEK
    with the server-side KEK.

    Returns
    -------
    ciphertext      : bytes — encrypted blob (nonce NOT prepended; stored separately)
    nonce_hex       : str   — 24-char hex string of the 12-byte file nonce
    wrapped_key_hex : str   — 120-char hex string of the wrapped DEK
    """
    if key is None:
        key = generate_file_key()

    file_nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(file_nonce, plaintext, None)

    wrapped_key_hex = wrap_key(key, kek=kek)
    return ciphertext, file_nonce.hex(), wrapped_key_hex


def decrypt_file(
    encrypted_path: str,
    nonce_hex: str,
    wrapped_key_hex: str,
    kek: bytes | None = None,
) -> bytes:
    """
    Unwrap the per-file DEK and decrypt the blob from *encrypted_path* in-memory.

    The decrypted bytes and plaintext DEK are NEVER written to disk.
    """
    key = unwrap_key(wrapped_key_hex, kek=kek)
    nonce = binascii.unhexlify(nonce_hex)

    with open(encrypted_path, "rb") as fh:
        ciphertext = fh.read()

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def decrypt_file_bytes(
    ciphertext: bytes,
    nonce_hex: str,
    wrapped_key_hex: str,
    kek: bytes | None = None,
) -> bytes:
    """Same as decrypt_file but accepts raw ciphertext bytes instead of a path."""
    key = unwrap_key(wrapped_key_hex, kek=kek)
    nonce = binascii.unhexlify(nonce_hex)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)
