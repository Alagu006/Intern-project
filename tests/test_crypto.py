"""
Unit and integration tests for Envelope Encryption (DEK/KEK) in app/crypto/file_crypto.py.
"""

import os
import io
import base64
import pytest
from cryptography.exceptions import InvalidTag
from app import create_app
from app.config import Config
from app.crypto.file_crypto import (
    generate_file_key,
    wrap_key,
    unwrap_key,
    encrypt_file,
    decrypt_file,
    decrypt_file_bytes,
    get_master_kek,
)
from app.models import File


class TestEnvelopeEncryption:
    def test_wrap_and_unwrap_key_roundtrip(self):
        """DEK wrapped with a 32-byte KEK can be accurately unwrapped."""
        dek = generate_file_key()
        kek = os.urandom(32)

        wrapped_hex = wrap_key(dek, kek=kek)
        # 12 bytes nonce + 32 bytes ciphertext + 16 bytes tag = 60 bytes = 120 hex chars
        assert len(wrapped_hex) == 120
        assert wrapped_hex != dek.hex()

        unwrapped = unwrap_key(wrapped_hex, kek=kek)
        assert unwrapped == dek

    def test_unwrap_with_wrong_kek_fails(self):
        """Unwrapping with an incorrect KEK must fail authentication with InvalidTag."""
        dek = generate_file_key()
        kek1 = os.urandom(32)
        kek2 = os.urandom(32)

        wrapped_hex = wrap_key(dek, kek=kek1)
        with pytest.raises(InvalidTag):
            unwrap_key(wrapped_hex, kek=kek2)

    def test_tampered_wrapped_key_fails(self):
        """Tampering with the wrapped key ciphertext or tag must raise InvalidTag."""
        dek = generate_file_key()
        kek = os.urandom(32)

        wrapped_hex = wrap_key(dek, kek=kek)
        # Corrupt the last character
        tampered_hex = wrapped_hex[:-2] + ("00" if wrapped_hex[-2:] != "00" else "ff")

        with pytest.raises(InvalidTag):
            unwrap_key(tampered_hex, kek=kek)

    def test_invalid_kek_raises_error(self, monkeypatch):
        """Non-32-byte or malformed Base64 KEK must raise ValueError."""
        # Non-32-byte key (e.g. 16 bytes)
        short_key_b64 = base64.b64encode(b"short-key-16byte").decode()
        monkeypatch.setenv("MASTER_KEK", short_key_b64)
        with pytest.raises(ValueError, match="32 bytes"):
            get_master_kek()

        # Malformed Base64
        monkeypatch.setenv("MASTER_KEK", "not-valid-base64!@#$")
        with pytest.raises(ValueError, match="Base64"):
            get_master_kek()

    def test_legacy_unwrapped_key_compatibility(self):
        """A legacy raw 32-byte DEK (64 hex characters) is returned as-is for backward compatibility."""
        raw_dek = os.urandom(32)
        legacy_hex = raw_dek.hex()
        assert len(legacy_hex) == 64

        recovered = unwrap_key(legacy_hex)
        assert recovered == raw_dek

    def test_encrypt_and_decrypt_file_envelope(self, tmp_path):
        """End-to-end file encryption and decryption using envelope encryption."""
        plaintext = b"Highly confidential financial document payload"
        ciphertext, nonce_hex, wrapped_key_hex = encrypt_file(plaintext)

        assert ciphertext != plaintext
        assert len(nonce_hex) == 24
        assert len(wrapped_key_hex) == 120

        # Test decrypt_file_bytes
        decrypted_bytes = decrypt_file_bytes(ciphertext, nonce_hex, wrapped_key_hex)
        assert decrypted_bytes == plaintext

        # Test decrypt_file from disk
        file_path = tmp_path / "test.enc"
        file_path.write_bytes(ciphertext)

        decrypted_disk = decrypt_file(str(file_path), nonce_hex, wrapped_key_hex)
        assert decrypted_disk == plaintext

    def test_decrypt_file_fails_on_tampered_ciphertext(self, tmp_path):
        """Decryption must fail and raise InvalidTag if the ciphertext on disk or in memory is tampered."""
        plaintext = b"Tamper detection verification payload"
        ciphertext, nonce_hex, wrapped_key_hex = encrypt_file(plaintext)

        # Tamper with the ciphertext byte sequence (flip bits in the last byte)
        tampered_byte = bytes([ciphertext[-1] ^ 0x01])
        tampered_ciphertext = ciphertext[:-1] + tampered_byte

        # In-memory decryption fails
        with pytest.raises(InvalidTag):
            decrypt_file_bytes(tampered_ciphertext, nonce_hex, wrapped_key_hex)

        # File-based decryption fails
        tampered_file = tmp_path / "tampered.enc"
        tampered_file.write_bytes(tampered_ciphertext)
        with pytest.raises(InvalidTag):
            decrypt_file(str(tampered_file), nonce_hex, wrapped_key_hex)

    def test_decrypt_file_fails_on_wrong_key(self, tmp_path):
        """Decryption must fail and raise InvalidTag if attempted with the wrong wrapped key."""
        plaintext = b"Secret data protected by key A"
        ciphertext, nonce_hex, wrapped_key_hex_a = encrypt_file(plaintext)

        # Generate a second independent encryption key
        _, _, wrapped_key_hex_b = encrypt_file(b"Another file payload")
        assert wrapped_key_hex_a != wrapped_key_hex_b

        # Attempt in-memory decryption of ciphertext A using key B
        with pytest.raises(InvalidTag):
            decrypt_file_bytes(ciphertext, nonce_hex, wrapped_key_hex_b)

        # Attempt file-based decryption using key B
        file_path = tmp_path / "original.enc"
        file_path.write_bytes(ciphertext)
        with pytest.raises(InvalidTag):
            decrypt_file(str(file_path), nonce_hex, wrapped_key_hex_b)


class TestEnvelopeEncryptionIntegration:
    def test_upload_and_download_flow_uses_envelope_encryption(
        self, app, client, owner_token, db
    ):
        """
        Uploading a file via /api/files must store a wrapped DEK (120 hex chars)
        in wrapped_key_hex, and downloading the share must successfully unwrap and
        decrypt in-memory.
        """
        file_content = b"Envelope encrypted file content for sharing"
        upload_res = client.post(
            "/api/files",
            data={"file": (io.BytesIO(file_content), "envelope_test.txt")},
            headers={"Authorization": f"Bearer {owner_token}"},
            content_type="multipart/form-data",
        )
        assert upload_res.status_code == 201
        file_id = upload_res.get_json()["file"]["id"]

        # Verify database record
        with app.app_context():
            import uuid
            file_record = db.session.get(File, uuid.UUID(file_id))
            assert file_record is not None
            # Must be wrapped DEK (120 hex chars), NOT raw 64-char key
            assert len(file_record.wrapped_key_hex) == 120
            # Backward-compatibility alias
            assert file_record.encrypted_key_hex == file_record.wrapped_key_hex

        # Create share
        share_res = client.post(
            f"/api/files/{file_id}/share",
            json={"permissions": {"can_view": True, "can_download": True}},
            headers={"Authorization": f"Bearer {owner_token}"},
        )
        assert share_res.status_code == 201
        token = share_res.get_json()["shares"][0]["share_token"]

        # Download share
        dl_res = client.get(f"/api/shares/{token}/download")
        assert dl_res.status_code == 200
        assert dl_res.data == file_content


class TestMasterKekStartupCheck:
    def test_startup_check_raises_with_default_master_kek(self):
        """create_app in non-testing mode raises RuntimeError if MASTER_KEK is placeholder."""
        class InsecureKekConfig(Config):
            TESTING = False
            SECRET_KEY = "secure-random-secret-key-1234567890"
            JWT_SECRET_KEY = "secure-random-jwt-secret-key-12345678"
            MASTER_KEK = "change-me-in-production-master-kek"

        with pytest.raises(RuntimeError, match="MASTER_KEK"):
            create_app(InsecureKekConfig)

    def test_startup_check_raises_when_master_kek_invalid_length(self):
        """create_app in non-testing mode raises RuntimeError if MASTER_KEK is not 32 bytes."""
        class InvalidKekConfig(Config):
            TESTING = False
            SECRET_KEY = "secure-random-secret-key-1234567890"
            JWT_SECRET_KEY = "secure-random-jwt-secret-key-12345678"
            MASTER_KEK = base64.b64encode(b"too-short-16byte").decode()

        with pytest.raises(RuntimeError, match="MASTER_KEK"):
            create_app(InvalidKekConfig)

    def test_startup_check_passes_with_valid_master_kek(self):
        """create_app in non-testing mode succeeds when all keys including MASTER_KEK are valid."""
        class SecureConfig(Config):
            TESTING = False
            SECRET_KEY = "secure-random-secret-key-1234567890"
            JWT_SECRET_KEY = "secure-random-jwt-secret-key-12345678"
            MASTER_KEK = base64.b64encode(os.urandom(32)).decode()

        app = create_app(SecureConfig)
        assert app is not None
