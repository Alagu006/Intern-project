import io
import pytest
from app import create_app
from app.extensions import db as _db
from app.models import User, File
from app.crypto.file_crypto import encrypt_file
from app.auth.decorators import generate_access_token


@pytest.fixture(scope="function")
def app():
    app = create_app("testing")
    with app.app_context():
        import os
        upload_dir = app.config.get("UPLOAD_FOLDER")
        if upload_dir:
            os.makedirs(upload_dir, exist_ok=True)
        staging_dir = app.config.get("UPLOAD_STAGING_DIR")
        if staging_dir:
            os.makedirs(staging_dir, exist_ok=True)
        _db.create_all()
        yield app
        _db.session.remove()
        _db.drop_all()


@pytest.fixture(scope="function")
def client(app):
    return app.test_client()


@pytest.fixture(scope="function")
def db(app):
    return _db


# ------------------------------------------------------------------
# Reusable user + file factories
# ------------------------------------------------------------------

def make_user(db_session, username, email, password="Test1234!"):
    u = User(username=username, email=email)
    u.set_password(password)
    db_session.add(u)
    db_session.commit()
    return u


def make_file(app_ctx, db_session, owner):
    plaintext = b"Hello, secure world!"
    ciphertext, nonce_hex, wrapped_key_hex = encrypt_file(plaintext)

    import uuid, os, tempfile
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".enc")
    tmp.write(ciphertext)
    tmp.close()

    f = File(
        owner_id=owner.id,
        filename="test.txt",
        mime_type="text/plain",
        size_bytes=len(plaintext),
        encrypted_path=tmp.name,
        nonce_hex=nonce_hex,
        wrapped_key_hex=wrapped_key_hex,
    )
    db_session.add(f)
    db_session.commit()
    return f


@pytest.fixture(scope="function")
def owner(app, db):
    with app.app_context():
        user = make_user(db.session, "owner_user", "owner@test.com")
        db.session.refresh(user)
        return user


@pytest.fixture(scope="function")
def recipient(app, db):
    with app.app_context():
        user = make_user(db.session, "recipient_user", "recipient@test.com")
        db.session.refresh(user)
        return user


@pytest.fixture(scope="function")
def shared_file(app, db, owner):
    with app.app_context():
        file = make_file(app, db.session, owner)
        db.session.refresh(file)
        return file


@pytest.fixture(scope="function")
def owner_token(app, db, owner):
    with app.app_context():
        db.session.add(owner)
        return generate_access_token(owner)


@pytest.fixture(scope="function")
def recipient_token(app, db, recipient):
    with app.app_context():
        db.session.add(recipient)
        return generate_access_token(recipient)
