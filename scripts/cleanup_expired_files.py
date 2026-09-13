#!/usr/bin/env python3
"""
scripts/cleanup_expired_files.py

Cleanup job for expired files and trash retention purging.
1. Finds Files where auto_delete_at has passed and permanently deletes them.
2. Finds Files where deleted_at is older than TRASH_RETENTION_DAYS (default: 30)
   and permanently purges them.

Permanently deletes encrypted blob(s) from disk (including FileVersion blobs),
revokes active shares, and removes File database records.

Usage via cron / scheduler:
    0 * * * * cd /opt/secure_file_share && python scripts/cleanup_expired_files.py
"""

import os
import sys
import logging
from datetime import datetime, timedelta, timezone
from flask import current_app

# Ensure project root is on sys.path for direct CLI execution
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import create_app
from app.extensions import db
from app.models.file import File
from app.models.share import Share

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("cleanup_expired_files")


def _purge_file(file: File) -> None:
    """
    Internal helper to revoke active shares, remove encrypted disk blobs
    (base file + all historical versions), and delete the File record from the session.
    """
    # 1. Revoke all active shares before deletion
    active_shares = Share.query.filter_by(file_id=file.id, is_revoked=False).all()
    for s in active_shares:
        s.is_revoked = True
    db.session.flush()

    # 2. Collect and remove all encrypted blobs from disk
    blobs_to_remove = set()
    if file.encrypted_path:
        blobs_to_remove.add(file.encrypted_path)
    for v in file.versions:
        if v.encrypted_path:
            blobs_to_remove.add(v.encrypted_path)

    for path in blobs_to_remove:
        if os.path.exists(path):
            try:
                os.remove(path)
                logger.debug(f"Deleted blob: {path}")
            except OSError as err:
                logger.warning(f"Failed to delete disk blob {path}: {err}")

    # 3. Delete File row (cascades to file_versions, shares, and access_logs)
    db.session.delete(file)


def purge_trash_files(app=None, retention_days: int | None = None) -> int:
    """
    Find and permanently delete soft-deleted files whose deleted_at timestamp
    is older than retention_days (defaulting to TRASH_RETENTION_DAYS from config).
    """
    if app is None:
        app = create_app()

    purged_count = 0
    with app.app_context():
        now = datetime.now(timezone.utc)
        if retention_days is None:
            retention_days = current_app.config.get("TRASH_RETENTION_DAYS", 30)

        cutoff = now - timedelta(days=retention_days)

        candidates = File.query.filter(File.deleted_at.isnot(None)).all()
        to_purge = []
        for f in candidates:
            dt = f.deleted_at
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            if dt <= cutoff:
                to_purge.append(f)

        for file in to_purge:
            file_id_str = str(file.id)
            try:
                _purge_file(file)
                purged_count += 1
                logger.info(f"Purged trash file {file_id_str} (deleted_at: {file.deleted_at})")
            except Exception as err:
                logger.error(f"Error purging trash file {file_id_str}: {err}")
                db.session.rollback()
                raise

        db.session.commit()
        logger.info(f"Trash purge finished. Successfully purged {purged_count} file(s).")

    return purged_count


def cleanup_expired_files(app=None, retention_days: int | None = None) -> int:
    """
    Find and remove files whose auto_delete_at has passed, AND permanently purge
    soft-deleted files whose deleted_at is older than TRASH_RETENTION_DAYS.

    Returns:
        int: Total number of files deleted/purged.
    """
    if app is None:
        app = create_app()

    deleted_count = 0

    with app.app_context():
        now = datetime.now(timezone.utc)

        # 1. Clean up files whose auto_delete_at has passed
        candidates = File.query.filter(File.auto_delete_at.isnot(None)).all()
        expired_files = []
        for f in candidates:
            exp = f.auto_delete_at
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp <= now:
                expired_files.append(f)

        for file in expired_files:
            file_id_str = str(file.id)
            try:
                _purge_file(file)
                deleted_count += 1
                logger.info(f"Cleaned up expired file {file_id_str} (expired at {file.auto_delete_at})")
            except Exception as err:
                logger.error(f"Error while cleaning up file {file_id_str}: {err}")
                db.session.rollback()
                raise

        # 2. Permanently purge soft-deleted files older than TRASH_RETENTION_DAYS
        if retention_days is None:
            retention_days = current_app.config.get("TRASH_RETENTION_DAYS", 30)
        cutoff = now - timedelta(days=retention_days)

        trash_candidates = File.query.filter(File.deleted_at.isnot(None)).all()
        trash_to_purge = []
        for f in trash_candidates:
            dt = f.deleted_at
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            if dt <= cutoff:
                trash_to_purge.append(f)

        for file in trash_to_purge:
            file_id_str = str(file.id)
            try:
                _purge_file(file)
                deleted_count += 1
                logger.info(f"Purged trash file {file_id_str} (deleted_at: {file.deleted_at})")
            except Exception as err:
                logger.error(f"Error purging trash file {file_id_str}: {err}")
                db.session.rollback()
                raise

        db.session.commit()
        logger.info(f"Cleanup finished. Successfully deleted/purged {deleted_count} file(s).")

    return deleted_count


if __name__ == "__main__":
    count = cleanup_expired_files()
    print(f"Cleanup completed: {count} expired/trash file(s) removed.")
