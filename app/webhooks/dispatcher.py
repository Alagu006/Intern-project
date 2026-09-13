import hashlib
import hmac
import json
import logging
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import requests
from app.models.webhook import Webhook
from app.webhooks.security import validate_webhook_url

logger = logging.getLogger(__name__)

EVENT_SHARE_DOWNLOADED = "share.downloaded"
EVENT_SHARE_REVOKED = "share.revoked"

SUPPORTED_EVENTS = {
    EVENT_SHARE_DOWNLOADED,
    EVENT_SHARE_REVOKED,
}

# Thread tracking for deterministic test execution
_active_threads_lock = threading.Lock()
_active_threads: List[threading.Thread] = []


def compute_webhook_signature(secret: str, payload_bytes: bytes) -> str:
    """
    Compute HMAC-SHA256 hex digest of the raw payload bytes using the secret.
    """
    if isinstance(secret, str):
        secret_bytes = secret.encode("utf-8")
    else:
        secret_bytes = secret
    return hmac.new(secret_bytes, payload_bytes, hashlib.sha256).hexdigest()


def _send_webhook(
    url: str,
    secret: str,
    payload_bytes: bytes,
    event_type: str,
    timeout: float = 5.0,
) -> bool:
    """
    Perform synchronous outbound HTTP POST with HMAC signature.
    Wrapped in try-except for non-blocking / best-effort resilience.
    Re-validates resolved IP right before request to mitigate DNS-rebinding.
    Sets allow_redirects=False to prevent open-redirect SSRF bypasses.
    """
    # 1. Re-validate URL and resolved IP right before dispatch (DNS-rebinding mitigation)
    is_safe, err_msg = validate_webhook_url(url)
    if not is_safe:
        logger.warning(
            "Webhook dispatch blocked by SSRF/DNS-rebinding protection for %s [event=%s]: %s",
            url,
            event_type,
            err_msg,
        )
        return False

    signature = compute_webhook_signature(secret, payload_bytes)
    headers = {
        "Content-Type": "application/json",
        "X-Signature": signature,
        "X-Hub-Signature-256": f"sha256={signature}",
        "X-Event-Type": event_type,
        "User-Agent": "SecureFileShare-Webhooks/1.0",
    }
    try:
        response = requests.post(
            url,
            data=payload_bytes,
            headers=headers,
            timeout=timeout,
            allow_redirects=False,
        )
        logger.info(
            "Webhook delivered to %s [event=%s, status=%s]",
            url,
            event_type,
            response.status_code,
        )
        return response.status_code < 400
    except Exception as exc:
        logger.warning(
            "Webhook delivery failed for %s [event=%s]: %s",
            url,
            event_type,
            exc,
        )
        return False


def wait_for_active_webhooks(timeout: float = 2.0) -> None:
    """
    Wait for all in-flight background webhook threads to complete.
    Primarily used in test suites to ensure deterministic assertions without arbitrary sleeps.
    """
    with _active_threads_lock:
        threads = list(_active_threads)
        _active_threads.clear()

    for t in threads:
        if t.is_alive():
            t.join(timeout=timeout)


def dispatch_webhook_event(
    user_id: Any,
    event_type: str,
    data: Dict[str, Any],
    sync: bool = False,
) -> int:
    """
    Find all active webhooks for `user_id` subscribing to `event_type`,
    serialize the payload, compute HMAC signatures, and dispatch via background daemon threads.

    Returns the number of matching webhooks to which dispatch was initiated.
    """
    try:
        webhooks = Webhook.query.filter_by(user_id=user_id, is_active=True).all()
    except Exception as exc:
        logger.error("Failed to query webhooks for user %s: %s", user_id, exc)
        return 0

    matching = []
    for wh in webhooks:
        events = wh.event_types or []
        if event_type in events or "*" in events:
            matching.append((wh.url, wh.secret))

    if not matching:
        return 0

    payload = {
        "event": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": data,
    }
    # Deterministic JSON serialization
    payload_bytes = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")

    dispatched = 0
    for url, secret in matching:
        if sync:
            _send_webhook(url, secret, payload_bytes, event_type)
        else:
            t = threading.Thread(
                target=_send_webhook,
                args=(url, secret, payload_bytes, event_type),
                daemon=True,
                name=f"WebhookSender-{event_type}",
            )
            with _active_threads_lock:
                _active_threads.append(t)
            t.start()
        dispatched += 1

    return dispatched
