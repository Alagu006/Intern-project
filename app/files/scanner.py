"""
ClamAV malware scanning integration for file uploads.

Scans plaintext bytes using a remote or local clamd daemon via clamd.ClamdNetworkSocket.
Fails gracefully when disabled or when the daemon is unavailable.
"""

import io
import socket
import clamd
from flask import current_app


def scan_file_for_malware(plaintext: bytes, client=None) -> tuple[bool, str | None]:
    """
    Scan plaintext bytes for viruses/malware using ClamAV daemon.

    Returns:
        tuple[bool, str | None]: (is_clean, virus_name_or_none)
        - (True, None) if clean or scanning is disabled/unavailable.
        - (False, virus_name) if infected with malware.
    """
    if not current_app.config.get("SCAN_UPLOADS", False):
        return True, None

    host = current_app.config.get("CLAMD_HOST", "127.0.0.1")
    port = int(current_app.config.get("CLAMD_PORT", 3310))
    timeout = float(current_app.config.get("CLAMD_TIMEOUT", 10.0))

    try:
        scanner = client or clamd.ClamdNetworkSocket(host=host, port=port, timeout=timeout)
        result = scanner.instream(io.BytesIO(plaintext))

        if result:
            for _stream_key, res_tuple in result.items():
                if isinstance(res_tuple, (tuple, list)) and len(res_tuple) >= 1:
                    status = res_tuple[0]
                    virus_name = res_tuple[1] if len(res_tuple) > 1 else None
                    if status == "FOUND":
                        return False, virus_name or "Malware detected"

        return True, None

    except (clamd.ClamdError, clamd.ConnectionError, socket.error, OSError, Exception) as exc:
        # Fail gracefully when ClamAV daemon is unreachable or fails
        current_app.logger.warning("ClamAV malware scan failed or daemon unreachable: %s", exc)
        return True, None
