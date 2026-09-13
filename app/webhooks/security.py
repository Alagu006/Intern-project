"""
app/webhooks/security.py

SSRF (Server-Side Request Forgery) and DNS-rebinding protection utilities
for outbound webhook deliveries.

Validates that webhook URLs:
1. Use HTTP or HTTPS schemes only.
2. Do not point to blocked internal infrastructure ports (e.g. 22, 3306, 5432, 6379, 3310).
3. Do not point directly to, or resolve via DNS to, private (RFC 1918),
   loopback (127.0.0.0/8, ::1), link-local (169.254.0.0/16, fe80::/10),
   multicast, reserved, unspecified (0.0.0.0, ::), or non-globally-routable IP addresses.
"""

import ipaddress
import socket
import urllib.parse
from typing import Tuple, Set

# Commonly internal service and database ports that should never receive webhooks
BLOCKED_PORTS: Set[int] = {
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    69,    # TFTP
    110,   # POP3
    111,   # RPC
    135,   # RPC
    137,   # NetBIOS
    138,   # NetBIOS
    139,   # NetBIOS
    143,   # IMAP
    389,   # LDAP
    445,   # SMB
    636,   # LDAPS
    1433,  # MSSQL
    1521,  # Oracle
    2049,  # NFS
    2375,  # Docker unencrypted
    2376,  # Docker TLS
    3306,  # MySQL
    3310,  # ClamAV daemon
    3389,  # RDP
    5432,  # PostgreSQL
    6379,  # Redis
    11211, # Memcached
    27017, # MongoDB
}


def is_safe_ip(ip_str: str) -> bool:
    """
    Verify whether an IP address is publicly routable and safe from SSRF.

    Returns False for:
      - Private IPs (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, RFC 4193: fc00::/7)
      - Loopback IPs (127.0.0.0/8, ::1)
      - Link-local IPs (169.254.0.0/16, fe80::/10 - AWS/GCP/Azure instance metadata service 169.254.169.254)
      - Multicast IPs (224.0.0.0/4, ff00::/8)
      - Reserved or unspecified IPs (0.0.0.0, ::)
      - Any non-global IP address
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    if (
        not ip.is_global
        or ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return False

    return True


def resolve_and_validate_hostname(hostname: str) -> Tuple[bool, str]:
    """
    Resolve a hostname via DNS and ensure all resolved IP addresses are safe.
    Handles direct IPv4/IPv6 literals and standard hostnames.
    """
    if not hostname:
        return False, "Missing hostname"

    clean_host = hostname.strip("[]")

    # Check if the hostname is directly an IP address literal
    try:
        ip = ipaddress.ip_address(clean_host)
        if not is_safe_ip(str(ip)):
            return False, f"URL points to forbidden IP address: {ip}"
        return True, ""
    except ValueError:
        pass

    # Resolve hostname to all associated IP addresses
    try:
        addr_info = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, socket.herror) as exc:
        return False, f"Could not resolve hostname '{hostname}'"
    except Exception as exc:
        return False, f"DNS resolution failed for '{hostname}': {exc}"

    if not addr_info:
        return False, f"No IP addresses resolved for hostname '{hostname}'"

    resolved_ips = {item[4][0] for item in addr_info}
    for ip_str in resolved_ips:
        if not is_safe_ip(ip_str):
            return False, f"Hostname '{hostname}' resolves to forbidden IP address: {ip_str}"

    return True, ""


def validate_webhook_url(url: str) -> Tuple[bool, str]:
    """
    Validate a webhook URL for scheme, port, and SSRF restrictions.

    Returns:
        tuple[bool, str]: (is_valid, error_message)
    """
    if not isinstance(url, str) or not url.strip():
        return False, "URL must be a non-empty string"

    try:
        parsed = urllib.parse.urlsplit(url.strip())
    except Exception as exc:
        return False, f"Malformed URL: {exc}"

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        return False, f"Invalid URL scheme '{parsed.scheme}'. Only HTTP and HTTPS are allowed"

    if not parsed.netloc:
        return False, "URL is missing network location (host)"

    hostname = parsed.hostname
    if not hostname:
        return False, "URL is missing hostname"

    if parsed.port and parsed.port in BLOCKED_PORTS:
        return False, f"Port {parsed.port} is blocked for security reasons"

    # Validate the hostname / IP
    is_safe, reason = resolve_and_validate_hostname(hostname)
    if not is_safe:
        return False, reason

    return True, ""
