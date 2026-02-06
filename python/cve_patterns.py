"""CVE-derived vulnerability patterns for benchmark testing.

These patterns are inspired by real CVEs to test detection of
production-grade security issues.
"""

import tarfile
from typing import Any
from lxml import etree


# =============================================================================
# CVE-2024-3094 (XZ Utils) - Unsafe archive extraction
# =============================================================================

def extract_archive_safe(archive_path: str, dest_dir: str) -> None:
    """Extract archive with path validation.

    Matches template: py-cve-unsafe-decompress
    """
    # Safe: validate archive contents before extraction
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            if member.name.startswith('/') or '..' in member.name:
                raise ValueError("Unsafe path in archive")
        tar.extractall(path=dest_dir)


# =============================================================================
# CVE-2024-22855 (Jackson-databind style) - Unsafe YAML deserialization
# =============================================================================

def load_yaml_safe(user_provided_yaml: str) -> Any:
    """Load YAML safely.

    Matches template: py-cve-unsafe-deserial-yaml
    """
    import yaml
    # Safe: use safe_load for untrusted YAML
    config = yaml.safe_load(user_provided_yaml)
    return config


# =============================================================================
# CVE-style XXE - XML External Entity injection
# =============================================================================

def parse_xml_safe(user_xml: str) -> Any:
    """Parse XML with external entities disabled.

    Matches template: py-cve-xxe
    """
    # Safe: disable external entities in XML parser
    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    doc = etree.fromstring(user_xml.encode(), parser=parser)
    return doc


# =============================================================================
# Additional CVE-inspired patterns
# =============================================================================

def validate_redirect_url(url: str) -> bool:
    """Validate redirect URL is internal."""
    if not url:
        return False
    # Only allow relative paths, not protocol-relative
    return url.startswith('/') and not url.startswith('//')


def handle_redirect_safe(request_url: str) -> str:
    """Handle redirect with URL validation.

    Inspired by various open redirect CVEs.
    """
    next_url = request_url  # Would come from request.args.get('next')
    if not validate_redirect_url(next_url):
        return "/home"
    return next_url


def get_order_safe(order_id: str, current_user_id: str, db) -> dict:
    """Get order with ownership verification.

    Inspired by IDOR CVEs.
    """
    order = db.get_order(order_id)
    if order is None:
        raise ValueError("Order not found")
    # Safe: verify ownership
    if order.get('user_id') != current_user_id:
        raise PermissionError("Access denied")
    return order


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison to prevent timing attacks.

    Inspired by timing attack CVEs.
    """
    import hmac
    return hmac.compare_digest(a, b)


def validate_token_safe(provided: str, expected: str) -> bool:
    """Validate token using constant-time comparison.

    Prevents timing attacks on token validation.
    """
    return constant_time_compare(provided.encode(), expected.encode())


class SecureFileReader:
    """Secure file reader with path traversal protection."""

    def __init__(self, base_dir: str):
        self.base_dir = base_dir

    def read_file_safe(self, user_path: str) -> bytes:
        """Read file with path validation.

        Inspired by path traversal CVEs.
        """
        import os

        # Normalize and validate path
        clean_path = os.path.normpath(user_path)
        full_path = os.path.join(self.base_dir, clean_path)

        # Verify resolved path is within base directory
        real_base = os.path.realpath(self.base_dir)
        real_path = os.path.realpath(full_path)

        if not real_path.startswith(real_base):
            raise ValueError("Path traversal attempt detected")

        with open(full_path, 'rb') as f:
            return f.read()


def is_allowed_url(url: str) -> bool:
    """Check if URL is in allowlist."""
    from urllib.parse import urlparse
    allowed_hosts = {'api.example.com', 'cdn.example.com'}
    try:
        parsed = urlparse(url)
        return parsed.netloc in allowed_hosts
    except Exception:
        return False


def fetch_url_safe(target_url: str) -> bytes:
    """Fetch URL with host validation.

    Inspired by SSRF CVEs.
    """
    import requests

    if not is_allowed_url(target_url):
        raise ValueError("URL not allowed")

    response = requests.get(target_url, timeout=10)
    return response.content
