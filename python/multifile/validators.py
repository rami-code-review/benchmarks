"""Input validation utilities."""

import re
from typing import Optional


def validate_user_id(user_id: str) -> bool:
    """Validate that user_id is a positive integer string.

    Matches template: py-multifile-sqli-safe (validator)
    """
    if not user_id:
        return False

    # Must be numeric only
    if not user_id.isdigit():
        return False

    # Must be positive
    if int(user_id) <= 0:
        return False

    return True


def sanitize_search_query(query: str) -> str:
    """Sanitize search query by removing special characters.

    Matches template: py-multifile-sqli-search-safe (sanitizer)
    """
    if not query:
        return ""

    # Remove SQL special characters
    # This is defense-in-depth; parameterized queries are the primary protection
    sanitized = re.sub(r"[;'\"\\]", "", query)

    # Limit length
    return sanitized[:100]


def validate_email(email: str) -> bool:
    """Validate email format."""
    if not email:
        return False

    # Basic email pattern
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_filename(filename: str) -> bool:
    """Validate filename doesn't contain path traversal.

    Matches template: py-multifile-pathtraversal-safe (validator)
    """
    if not filename:
        return False

    # No path separators
    if '/' in filename or '\\' in filename:
        return False

    # No parent directory references
    if '..' in filename:
        return False

    # Only alphanumeric, dash, underscore, and single dot
    pattern = r'^[a-zA-Z0-9_-]+(\.[a-zA-Z0-9]+)?$'
    return bool(re.match(pattern, filename))


def validate_command_key(key: str, allowed_keys: set) -> bool:
    """Validate command key is in allowlist.

    Matches template: py-multifile-cmdi-safe (validator)
    """
    return key in allowed_keys
