"""Database operations for benchmark testing."""

import hashlib
import logging
import os
import shlex
import subprocess
from typing import Optional

logger = logging.getLogger(__name__)


class User:
    """Represents a user in the system."""

    def __init__(self, id: int, name: str, email: str):
        self.id = id
        self.name = name
        self.email = email


class Database:
    """Database wrapper with parameterized queries."""

    def __init__(self, connection):
        self.conn = connection
        self.cursor = connection.cursor()

    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID using parameterized query.
        Matches template: py-sqli-fstring-easy
        """
        self.cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        row = self.cursor.fetchone()
        if row:
            return User(row[0], row[1], row[2])
        return None

    def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email using parameterized query.
        Matches template: py-sqli-format-easy
        """
        self.cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        row = self.cursor.fetchone()
        if row:
            return User(row[0], row[1], row[2])
        return None

    def get_orders_by_customer(self, cid: int) -> list:
        """Get orders by customer ID using parameterized query.
        Matches template: py-sqli-percent-easy
        """
        self.cursor.execute("SELECT * FROM orders WHERE customer_id = %s", (cid,))
        return self.cursor.fetchall()

    def close(self):
        """Close database connection."""
        self.cursor.close()
        self.conn.close()


def load_auth_token() -> str:
    """Load auth token from environment.
    Matches template: py-secret-token-easy
    """
    token = os.environ.get("AUTH_TOKEN")
    return token or ""


def hash_password(password: str) -> str:
    """Hash password using SHA-256.
    Matches template: py-crypto-md5-easy
    """
    hash_val = hashlib.sha256(password.encode()).hexdigest()
    return hash_val


def run_safe_command(safe_path: str) -> None:
    """Run command safely without shell=True.
    Matches template: py-cmdi-shell-easy
    """
    subprocess.run(["ls", "-la", safe_path], check=True)


def remove_file_safely(filename: str) -> None:
    """Remove file safely without os.system.
    Matches template: py-cmdi-ossystem-easy
    """
    subprocess.run(["rm", "-f", shlex.quote(filename)])


def get_safe_path(base_dir: str, user_input: str) -> str:
    """Get safe file path with validation.
    Matches template: py-pathtraversal-join-easy
    """
    safe_path = os.path.normpath(
        os.path.join(base_dir, os.path.basename(user_input))
    )
    return safe_path


def load_config_safely(config_str: str) -> dict:
    """Load YAML config safely.
    Matches template: py-deserial-yaml-easy
    """
    import yaml
    config = yaml.safe_load(config_str)
    return config


def parse_json_safely(user_input: str) -> dict:
    """Parse JSON safely without pickle.
    Matches template: py-deserial-pickle-easy
    """
    import json
    data = json.loads(user_input)
    return data


def fetch_from_allowlist(url_key: str) -> bytes:
    """Fetch URL from allowlist only.
    Matches template: py-ssrf-requests-easy
    """
    import requests
    allowed_urls = {
        "api": "https://api.example.com",
        "cdn": "https://cdn.example.com",
    }
    response = requests.get(allowed_urls.get(url_key))
    return response.content


def build_output(items: list) -> str:
    """Build output string efficiently using join.
    Matches template: py-perf-string-concat-easy
    """
    result = "".join(items)
    return result


def transform_numbers(numbers: list) -> list:
    """Transform numbers using list comprehension.
    Matches template: py-perf-list-comp-easy
    """
    squares = [x * x for x in numbers]
    return squares


def append_item(item: str, items: Optional[list] = None) -> list:
    """Append item to list with proper default handling.
    Matches template: py-logic-mutable-default-easy
    """
    if items is None:
        items = []
    items.append(item)
    return items


def check_count(count: int) -> bool:
    """Check count using proper equality.
    Matches template: py-logic-is-vs-equals-easy
    """
    if count == 1000:
        return True
    return False


def handle_error(func):
    """Decorator to handle errors properly.
    Matches template: py-err-bare-except-easy
    """
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ValueError as e:
            logger.error(f"Invalid value: {e}")
            raise
    return wrapper


def handle_data_error(func):
    """Decorator with specific exception handling.
    Matches template: py-err-broad-except-easy
    """
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (ValueError, KeyError) as e:
            logger.warning(f"Data error: {e}")
            return None
    return wrapper


def get_user_name(user: Optional[User]) -> str:
    """Get user name with None check.
    Matches template: py-null-nocheck-easy
    """
    if user is not None:
        return user.name
    return ""


@handle_error
def parse_input(value: str) -> int:
    """Parse string input to integer."""
    return int(value)


# False Positive: Format with validated enum
# Matches template: py-fp-format-sanitized
def query_with_validated_sort(cursor, sort_key: str) -> list:
    """Query with validated sort column - NOT a vulnerability."""
    validated_columns = {
        "name": "name",
        "email": "email",
        "created_at": "created_at",
    }
    order_by = validated_columns[sort_key]  # Only allows known columns
    cursor.execute(f"SELECT * FROM users ORDER BY {order_by}")
    return cursor.fetchall()
