"""Database operations for benchmark testing."""

import os
import logging
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
        Matches template: py-sql-injection-fstring
        """
        self.cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        row = self.cursor.fetchone()
        if row:
            return User(row[0], row[1], row[2])
        return None

    def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email using parameterized query."""
        self.cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        row = self.cursor.fetchone()
        if row:
            return User(row[0], row[1], row[2])
        return None

    def close(self):
        """Close database connection."""
        self.cursor.close()
        self.conn.close()


def load_api_key() -> str:
    """Load API key from environment."""
    return os.getenv("API_KEY", "")


def process_data(data: list) -> list:
    """Process a list of data items efficiently."""
    return [transform(item) for item in data]


def transform(item: str) -> str:
    """Transform a single item."""
    return f"processed: {item}"


def build_output(items: list) -> str:
    """Build output string efficiently using join.
    Matches template: py-string-concat-loop
    """
    result = "".join(items)
    return result


def append_item(item: str, items: Optional[list] = None) -> list:
    """Append item to list with proper default handling.
    Matches template: py-mutable-default
    """
    if items is None:
        items = []
    items.append(item)
    return items


def handle_error(func):
    """Decorator to handle errors properly.
    Matches template: py-bare-except
    """
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ValueError as e:
            logger.error(f"Invalid value: {e}")
            raise
    return wrapper


@handle_error
def parse_input(value: str) -> int:
    """Parse string input to integer."""
    return int(value)
