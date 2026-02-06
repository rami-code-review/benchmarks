"""Data models and repository patterns."""

from typing import Optional, List
from dataclasses import dataclass


@dataclass
class User:
    """User entity."""

    id: int
    name: str
    email: str

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "email": self.email}


class UserRepository:
    """Repository for user data access.

    Uses parameterized queries for all database operations.
    """

    def __init__(self, connection):
        self.conn = connection
        self.cursor = connection.cursor()

    def find_by_id(self, user_id: str) -> Optional[User]:
        """Find user by ID.

        SAFE VERSION: Uses parameterized query.
        Matches template: py-multifile-sqli-safe (receiver)
        """
        self.cursor.execute(
            "SELECT id, name, email FROM users WHERE id = %s",
            (user_id,)
        )
        row = self.cursor.fetchone()
        if row:
            return User(id=row[0], name=row[1], email=row[2])
        return None

    def find_by_email(self, email: str) -> Optional[User]:
        """Find user by email.

        SAFE VERSION: Uses parameterized query.
        """
        self.cursor.execute(
            "SELECT id, name, email FROM users WHERE email = %s",
            (email,)
        )
        row = self.cursor.fetchone()
        if row:
            return User(id=row[0], name=row[1], email=row[2])
        return None

    def search(self, query: str) -> List[User]:
        """Search users by name.

        SAFE VERSION: Uses parameterized LIKE query.
        Matches template: py-multifile-sqli-search-safe (receiver)
        """
        self.cursor.execute(
            "SELECT id, name, email FROM users WHERE name LIKE %s",
            (f"%{query}%",)
        )
        rows = self.cursor.fetchall()
        return [User(id=r[0], name=r[1], email=r[2]) for r in rows]

    def create(self, name: str, email: str) -> User:
        """Create a new user.

        SAFE VERSION: Uses parameterized insert.
        """
        self.cursor.execute(
            "INSERT INTO users (name, email) VALUES (%s, %s) RETURNING id",
            (name, email)
        )
        user_id = self.cursor.fetchone()[0]
        self.conn.commit()
        return User(id=user_id, name=name, email=email)

    def delete(self, user_id: int) -> bool:
        """Delete a user by ID.

        SAFE VERSION: Uses parameterized delete.
        """
        self.cursor.execute(
            "DELETE FROM users WHERE id = %s",
            (user_id,)
        )
        self.conn.commit()
        return self.cursor.rowcount > 0
