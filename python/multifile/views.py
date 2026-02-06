"""HTTP views demonstrating cross-file data flow patterns."""

from typing import Optional
from .models import UserRepository
from .validators import validate_user_id, sanitize_search_query


class UserView:
    """Handles user-related HTTP requests."""

    def __init__(self, repository: UserRepository):
        self.repository = repository

    def get_user(self, request_id: str) -> Optional[dict]:
        """Get user by ID from request.

        SAFE VERSION: ID is validated before database query.
        Matches template: py-multifile-sqli-safe
        """
        # Validation in view layer
        if not validate_user_id(request_id):
            return {"error": "invalid id"}

        # Safe: validated ID passed to repository
        user = self.repository.find_by_id(request_id)
        if user is None:
            return {"error": "not found"}

        return {"user": user.to_dict()}

    def search_users(self, query: str) -> dict:
        """Search users by query string.

        SAFE VERSION: Query is sanitized and repository uses parameterized query.
        Matches template: py-multifile-sqli-search-safe
        """
        # Sanitization in view layer
        safe_query = sanitize_search_query(query)

        # Repository uses parameterized query
        users = self.repository.search(safe_query)

        return {"users": [u.to_dict() for u in users]}

    def get_user_by_email(self, email: str) -> Optional[dict]:
        """Get user by email address.

        SAFE VERSION: Repository uses parameterized query.
        """
        user = self.repository.find_by_email(email)
        if user is None:
            return {"error": "not found"}

        return {"user": user.to_dict()}


class FileView:
    """Handles file-related HTTP requests."""

    def __init__(self, base_path: str):
        self.base_path = base_path

    def read_file(self, filename: str) -> Optional[dict]:
        """Read a file from the uploads directory.

        SAFE VERSION: Path is validated against base directory.
        Matches template: py-multifile-pathtraversal-safe
        """
        import os

        # Normalize and validate path
        safe_name = os.path.basename(filename)
        full_path = os.path.join(self.base_path, safe_name)

        # Double-check it's within base path
        if not full_path.startswith(os.path.abspath(self.base_path)):
            return {"error": "invalid path"}

        try:
            with open(full_path, 'r') as f:
                content = f.read()
            return {"content": content}
        except FileNotFoundError:
            return {"error": "file not found"}
