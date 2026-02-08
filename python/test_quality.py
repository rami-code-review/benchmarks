"""
TEST QUALITY ISSUES - LLM-ADVANTAGE PATTERNS

These patterns require understanding test semantics and intent.
SAST tools score ~0% on these patterns.
"""

import time
from unittest.mock import patch
import pytest
from freezegun import freeze_time

# =============================================================================
# HELPER CLASSES FOR TESTS
# =============================================================================

class User:
    def __init__(self, id: str, email: str, created_at=None):
        self.id = id
        self.email = email
        self.created_at = created_at or time.time()


class Item:
    def __init__(self, price: float, quantity: int):
        self.price = price
        self.quantity = quantity


class ShoppingCart:
    def __init__(self):
        self.items = []

    def add_item(self, item: Item):
        self.items.append(item)

    def calculate_total(self):
        return sum(item.price * item.quantity for item in self.items)


class Token:
    def __init__(self, created_at: float, expires_in: int):
        self.created_at = created_at
        self.expires_in = expires_in

    def is_expired(self):
        return time.time() > self.created_at + self.expires_in


def create_user(email: str) -> User:
    return User(id="123", email=email)


def get_user(user_id: str) -> User | None:
    return None  # Simulates deleted user


def delete_user(user_id: str):
    pass


def create_token(expires_in: int) -> Token:
    return Token(created_at=time.time(), expires_in=expires_in)


def parse_email(email: str) -> tuple[str, str]:
    if not email:
        raise ValueError("Email cannot be empty")
    if "@" not in email:
        raise ValueError("Invalid email format")
    parts = email.split("@")
    return parts[0], parts[1]


# =============================================================================
# py-test-no-assertion-easy: Test doesn't assert anything meaningful
# =============================================================================

# SAFE: Test with meaningful assertions
def test_user_creation_safe():
    user = create_user("test@example.com")
    assert user.id is not None
    assert user.email == "test@example.com"
    assert user.created_at is not None


# VULNERABLE: Test with no assertions - just prints
def test_user_creation_bad():
    user = create_user("test@example.com")
    print(f"User created: {user}")


# =============================================================================
# py-test-mock-sut-hard: Test mocks the thing being tested
# =============================================================================

# SAFE: Tests actual implementation
def test_calculate_total_safe():
    cart = ShoppingCart()
    cart.add_item(Item(price=10, quantity=2))
    cart.add_item(Item(price=5, quantity=1))
    assert cart.calculate_total() == 25


# VULNERABLE: Mocks the method being tested - tests nothing!
@patch.object(ShoppingCart, 'calculate_total', return_value=25)
def test_calculate_total_bad(mock_calc):
    cart = ShoppingCart()
    assert cart.calculate_total() == 25


# =============================================================================
# py-test-missing-edge-case-medium: Missing edge case coverage
# =============================================================================

# SAFE: Comprehensive edge case coverage
def test_parse_email_safe():
    assert parse_email("user@example.com") == ("user", "example.com")


def test_parse_email_empty_safe():
    with pytest.raises(ValueError):
        parse_email("")


def test_parse_email_none_safe():
    with pytest.raises(ValueError):
        parse_email(None)


def test_parse_email_no_at_safe():
    with pytest.raises(ValueError):
        parse_email("invalid")


# VULNERABLE: Only tests happy path - no edge cases
def test_parse_email_bad():
    assert parse_email("user@example.com") == ("user", "example.com")


# =============================================================================
# py-test-flaky-time-hard: Flaky test pattern - time-dependent
# =============================================================================

# SAFE: Uses freeze_time for deterministic testing
@freeze_time("2024-01-15 12:00:00")
def test_token_expiry_safe():
    token = Token(created_at=time.time(), expires_in=3600)
    assert not token.is_expired()

    with freeze_time("2024-01-15 13:00:01"):
        assert token.is_expired()


# VULNERABLE: Time-dependent test - flaky!
def test_token_expiry_bad():
    token = create_token(expires_in=1)
    time.sleep(2)
    assert token.is_expired()


# =============================================================================
# py-test-wrong-name-easy: Test name doesn't match what it tests
# =============================================================================

# SAFE: Descriptive test name
def test_delete_user_removes_from_database_safe():
    user = create_user("test@example.com")
    delete_user(user.id)
    assert get_user(user.id) is None


# VULNERABLE: Vague, misleading test name
def test_user_bad():
    user = create_user("test@example.com")
    delete_user(user.id)
    assert get_user(user.id) is None
