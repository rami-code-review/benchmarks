"""Test-suite fixtures exercising assertion strength and determinism."""

import unittest

import pytest
from freezegun import freeze_time

from .accounts import create_token, create_user, delete_user, find_user, get_user
from .accounts import Item, ShoppingCart, parse_email


def test_user_creation():
    user = create_user("test@example.com")
    assert user.id is not None
    assert user.email == "test@example.com"
    assert user.created_at is not None


def test_calculate_total():
    cart = ShoppingCart()
    cart.add_item(Item(price=10, quantity=2))
    cart.add_item(Item(price=5, quantity=1))
    assert cart.calculate_total() == 25


def test_parse_email():
    assert parse_email("user@example.com") == ("user", "example.com")

def test_parse_email_empty():
    with pytest.raises(ValueError):
        parse_email("")

def test_parse_email_none():
    with pytest.raises(ValueError):
        parse_email(None)

def test_parse_email_no_at():
    with pytest.raises(ValueError):
        parse_email("invalid")


@freeze_time("2024-01-15 12:00:00")
def test_token_expiry():
    token = create_token(expires_in=3600)
    assert not token.is_expired()

    with freeze_time("2024-01-15 13:00:01"):
        assert token.is_expired()


def test_delete_user_removes_from_database():
    user = create_user()
    delete_user(user.id)
    assert get_user(user.id) is None


class UserLookupTests(unittest.TestCase):
    def test_find_nonexistent(self):
        result = find_user("nonexistent")
        self.assertIsNone(result)
