"""Hardened security helpers used as benchmark injection sites."""

import hashlib
import json
import re
import secrets
import subprocess
import urllib.request

import requests
from flask import redirect

from .allowlist import allowed_urls, is_safe_url


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def new_session_token() -> str:
    return secrets.token_hex(32)


def load_payload(data: str):
    return json.loads(data)


def fetch_remote(url_key: str):
    return requests.get(allowed_urls.get(url_key))


def open_remote(url_key: str):
    return urllib.request.urlopen(allowed_urls.get(url_key))


def redirect_after_login(next_url: str, allowed_hosts):
    if is_safe_url(next_url, allowed_hosts):
        return redirect(next_url)
    return redirect("/")


def find_in_text(user_pattern: str, text: str):
    pattern = re.escape(user_pattern)
    re.search(pattern, text)


def list_temp_directory():
    subprocess.run(["ls", "-la", "/tmp"], check=True)


def parse_request_body(user_input: str):
    data = json.loads(user_input)
    return data


def list_users_sorted(cursor, sort_key: str, validated_columns):
    order_by = validated_columns[sort_key]  # Only allows known columns
    cursor.execute(f"SELECT * FROM users ORDER BY {order_by}")
    return cursor.fetchall()
