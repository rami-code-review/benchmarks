"""Exact template patterns for benchmark testing.

Each function contains the EXACT OriginalCode from templates.go.
"""

import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

# Mock objects for pattern matching
cursor = None
user_id = None
email = None
cid = None
user_input = None
config_str = None
user_provided_yaml = None
user_provided_url = None
allowed_urls = {}
url_key = None
items = []
numbers = []
item = None
count = None
user = None
safe_path = None
filename = None
base_dir = None
user_xml = None
sort_key = None
validated_columns = {}


# =============================================================================
# SQL INJECTION PATTERNS
# =============================================================================

def sqli_fstring_easy():
    """py-sqli-fstring-easy"""
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))


def sqli_format_easy():
    """py-sqli-format-easy"""
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))


def sqli_percent_easy():
    """py-sqli-percent-easy"""
    cursor.execute("SELECT * FROM orders WHERE customer_id = %s", (cid,))


# =============================================================================
# SECRETS PATTERNS
# =============================================================================

def secret_token_easy():
    """py-secret-token-easy"""
    token = os.environ.get("AUTH_TOKEN")
    return token


# =============================================================================
# CRYPTO PATTERNS
# =============================================================================

def crypto_md5_easy(password):
    """py-crypto-md5-easy"""
    import hashlib
    hash_val = hashlib.sha256(password.encode()).hexdigest()
    return hash_val


# =============================================================================
# COMMAND INJECTION PATTERNS
# =============================================================================

def cmdi_shell_easy():
    """py-cmdi-shell-easy"""
    import subprocess
    subprocess.run(["ls", "-la", safe_path], check=True)


def cmdi_ossystem_easy():
    """py-cmdi-ossystem-easy"""
    import shlex
    import subprocess
    subprocess.run(["rm", "-f", shlex.quote(filename)])


# =============================================================================
# PATH TRAVERSAL PATTERNS
# =============================================================================

def pathtraversal_join_easy():
    """py-pathtraversal-join-easy"""
    safe_path = os.path.normpath(os.path.join(base_dir, os.path.basename(user_input)))
    return safe_path


# =============================================================================
# DESERIALIZATION PATTERNS
# =============================================================================

def deserial_pickle_easy():
    """py-deserial-pickle-easy"""
    import json
    data = json.loads(user_input)
    return data


def deserial_yaml_easy():
    """py-deserial-yaml-easy"""
    import yaml
    config = yaml.safe_load(config_str)
    return config


# =============================================================================
# SSRF PATTERNS
# =============================================================================

def ssrf_requests_easy():
    """py-ssrf-requests-easy"""
    import requests
    response = requests.get(allowed_urls.get(url_key))
    return response


# =============================================================================
# PERFORMANCE PATTERNS
# =============================================================================

def perf_string_concat_easy():
    """py-perf-string-concat-easy"""
    result = "".join(items)
    return result


def perf_list_comp_easy():
    """py-perf-list-comp-easy"""
    squares = [x * x for x in numbers]
    return squares


# =============================================================================
# LOGIC PATTERNS
# =============================================================================

def logic_mutable_default_easy(item, items=None):
    """py-logic-mutable-default-easy"""
    if items is None:
        items = []
    items.append(item)
    return items


def logic_is_vs_equals_easy():
    """py-logic-is-vs-equals-easy"""
    if count == 1000:
        return True
    return False


# =============================================================================
# ERROR HANDLING PATTERNS
# =============================================================================

def err_bare_except_easy(func):
    """py-err-bare-except-easy"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ValueError as e:
            logger.error(f"Invalid value: {e}")
            raise
    return wrapper


def err_broad_except_easy(func):
    """py-err-broad-except-easy"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (ValueError, KeyError) as e:
            logger.warning(f"Data error: {e}")
            return None
    return wrapper


# =============================================================================
# NULL SAFETY PATTERNS
# =============================================================================

def null_nocheck_easy():
    """py-null-nocheck-easy"""
    if user is not None:
        return user.name
    return ""


# =============================================================================
# CVE PATTERNS
# =============================================================================

def cve_unsafe_decompress(archive_path, dest_dir):
    """py-cve-unsafe-decompress"""
    import tarfile
    # Safe: validate archive contents before extraction
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            if member.name.startswith('/') or '..' in member.name:
                raise ValueError("Unsafe path in archive")
        tar.extractall(path=dest_dir)


def cve_unsafe_deserial_yaml():
    """py-cve-unsafe-deserial-yaml"""
    import yaml
    # Safe: use safe_load for untrusted YAML
    config = yaml.safe_load(user_provided_yaml)
    return config


def cve_xxe():
    """py-cve-xxe"""
    from lxml import etree
    # Safe: disable external entities in XML parser
    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    doc = etree.fromstring(user_xml, parser=parser)
    return doc


# =============================================================================
# FALSE POSITIVE PATTERNS
# =============================================================================

def fp_format_sanitized():
    """py-fp-format-sanitized"""
    order_by = validated_columns[sort_key]  # Only allows known columns
    cursor.execute(f"SELECT * FROM users ORDER BY {order_by}")
