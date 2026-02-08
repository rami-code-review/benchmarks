"""Benchmark patterns for Python security and quality detection.

Each function represents a template pattern for testing code review capabilities.
"""

import logging
import os
from typing import Any, Callable, Dict, List, Optional

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


def sqli_fstring_unsafe(user_id: str):
    """py-sqli-fstring-unsafe: UNSAFE f-string in SQL"""
    # UNSAFE: SQL injection via f-string
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")


def sqli_fstring_fix(user_id: str):
    """py-sqli-fstring-fix: Parameterized query"""
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))


def sqli_format_unsafe(name: str):
    """py-sqli-format-unsafe: UNSAFE .format() in SQL"""
    # UNSAFE: SQL injection via format
    query = "SELECT * FROM users WHERE name = '{}'".format(name)
    cursor.execute(query)


def sqli_concat_unsafe(status: str):
    """py-sqli-concat-unsafe: UNSAFE string concatenation in SQL"""
    # UNSAFE: SQL injection via concatenation
    cursor.execute("SELECT * FROM orders WHERE status = '" + status + "'")


# Django ORM patterns
def django_raw_sql_unsafe(search: str):
    """py-sqli-django-raw-unsafe: UNSAFE raw SQL in Django"""
    from django.db import connection
    # UNSAFE: Raw SQL with user input
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{search}%'")
        return cursor.fetchall()


def django_raw_sql_safe(search: str):
    """py-sqli-django-raw-safe: Safe parameterized raw SQL"""
    from django.db import connection
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT * FROM products WHERE name LIKE %s",
            [f"%{search}%"]
        )
        return cursor.fetchall()


def django_extra_unsafe(order_by: str):
    """py-sqli-django-extra-unsafe: UNSAFE extra() with user input"""
    from django.contrib.auth.models import User
    # UNSAFE: User input in order_by
    return User.objects.extra(order_by=[order_by])


def django_extra_safe(order_by: str):
    """py-sqli-django-extra-safe: Validated order_by"""
    from django.contrib.auth.models import User
    allowed = ['username', 'email', 'date_joined', '-username', '-email', '-date_joined']
    if order_by not in allowed:
        order_by = 'username'
    return User.objects.order_by(order_by)


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


def cmdi_shell_true_unsafe(filename: str):
    """py-cmdi-shell-true-unsafe: UNSAFE shell=True with user input"""
    import subprocess
    # UNSAFE: Shell injection
    subprocess.run(f"cat {filename}", shell=True)


def cmdi_shell_true_fix(filename: str):
    """py-cmdi-shell-true-fix: Safe subprocess without shell"""
    import subprocess
    # Validate filename
    if not filename.replace('.', '').replace('_', '').replace('-', '').isalnum():
        raise ValueError("Invalid filename")
    subprocess.run(["cat", filename], check=True)


def cmdi_os_system_unsafe(cmd: str):
    """py-cmdi-os-system-unsafe: UNSAFE os.system()"""
    import os
    # UNSAFE: Direct command execution
    os.system(cmd)


def cmdi_popen_unsafe(user_arg: str):
    """py-cmdi-popen-unsafe: UNSAFE Popen with shell"""
    import subprocess
    # UNSAFE: Shell injection via Popen
    subprocess.Popen(f"grep {user_arg} /var/log/app.log", shell=True)


def cmdi_popen_fix(user_arg: str):
    """py-cmdi-popen-fix: Safe Popen with args list"""
    import subprocess
    if not user_arg.isalnum():
        raise ValueError("Invalid search term")
    subprocess.Popen(["grep", user_arg, "/var/log/app.log"])


# =============================================================================
# PATH TRAVERSAL PATTERNS
# =============================================================================

def pathtraversal_join_easy():
    """py-pathtraversal-join-easy"""
    safe_path = os.path.normpath(os.path.join(base_dir, os.path.basename(user_input)))
    return safe_path


def pathtraversal_open_unsafe(filename: str):
    """py-pathtraversal-open-unsafe: UNSAFE file open"""
    # UNSAFE: Path traversal
    with open(os.path.join("/uploads", filename)) as f:
        return f.read()


def pathtraversal_open_fix(filename: str):
    """py-pathtraversal-open-fix: Validated path"""
    import os
    base = os.path.abspath("/uploads")
    path = os.path.abspath(os.path.join(base, filename))
    if not path.startswith(base + os.sep):
        raise ValueError("Path traversal detected")
    with open(path) as f:
        return f.read()


def pathtraversal_send_file_unsafe(filename: str):
    """py-pathtraversal-send-file-unsafe: Flask send_file vulnerability"""
    from flask import send_file
    # UNSAFE: User-controlled path
    return send_file(os.path.join("static", filename))


def pathtraversal_send_file_fix(filename: str):
    """py-pathtraversal-send-file-fix: Safe send_from_directory"""
    from flask import send_from_directory
    return send_from_directory("static", filename)


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


def deserial_pickle_unsafe(data: bytes):
    """py-deserial-pickle-unsafe: UNSAFE pickle.loads()"""
    import pickle
    # UNSAFE: Arbitrary code execution
    return pickle.loads(data)


def deserial_pickle_fix(data: str):
    """py-deserial-pickle-fix: Use JSON instead"""
    import json
    return json.loads(data)


def deserial_yaml_unsafe(yaml_str: str):
    """py-deserial-yaml-unsafe: UNSAFE yaml.load()"""
    import yaml
    # UNSAFE: Code execution via YAML
    return yaml.load(yaml_str, Loader=yaml.Loader)


def deserial_yaml_fix(yaml_str: str):
    """py-deserial-yaml-fix: Safe yaml.safe_load()"""
    import yaml
    return yaml.safe_load(yaml_str)


def deserial_marshal_unsafe(data: bytes):
    """py-deserial-marshal-unsafe: UNSAFE marshal.loads()"""
    import marshal
    # UNSAFE: Can execute arbitrary code
    return marshal.loads(data)


# =============================================================================
# XSS PATTERNS (Jinja2/Flask)
# =============================================================================

def xss_jinja_unsafe(user_input: str):
    """py-xss-jinja-unsafe: UNSAFE Jinja2 rendering"""
    from jinja2 import Template
    # UNSAFE: User input in template
    template = Template(f"<div>{user_input}</div>")
    return template.render()


def xss_jinja_fix(user_input: str):
    """py-xss-jinja-fix: Escaped output"""
    from markupsafe import escape
    return f"<div>{escape(user_input)}</div>"


def xss_flask_unsafe():
    """py-xss-flask-unsafe: UNSAFE make_response with HTML"""
    from flask import make_response, request
    # UNSAFE: Direct HTML injection
    name = request.args.get('name')
    resp = make_response(f"<h1>Hello, {name}</h1>")
    resp.headers['Content-Type'] = 'text/html'
    return resp


def xss_flask_fix():
    """py-xss-flask-fix: Escaped response"""
    from flask import make_response, request
    from markupsafe import escape
    name = escape(request.args.get('name', ''))
    resp = make_response(f"<h1>Hello, {name}</h1>")
    resp.headers['Content-Type'] = 'text/html'
    return resp


# =============================================================================
# TEMPLATE INJECTION PATTERNS
# =============================================================================

def ssti_jinja_unsafe(user_template: str):
    """py-ssti-jinja-unsafe: Server-side template injection"""
    from jinja2 import Environment
    # UNSAFE: User-controlled template
    env = Environment()
    template = env.from_string(user_template)
    return template.render()


def ssti_jinja_fix(template_name: str, context: dict):
    """py-ssti-jinja-fix: Use predefined templates"""
    from jinja2 import Environment, select_autoescape, FileSystemLoader
    env = Environment(
        loader=FileSystemLoader('templates'),
        autoescape=select_autoescape(['html', 'xml'])
    )
    template = env.get_template(template_name)
    return template.render(**context)


# =============================================================================
# SSRF PATTERNS
# =============================================================================

def ssrf_requests_easy():
    """py-ssrf-requests-easy"""
    import requests
    response = requests.get(allowed_urls.get(url_key))
    return response


def ssrf_requests_unsafe(url: str):
    """py-ssrf-requests-unsafe: UNSAFE unvalidated URL"""
    import requests
    # UNSAFE: SSRF
    return requests.get(url)


def ssrf_requests_fix(url: str):
    """py-ssrf-requests-fix: Validated URL"""
    import ipaddress
    import socket
    from urllib.parse import urlparse
    import requests

    parsed = urlparse(url)
    allowed_hosts = ['api.example.com', 'cdn.example.com']

    if parsed.hostname not in allowed_hosts:
        raise ValueError("Host not allowed")

    # Check for internal IPs
    try:
        ip = socket.gethostbyname(parsed.hostname)
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback:
            raise ValueError("Internal addresses not allowed")
    except socket.gaierror:
        raise ValueError("Cannot resolve hostname")

    return requests.get(url)


def ssrf_urllib_unsafe(url: str):
    """py-ssrf-urllib-unsafe: UNSAFE urllib request"""
    import urllib.request
    # UNSAFE: No URL validation
    return urllib.request.urlopen(url).read()


# =============================================================================
# SECRETS PATTERNS
# =============================================================================

def secret_token_easy():
    """py-secret-token-easy"""
    token = os.environ.get("AUTH_TOKEN")
    return token


def secret_hardcoded_unsafe():
    """py-secret-hardcoded-unsafe: Hardcoded API key"""
    # UNSAFE: Hardcoded secret
    API_KEY = "sk_live_abc123xyz789"
    return API_KEY


def secret_hardcoded_fix():
    """py-secret-hardcoded-fix: Environment variable"""
    api_key = os.environ.get("API_KEY")
    if not api_key:
        raise ValueError("API_KEY not configured")
    return api_key


def secret_logging_unsafe(api_key: str, user_id: str):
    """py-secret-logging-unsafe: Logging sensitive data"""
    # UNSAFE: Sensitive data in logs
    logger.info(f"Request with API key: {api_key} for user: {user_id}")


def secret_logging_fix(api_key: str, user_id: str):
    """py-secret-logging-fix: Redacted logging"""
    masked_key = api_key[:4] + "..." if len(api_key) > 4 else "[REDACTED]"
    logger.info(f"Request with API key: {masked_key} for user: {user_id}")


# =============================================================================
# CRYPTO PATTERNS
# =============================================================================

def crypto_md5_easy(password: str):
    """py-crypto-md5-easy"""
    import hashlib
    hash_val = hashlib.sha256(password.encode()).hexdigest()
    return hash_val


def crypto_md5_unsafe(password: str):
    """py-crypto-md5-unsafe: UNSAFE MD5 for passwords"""
    import hashlib
    # UNSAFE: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()


def crypto_md5_fix(password: str):
    """py-crypto-md5-fix: Use bcrypt or argon2"""
    import hashlib
    import os
    salt = os.urandom(16)
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000).hex()


def crypto_random_unsafe():
    """py-crypto-random-unsafe: UNSAFE random for security"""
    import random
    # UNSAFE: Predictable random
    return random.randint(0, 999999)


def crypto_random_fix():
    """py-crypto-random-fix: Cryptographic random"""
    import secrets
    return secrets.randbelow(1000000)


def crypto_weak_key_unsafe():
    """py-crypto-weak-key-unsafe: Weak encryption key"""
    from cryptography.fernet import Fernet
    # UNSAFE: Hardcoded/weak key
    key = b'weak_key_12345678901234567890123='  # Not a valid Fernet key, but illustrates pattern
    return Fernet(key)


# =============================================================================
# ASYNC/AWAIT PATTERNS
# =============================================================================

async def async_unhandled_exception_unsafe():
    """py-async-unhandled-unsafe: Unhandled async exception"""
    import asyncio
    # UNSAFE: Exception not propagated
    async def risky_operation():
        raise ValueError("Something went wrong")

    asyncio.create_task(risky_operation())  # Fire-and-forget


async def async_unhandled_exception_fix():
    """py-async-unhandled-fix: Proper async error handling"""
    import asyncio

    async def risky_operation():
        raise ValueError("Something went wrong")

    try:
        await risky_operation()
    except ValueError as e:
        logger.error(f"Async operation failed: {e}")
        raise


async def async_timeout_missing_unsafe(url: str):
    """py-async-timeout-missing-unsafe: No timeout on network call"""
    import aiohttp
    # UNSAFE: No timeout
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            return await response.text()


async def async_timeout_missing_fix(url: str):
    """py-async-timeout-missing-fix: Proper timeout"""
    import aiohttp
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(url) as response:
            return await response.text()


# =============================================================================
# ERROR HANDLING PATTERNS
# =============================================================================

def err_bare_except_easy(func: Callable):
    """py-err-bare-except-easy"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ValueError as e:
            logger.error(f"Invalid value: {e}")
            raise
    return wrapper


def err_broad_except_easy(func: Callable):
    """py-err-broad-except-easy"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (ValueError, KeyError) as e:
            logger.warning(f"Data error: {e}")
            return None
    return wrapper


def err_bare_except_unsafe():
    """py-err-bare-except-unsafe: UNSAFE bare except"""
    try:
        do_something()
    except:  # UNSAFE: Catches everything including KeyboardInterrupt
        pass


def err_bare_except_fix():
    """py-err-bare-except-fix: Specific exception handling"""
    try:
        do_something()
    except ValueError as e:
        logger.error(f"Value error: {e}")
        raise
    except Exception as e:
        logger.exception("Unexpected error")
        raise


def err_swallowed_unsafe(path: str):
    """py-err-swallowed-unsafe: Swallowed exception"""
    try:
        with open(path) as f:
            return f.read()
    except IOError:
        # UNSAFE: Error swallowed
        pass
    return None


def err_swallowed_fix(path: str) -> Optional[str]:
    """py-err-swallowed-fix: Proper error handling"""
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        logger.warning(f"File not found: {path}")
        return None
    except PermissionError:
        logger.error(f"Permission denied: {path}")
        raise


def err_info_leak_unsafe(e: Exception):
    """py-err-info-leak-unsafe: Exception info leak to user"""
    from flask import jsonify
    # UNSAFE: Stack trace exposed
    import traceback
    return jsonify({"error": str(e), "trace": traceback.format_exc()})


def err_info_leak_fix(e: Exception):
    """py-err-info-leak-fix: Generic error message"""
    from flask import jsonify
    import traceback
    logger.exception("Internal error")
    return jsonify({"error": "An internal error occurred"}), 500


# =============================================================================
# NULL/NONE SAFETY PATTERNS
# =============================================================================

def null_nocheck_easy():
    """py-null-nocheck-easy"""
    if user is not None:
        return user.name
    return ""


def null_attribute_unsafe(user):
    """py-null-attribute-unsafe: No None check"""
    # UNSAFE: AttributeError if user is None
    return user.name.upper()


def null_attribute_fix(user) -> str:
    """py-null-attribute-fix: Safe access"""
    if user is None or user.name is None:
        return "Anonymous"
    return user.name.upper()


def null_dict_unsafe(data: dict, key: str):
    """py-null-dict-unsafe: KeyError possible"""
    # UNSAFE: May raise KeyError
    return data[key]


def null_dict_fix(data: dict, key: str, default=None):
    """py-null-dict-fix: Safe dict access"""
    return data.get(key, default)


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


def logic_mutable_default_unsafe(item, items=[]):
    """py-logic-mutable-default-unsafe: UNSAFE mutable default"""
    # UNSAFE: Mutable default argument
    items.append(item)
    return items


def logic_is_comparison_unsafe(value: int):
    """py-logic-is-comparison-unsafe: UNSAFE 'is' for value comparison"""
    # UNSAFE: 'is' compares identity, not value
    if value is 1000:
        return True
    return False


def logic_is_comparison_fix(value: int):
    """py-logic-is-comparison-fix: Use == for value comparison"""
    if value == 1000:
        return True
    return False


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


def perf_string_concat_unsafe(items: List[str]) -> str:
    """py-perf-string-concat-unsafe: UNSAFE string concatenation"""
    # UNSAFE: O(n²) string concatenation
    result = ""
    for item in items:
        result += item + ","
    return result


def perf_string_concat_fix(items: List[str]) -> str:
    """py-perf-string-concat-fix: Efficient join"""
    return ",".join(items)


def perf_list_in_loop_unsafe(items: List[int], targets: List[int]) -> List[int]:
    """py-perf-list-in-loop-unsafe: UNSAFE list membership in loop"""
    # UNSAFE: O(n) lookup in list
    result = []
    for item in items:
        if item in targets:  # O(n) per iteration
            result.append(item)
    return result


def perf_list_in_loop_fix(items: List[int], targets: List[int]) -> List[int]:
    """py-perf-list-in-loop-fix: Set for O(1) lookup"""
    target_set = set(targets)
    return [item for item in items if item in target_set]


def perf_global_import_unsafe():
    """py-perf-global-import-unsafe: Import in function body"""
    # UNSAFE: Import on every call
    import json
    return json.dumps({"key": "value"})


# =============================================================================
# REGEX PATTERNS
# =============================================================================

def regex_redos_unsafe(email: str) -> bool:
    """py-regex-redos-unsafe: ReDoS vulnerable regex"""
    import re
    # UNSAFE: Catastrophic backtracking
    pattern = r"^([a-zA-Z0-9]+)*@[a-zA-Z0-9]+\.[a-zA-Z]+$"
    return bool(re.match(pattern, email))


def regex_redos_fix(email: str) -> bool:
    """py-regex-redos-fix: Non-backtracking regex"""
    import re
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))


def regex_injection_unsafe(pattern: str, text: str):
    """py-regex-injection-unsafe: UNSAFE user input in regex"""
    import re
    # UNSAFE: User-controlled regex
    return re.findall(pattern, text)


def regex_injection_fix(pattern: str, text: str):
    """py-regex-injection-fix: Escape regex special chars"""
    import re
    safe_pattern = re.escape(pattern)
    return re.findall(safe_pattern, text)


# =============================================================================
# TIMING ATTACK PATTERNS
# =============================================================================

def timing_comparison_unsafe(provided: str, expected: str) -> bool:
    """py-timing-comparison-unsafe: Non-constant-time comparison"""
    # UNSAFE: Early exit reveals information
    return provided == expected


def timing_comparison_fix(provided: str, expected: str) -> bool:
    """py-timing-comparison-fix: Constant-time comparison"""
    import hmac
    return hmac.compare_digest(provided, expected)


# =============================================================================
# OPEN REDIRECT PATTERNS
# =============================================================================

def redirect_unsafe():
    """py-redirect-unsafe: UNSAFE unvalidated redirect"""
    from flask import redirect, request
    # UNSAFE: Open redirect
    next_url = request.args.get('next')
    return redirect(next_url)


def redirect_fix():
    """py-redirect-fix: Validated redirect"""
    from flask import redirect, request
    from urllib.parse import urlparse

    next_url = request.args.get('next', '/')
    parsed = urlparse(next_url)

    # Only allow relative URLs
    if parsed.netloc:
        next_url = '/'

    return redirect(next_url)


# =============================================================================
# CVE PATTERNS
# =============================================================================

def cve_unsafe_decompress(archive_path: str, dest_dir: str):
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


def fp_subprocess_constant():
    """py-fp-subprocess-constant: Safe constant command"""
    import subprocess
    # Safe: No user input
    subprocess.run(["ls", "-la", "/var/log"], check=True)


def fp_json_loads():
    """py-fp-json-loads: Safe JSON parsing"""
    import json
    # Safe: JSON.loads is safe
    return json.loads(user_input)


def fp_validated_path(filename: str):
    """py-fp-validated-path: Path validated before use"""
    import os
    # Safe: Basename removes path traversal
    safe_name = os.path.basename(filename)
    if not safe_name or safe_name.startswith('.'):
        raise ValueError("Invalid filename")
    return os.path.join("/uploads", safe_name)


# Helper function for examples
def do_something():
    pass


# =============================================================================
# ADDITIONAL PATTERNS FOR TEMPLATE MATCHING
# These patterns contain EXACT OriginalCode snippets from templates.go
# =============================================================================

# py-sqli-format-unsafe
def sqli_format_safe(name):
    cursor.execute("SELECT * FROM users WHERE name = %s", (name,))


# py-sqli-concat-unsafe
def sqli_concat_safe(status):
    cursor.execute("SELECT * FROM orders WHERE status = %s", (status,))


# py-sqli-django-raw-unsafe / py-sqli-django-raw-safe
def sqli_django_raw(search):
    cursor.execute("SELECT * FROM products WHERE name LIKE %s", [f"%{search}%"])


# py-cmdi-os-system-unsafe
def cmdi_safe(filename):
    subprocess.run(["rm", "-f", filename], check=True)


# py-pathtraversal-send-file-unsafe
def pathtraversal_safe(safe_name):
    return send_from_directory("/uploads", safe_name)


# py-xss-jinja-unsafe
def xss_jinja_safe(template, user_content):
    return Template(template).render(content=user_content)


# py-xss-flask-unsafe
def xss_flask_safe(user_content):
    return render_template("page.html", content=escape(user_content))


# py-ssti-jinja-unsafe
def ssti_safe(user_name):
    return render_template("page.html", name=user_name)


# py-ssrf-urllib-unsafe
def ssrf_urllib_safe(url_key, allowed_urls):
    response = urllib.request.urlopen(allowed_urls.get(url_key))
    return response


# py-secret-logging-unsafe
def secret_logging_safe(user_id):
    logger.info(f"User {user_id} authenticated")


# py-crypto-random-unsafe
def crypto_random_safe():
    token = secrets.token_hex(32)
    return token


# py-err-swallowed-unsafe
def err_swallowed_safe(e):
    logger.error(f"Operation failed: {e}")
    raise


# py-err-info-leak-unsafe
def err_info_leak_safe(e):
    logger.error(f"Error: {e}", exc_info=True)
    return {"error": "An unexpected error occurred"}


# py-perf-list-in-loop-unsafe
def perf_list_safe(items, allowed_set):
    for item in items:
        if item in allowed_set:
            process(item)


# py-regex-redos-unsafe
def regex_redos_safe(user_input):
    if re.match(r'^[a-zA-Z0-9_]+$', user_input):
        return True
    return False


# py-regex-injection-unsafe
def regex_injection_safe(pattern, text):
    re.search(pattern, text)


# py-timing-comparison-unsafe
def timing_safe(provided_token, expected_token):
    if hmac.compare_digest(provided_token, expected_token):
        return True
    return False


# py-redirect-unsafe
def redirect_safe(next_url, is_safe):
    if is_safe:
        return redirect(next_url)
    return redirect("/")


# py-fp-subprocess-constant
def fp_subprocess_constant():
    subprocess.run(["ls", "-la", "/tmp"], check=True)


# py-design-god-class-hard
class UserServiceSeparated:
    def __init__(self, repo):
        self.repo = repo

    def get_user(self, id): ...
    def create_user(self, data): ...

class EmailService:
    def __init__(self, client):
        self.client = client

    def send_email(self, to, subject, body): ...


# py-design-inheritance-over-composition-medium
class AnimalComposition:
    def __init__(self, locomotion, sound_maker):
        self.locomotion = locomotion
        self.sound_maker = sound_maker

    def move(self):
        self.locomotion.move()

    def make_sound(self):
        self.sound_maker.make_sound()


# py-test-missing-edge-case-medium
def test_parse_email_basic():
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


# py-test-flaky-time-hard
def test_token_expiry():
    token = create_token(expires_in=3600)
    assert not token.is_expired()

    with freeze_time("2024-01-15 13:00:01"):
        assert token.is_expired()


# py-test-wrong-name-easy
def test_delete_user():
    user = create_user()
    delete_user(user.id)
    assert get_user(user.id) is None


# py-django-nplus1-medium
def authors_list(request):
    authors = Author.objects.prefetch_related('books').all()
    return render(request, 'authors.html', {'authors': authors})


# py-flask-debug-production-easy
def run_flask(app):
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug_mode)


# py-asyncio-blocking-call-medium
async def fetch_json(url):
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            return await response.json()


# py-asyncio-gather-exception-medium
async def fetch_all(urls):
    results = await asyncio.gather(
        *[fetch(url) for url in urls],
        return_exceptions=True
    )
    for result in results:
        if isinstance(result, Exception):
            logger.error(f"Fetch failed: {result}")
    return [r for r in results if not isinstance(r, Exception)]
