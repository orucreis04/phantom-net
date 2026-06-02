from __future__ import annotations

import base64
import hmac
import os
import secrets
import time
from collections import defaultdict, deque
from hashlib import pbkdf2_hmac, sha256
from http.cookies import SimpleCookie
from urllib.parse import parse_qs


SESSION_COOKIE = "phantom_session"
CSRF_COOKIE = "phantom_csrf"
DEFAULT_ADMIN_USER = "admin"
DEFAULT_ADMIN_PASSWORD = "phantom-admin"
_runtime_auth: dict[str, object] = {}
_login_attempts: dict[str, deque[float]] = defaultdict(deque)


def configure_auth(
    username: str,
    password: str,
    secret: str,
    session_max_age_seconds: int,
    password_hash: str = "",
    login_window_seconds: int = 300,
    max_login_attempts: int = 5,
) -> None:
    _runtime_auth.update(
        {
            "username": username,
            "password": password,
            "password_hash": password_hash,
            "secret": secret,
            "session_max_age_seconds": session_max_age_seconds,
            "login_window_seconds": login_window_seconds,
            "max_login_attempts": max_login_attempts,
        }
    )


def hash_password(password: str, iterations: int = 260_000) -> str:
    salt = secrets.token_bytes(16)
    digest = pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return "pbkdf2_sha256${}${}${}".format(
        iterations,
        base64.b64encode(salt).decode(),
        base64.b64encode(digest).decode(),
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt, expected = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        digest = pbkdf2_hmac("sha256", password.encode(), base64.b64decode(salt), int(iterations))
        return hmac.compare_digest(base64.b64encode(digest).decode(), expected)
    except (ValueError, TypeError):
        return False


def admin_username() -> str:
    return str(_runtime_auth.get("username") or os.getenv("PHANTOM_ADMIN_USER", DEFAULT_ADMIN_USER))


def admin_password() -> str:
    return str(_runtime_auth.get("password") or os.getenv("PHANTOM_ADMIN_PASSWORD", DEFAULT_ADMIN_PASSWORD))


def admin_password_hash() -> str:
    return str(_runtime_auth.get("password_hash") or os.getenv("PHANTOM_ADMIN_PASSWORD_HASH", ""))


def auth_secret() -> str:
    return str(_runtime_auth.get("secret") or os.getenv("PHANTOM_AUTH_SECRET", "phantom-net-local-dev-secret"))


def verify_credentials(body: str) -> bool:
    fields = parse_qs(body)
    username = fields.get("username", [""])[0]
    password = fields.get("password", [""])[0]
    if not hmac.compare_digest(username, admin_username()):
        return False
    encoded = admin_password_hash()
    if encoded:
        return verify_password(password, encoded)
    return hmac.compare_digest(password, admin_password())


def is_rate_limited(source_ip: str, now: float | None = None) -> bool:
    now = now or time.time()
    window = int(_runtime_auth.get("login_window_seconds") or 300)
    max_attempts = int(_runtime_auth.get("max_login_attempts") or 5)
    attempts = _login_attempts[source_ip]
    while attempts and now - attempts[0] > window:
        attempts.popleft()
    return len(attempts) >= max_attempts


def record_failed_login(source_ip: str, now: float | None = None) -> None:
    _login_attempts[source_ip].append(now or time.time())


def clear_login_attempts(source_ip: str) -> None:
    _login_attempts.pop(source_ip, None)


def make_session_cookie(max_age: int | None = None) -> str:
    if max_age is None:
        max_age = int(_runtime_auth.get("session_max_age_seconds") or 8 * 60 * 60)
    expires = int(time.time()) + max_age
    nonce = secrets.token_hex(8)
    payload = f"{expires}:{nonce}"
    signature = hmac.new(auth_secret().encode(), payload.encode(), sha256).hexdigest()
    return f"{SESSION_COOKIE}={payload}:{signature}; HttpOnly; SameSite=Lax; Path=/; Max-Age={max_age}"


def clear_session_cookie() -> str:
    return f"{SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"


def make_csrf_cookie(token: str) -> str:
    return f"{CSRF_COOKIE}={token}; HttpOnly; SameSite=Lax; Path=/login; Max-Age=900"


def make_csrf_token() -> str:
    return secrets.token_urlsafe(24)


def csrf_token_from_cookie(cookie_header: str | None) -> str:
    return _cookie_value(cookie_header, CSRF_COOKIE)


def verify_csrf(cookie_header: str | None, body: str) -> bool:
    cookie_token = csrf_token_from_cookie(cookie_header)
    form_token = parse_qs(body).get("csrf_token", [""])[0]
    return bool(cookie_token and form_token and hmac.compare_digest(cookie_token, form_token))


def is_authenticated(cookie_header: str | None) -> bool:
    value = _cookie_value(cookie_header, SESSION_COOKIE)
    if not value:
        return False
    parts = value.split(":")
    if len(parts) != 3:
        return False
    expires, nonce, signature = parts
    try:
        if int(expires) < int(time.time()):
            return False
    except ValueError:
        return False
    payload = f"{expires}:{nonce}"
    expected = hmac.new(auth_secret().encode(), payload.encode(), sha256).hexdigest()
    return hmac.compare_digest(signature, expected)


def login_page(csrf_token: str, error: str = "") -> str:
    message = f"<p class=\"error\">{error}</p>" if error else ""
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Phantom-Net Login</title>
  <style>
    body {{ margin: 0; min-height: 100vh; display: grid; place-items: center; font-family: Arial, sans-serif; background: #eef3f8; color: #17212f; }}
    main {{ width: min(380px, calc(100vw - 32px)); background: white; border: 1px solid #d6dee8; border-radius: 8px; padding: 28px; }}
    h1 {{ margin: 0 0 6px; font-size: 24px; }}
    p {{ color: #647386; }}
    label {{ display: block; margin: 14px 0 6px; font-size: 14px; }}
    input {{ width: 100%; box-sizing: border-box; min-height: 38px; border: 1px solid #b8c4d2; border-radius: 6px; padding: 8px; }}
    button {{ width: 100%; margin-top: 18px; min-height: 38px; border: 1px solid #185abc; border-radius: 6px; background: #1f6feb; color: white; font-weight: 700; }}
    .error {{ color: #bf3b2b; }}
  </style>
</head>
<body>
  <main>
    <h1>Phantom-Net</h1>
    <p>Admin dashboard access</p>
    {message}
    <form method="post" action="/login">
      <input type="hidden" name="csrf_token" value="{csrf_token}">
      <label>Username</label><input name="username" autocomplete="username" autofocus>
      <label>Password</label><input name="password" type="password" autocomplete="current-password">
      <button>Sign in</button>
    </form>
  </main>
</body>
</html>"""


def _cookie_value(cookie_header: str | None, name: str) -> str:
    if not cookie_header:
        return ""
    cookies = SimpleCookie()
    cookies.load(cookie_header)
    morsel = cookies.get(name)
    return morsel.value if morsel else ""
