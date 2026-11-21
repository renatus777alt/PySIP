#!/usr/bin/env python3
"""PySIP Web Panel - retro-styled signup, personal account panel and administrator interface.

Uses only Python's standard library. Shares pysip.db with sip_server.py.
Run only on a trusted private network/VPN: this HTTP panel does not provide TLS.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import logging
import os
import re
import secrets
import sqlite3
import time
import threading
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Optional, Tuple
from urllib.parse import parse_qs, urlparse

APP_NAME = "PySIP Web Panel 1.0"
DEFAULT_DB = "pysip.db"
DEFAULT_REALM = "pysip.local"
WEB_HOST = os.environ.get("PYSIP_WEB_HOST", "127.0.0.1")
WEB_PORT = int(os.environ.get("PYSIP_WEB_PORT", "8080"))
DB_PATH = os.environ.get("PYSIP_DB_PATH", DEFAULT_DB)
SIP_REALM = os.environ.get("PYSIP_REALM", DEFAULT_REALM)
SIP_PORT = int(os.environ.get("PYSIP_PORT", "5060"))
ADVERTISED_HOST = os.environ.get("PYSIP_ADVERTISED_HOST", "127.0.0.1")
RTP_PORT_MIN = int(os.environ.get("PYSIP_RTP_PORT_MIN", "20000"))
RTP_PORT_MAX = int(os.environ.get("PYSIP_RTP_PORT_MAX", "30000"))
ADMIN_USERNAME = os.environ.get("PYSIP_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("PYSIP_ADMIN_PASSWORD")
if not ADMIN_PASSWORD:
    ADMIN_PASSWORD = secrets.token_urlsafe(24)
    print("\n[PySIP] Generated one-time admin password (save it now):")
    print(f"[PySIP] Admin username: {ADMIN_USERNAME}")
    print(f"[PySIP] Admin password: {ADMIN_PASSWORD}\n")

logging.basicConfig(level=os.environ.get("PYSIP_LOG_LEVEL", "INFO").upper(), format="%(asctime)s %(levelname)s %(message)s")
LOG = logging.getLogger("pysip-web")

SESSIONS: Dict[str, dict] = {}
RATE_LIMITS: Dict[Tuple[str, str], list[int]] = {}
SESSION_LOCK = threading.RLock()
RATE_LOCK = threading.Lock()
SESSION_TTL = 8 * 60 * 60


def remove_sessions(predicate) -> None:
    """Remove matching in-memory sessions while holding the session lock."""
    with SESSION_LOCK:
        for token, value in list(SESSIONS.items()):
            if predicate(value):
                SESSIONS.pop(token, None)
GUEST_TTL = 30 * 60
MAX_BODY = 32_768
PBKDF2_ITERATIONS = 310_000
PHONE_PREFIX = "+190"


def db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 10000")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA temp_store = MEMORY")
    return conn


def ensure_schema() -> None:
    with db_connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                sip_ha1 TEXT NOT NULL,
                phone_number TEXT NOT NULL UNIQUE,
                enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS registrations (
                user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                contact TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                source_ip TEXT NOT NULL,
                source_port INTEGER NOT NULL,
                user_agent TEXT NOT NULL DEFAULT '',
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sip_contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                contact_uri TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                source_port INTEGER NOT NULL,
                user_agent TEXT NOT NULL DEFAULT '',
                expires_at INTEGER NOT NULL,
                call_id TEXT NOT NULL DEFAULT '',
                cseq INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL,
                UNIQUE(user_id, contact_uri)
            );
            CREATE INDEX IF NOT EXISTS idx_sip_contacts_user_expiry
                ON sip_contacts(user_id, expires_at DESC, updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_sip_contacts_endpoint
                ON sip_contacts(source_ip, source_port, expires_at);
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS calls (
                call_id TEXT PRIMARY KEY,
                caller_username TEXT NOT NULL,
                callee_username TEXT NOT NULL,
                caller_number TEXT NOT NULL DEFAULT '',
                callee_number TEXT NOT NULL DEFAULT '',
                state TEXT NOT NULL,
                detail TEXT NOT NULL DEFAULT '',
                sip_code INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                caller_ip TEXT NOT NULL DEFAULT '',
                caller_port INTEGER NOT NULL DEFAULT 0,
                callee_ip TEXT NOT NULL DEFAULT '',
                callee_port INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_calls_updated ON calls(updated_at DESC);
            """
        )
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute(
            """INSERT OR IGNORE INTO sip_contacts
               (user_id, contact_uri, source_ip, source_port, user_agent, expires_at, call_id, cseq, updated_at)
               SELECT user_id, contact, source_ip, source_port, user_agent, expires_at, '', 0, updated_at
               FROM registrations WHERE expires_at > ?""",
            (int(time.time()),),
        )


def current_advertised_host() -> str:
    try:
        with db_connect() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key = 'advertised_host'").fetchone()
            if row and row["value"]:
                return str(row["value"])
    except sqlite3.Error:
        pass
    return ADVERTISED_HOST


def make_password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password_hash(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations_text, salt_hex, digest_hex = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iterations_text)
        if not 100_000 <= iterations <= 2_000_000:
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def sip_ha1(username: str, password: str) -> str:
    # SIP Digest's MD5 HA1 value is stored instead of the plaintext password.
    return hashlib.md5(f"{username}:{SIP_REALM}:{password}".encode("utf-8")).hexdigest()


def generate_phone_number(conn: sqlite3.Connection) -> str:
    row = conn.execute("SELECT value FROM settings WHERE key = 'next_phone_sequence'").fetchone()
    sequence = int(row["value"]) if row else 1
    while True:
        if sequence > 99_999_999:
            raise RuntimeError("The +190 number range has been exhausted")
        candidate = f"{PHONE_PREFIX}{sequence:08d}"
        exists = conn.execute("SELECT 1 FROM users WHERE phone_number = ?", (candidate,)).fetchone()
        sequence += 1
        if not exists:
            break
    conn.execute(
        "INSERT INTO settings (key, value) VALUES ('next_phone_sequence', ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(sequence),),
    )
    return candidate


def rate_allowed(ip: str, action: str, limit: int, window: int) -> bool:
    now = int(time.time())
    key = (ip, action)
    with RATE_LOCK:
        attempts = [stamp for stamp in RATE_LIMITS.get(key, []) if now - stamp < window]
        if len(attempts) >= limit:
            RATE_LIMITS[key] = attempts
            return False
        attempts.append(now)
        RATE_LIMITS[key] = attempts
        if len(RATE_LIMITS) > 5_000:
            for old_key in list(RATE_LIMITS)[:2_000]:
                RATE_LIMITS.pop(old_key, None)
        return True


CSS = r"""
:root { color-scheme: light; }
* { box-sizing: border-box; }
body {
  margin: 0; padding: 22px 12px 40px; color: #17263a;
  font: 12px Tahoma, Verdana, Arial, sans-serif;
  background-color: #7f9db9;
  background-image: linear-gradient(135deg, rgba(255,255,255,.12) 25%, transparent 25%),
                    linear-gradient(225deg, rgba(255,255,255,.10) 25%, transparent 25%),
                    linear-gradient(45deg, rgba(0,40,90,.08) 25%, transparent 25%),
                    linear-gradient(315deg, rgba(0,40,90,.08) 25%, #7895b0 25%);
  background-size: 26px 26px; background-position: 0 0, 0 13px, 13px -13px, -13px 0;
}
a { color: #075aa8; }
.wrap { width: min(900px, 100%); margin: 0 auto; }
.topbar {
  color: #fff; padding: 12px 16px; border: 1px solid #174477;
  background: linear-gradient(#6eb4ed, #2875bd 48%, #14518d 49%, #236bad);
  box-shadow: 0 2px 5px rgba(0,0,0,.25); text-shadow: 1px 1px #194b78;
}
.brand { font-size: 23px; font-weight: bold; letter-spacing: .4px; }
.subbrand { margin-top: 4px; color: #e2f2ff; font-size: 11px; }
.nav { padding: 7px 12px; background: #e5edf5; border: 1px solid #819bb5; border-top: 0; }
.nav a { margin-right: 15px; font-weight: bold; text-decoration: none; }
.panel { margin-top: 14px; border: 1px solid #718ba5; background: #f5f8fb; box-shadow: 0 3px 8px rgba(0,0,0,.18); }
.panel-title { padding: 7px 10px; color: #fff; font-weight: bold; background: linear-gradient(#78a9d4, #376f9f); border-bottom: 1px solid #244f78; }
.panel-body { padding: 15px; }
.cols { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
.note { padding: 9px 11px; margin: 10px 0; background: #eaf3fc; border: 1px solid #b4cbe0; line-height: 1.5; }
.warn { background: #fff8df; border-color: #e4d18b; }
.success { background: #e8f6e8; border-color: #9ac99a; }
.error { background: #fff0ee; border-color: #dfaaa3; }
label { display: block; margin: 9px 0 4px; font-weight: bold; }
input[type=text], input[type=password] { width: 100%; max-width: 420px; padding: 7px 8px; border: 1px solid #8c9eae; border-top-color: #586b7b; background: #fff; font: 12px Tahoma, Arial; }
input:focus { outline: 1px solid #438bd0; border-color: #438bd0; }
button, .button { display: inline-block; margin: 8px 4px 2px 0; padding: 6px 14px; color: #173550; font: bold 12px Tahoma, Arial; text-decoration: none; cursor: pointer; border: 1px solid #66849f; border-radius: 3px; background: linear-gradient(#fff, #d8e3ed 48%, #c2d1df 49%, #e8eff5); box-shadow: inset 1px 1px #fff; }
button:hover, .button:hover { background: linear-gradient(#fff, #e6f2ff 48%, #c7ddf2 49%, #f1f7fc); }
button.danger { color: #7b1717; border-color: #b98b8b; }
table { width: 100%; border-collapse: collapse; background: #fff; }
th { text-align: left; color: #fff; padding: 8px; background: linear-gradient(#7ea9ce, #47769e); border: 1px solid #7190aa; }
td { padding: 8px; border: 1px solid #c5d1dc; vertical-align: middle; }
tr:nth-child(even) td { background: #edf3f8; }
.small { color: #627487; font-size: 10px; }
.status-on { color: #18702b; font-weight: bold; }
.status-off { color: #a02020; font-weight: bold; }
.call-state { font-weight: bold; white-space: nowrap; }
.call-active { color: #1769aa; }
.call-good { color: #18702b; }
.call-bad { color: #a02020; }
.footer { margin-top: 15px; color: #e7f0f8; text-align: center; font-size: 10px; text-shadow: 1px 1px #38536b; }
.code { font-family: Consolas, "Courier New", monospace; padding: 2px 4px; background: #e7edf3; border: 1px solid #c5d0da; }
@media (max-width: 650px) { .cols { grid-template-columns: 1fr; } .panel-body { padding: 11px; } table { font-size: 10px; } td, th { padding: 5px; } }
"""


def page(title: str, body: str, nav: str = "") -> str:
    return (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta name="color-scheme" content="light"><title>'
        + html.escape(title)
        + ' - PySIP</title><style>' + CSS + '</style></head>\n'
        '<body><div class="wrap"><header class="topbar"><div class="brand">'
        'PySIP <span style="font-size:12px;font-weight:normal">Server Portal</span>'
        '</div><div class="subbrand">A little SIP server with a classic web control panel</div></header>'
        '<div class="nav"><a href="/">Sign up</a><a href="/login">Sign in</a>'
        '<a href="/panel">My account</a><a href="/admin">Server admin</a>'
        + nav + '</div>' + body
        + '<div class="footer">PySIP 1.0 &nbsp; | &nbsp; Private network edition &nbsp; | &nbsp; Best viewed with a browser from this century</div>'
        '</div></body></html>'
    )


class PySIPHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 32


class Handler(BaseHTTPRequestHandler):
    server_version = "PySIPWeb/1.0"
    sys_version = ""

    def log_message(self, fmt: str, *args) -> None:
        LOG.info("%s - %s", self.client_address[0], fmt % args)

    def _send(self, status: int, content: str, set_cookie: Optional[str] = None) -> None:
        payload = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        self.end_headers()
        self.wfile.write(payload)

    def _redirect(self, location: str, set_cookie: Optional[str] = None) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        self.end_headers()

    def _get_session(self, create: bool = False) -> Tuple[Optional[dict], Optional[str]]:
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except Exception:
            pass
        morsel = cookie.get("pysip_session")
        token = morsel.value if morsel else ""
        now = int(time.time())
        with SESSION_LOCK:
            session = SESSIONS.get(token)
            if session and session.get("expires", 0) > now:
                return session, None
            if token:
                SESSIONS.pop(token, None)
        if not create:
            return None, None
        token = secrets.token_urlsafe(32)
        session = {"csrf": secrets.token_urlsafe(24), "role": "guest", "expires": now + GUEST_TTL}
        with SESSION_LOCK:
            SESSIONS[token] = session
        return session, f"pysip_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={GUEST_TTL}"

    def _new_admin_session(self) -> str:
        old, _ = self._get_session(False)
        if old:
            remove_sessions(lambda value: value is old)
        token = secrets.token_urlsafe(32)
        with SESSION_LOCK:
            SESSIONS[token] = {"csrf": secrets.token_urlsafe(24), "role": "admin", "expires": int(time.time()) + SESSION_TTL}
        return f"pysip_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}"

    def _new_user_session(self, user_id: int) -> str:
        old, _ = self._get_session(False)
        if old:
            remove_sessions(lambda value: value is old)
        token = secrets.token_urlsafe(32)
        with SESSION_LOCK:
            SESSIONS[token] = {
                "csrf": secrets.token_urlsafe(24), "role": "user", "user_id": int(user_id),
                "expires": int(time.time()) + SESSION_TTL,
            }
        return f"pysip_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}"

    def _form(self) -> Dict[str, str]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length < 0 or length > MAX_BODY:
            raise ValueError("Request body too large")
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        parsed = parse_qs(raw, keep_blank_values=True, max_num_fields=30)
        return {key: values[0] for key, values in parsed.items()}

    def _csrf_ok(self, form: Dict[str, str], session: Optional[dict]) -> bool:
        return bool(session and hmac.compare_digest(form.get("csrf", ""), session.get("csrf", "")))

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        session, cookie = self._get_session(create=path in ("/", "/login", "/admin"))
        if path == "/":
            if session and session.get("role") == "user":
                self._redirect("/panel", cookie)
            else:
                self._send(200, self._signup_page(session, ""), cookie)
            return
        if path == "/login":
            if session and session.get("role") == "user":
                self._redirect("/panel", cookie)
            else:
                self._send(200, self._login_page(session, ""), cookie)
            return
        if path == "/panel":
            if not session or session.get("role") != "user":
                self._redirect("/login", cookie)
            else:
                self._send(200, self._account_page(session, ""), cookie)
            return
        if path == "/admin":
            if not session or session.get("role") != "admin":
                self._send(200, self._admin_login_page(session, ""), cookie)
            else:
                self._send(200, self._admin_page(session, ""), cookie)
            return
        if path == "/health":
            self._send(200, page("Status", '<div class="panel"><div class="panel-title">Server status</div><div class="panel-body">Web panel is running. SIP UDP listener should be started separately.</div></div>'), cookie)
            return
        self._send(404, page("Not found", '<div class="panel"><div class="panel-title">404</div><div class="panel-body">That page does not exist.</div></div>'), cookie)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        try:
            form = self._form()
        except (ValueError, UnicodeError):
            self._send(413, page("Request too large", '<div class="panel"><div class="panel-body">Request was too large.</div></div>'))
            return
        session, _ = self._get_session(False)
        ip = str(self.client_address[0])

        if path == "/signup":
            session, cookie = self._get_session(create=True)
            if not self._csrf_ok(form, session):
                self._send(403, self._signup_page(session, "<div class='note error'>Form expired. Reload and try again.</div>"), cookie)
                return
            if not rate_allowed(ip, "signup", 4, 3600):
                self._send(429, self._signup_page(session, "<div class='note error'>Too many sign-up attempts from this network. Try again later.</div>"), cookie)
                return
            username = form.get("username", "").strip()
            password = form.get("password", "")
            confirm = form.get("confirm", "")
            if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
                message = "Username must be 3-32 characters and use only letters, numbers, dot, underscore or hyphen."
                self._send(400, self._signup_page(session, f'<div class="note error">{html.escape(message)}</div>'), cookie)
                return
            if len(password) < 12 or len(password) > 128:
                self._send(400, self._signup_page(session, '<div class="note error">Password must be 12-128 characters.</div>'), cookie)
                return
            if password != confirm:
                self._send(400, self._signup_page(session, '<div class="note error">The passwords do not match.</div>'), cookie)
                return
            try:
                with db_connect() as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    number = generate_phone_number(conn)
                    cursor = conn.execute(
                        "INSERT INTO users (username, password_hash, sip_ha1, phone_number, enabled, created_at) VALUES (?, ?, ?, ?, 1, ?)",
                        (username, make_password_hash(password), sip_ha1(username, password), number, int(time.time())),
                    )
                    new_user_id = int(cursor.lastrowid)
                    conn.commit()
            except sqlite3.IntegrityError:
                self._send(409, self._signup_page(session, '<div class="note error">That username is already taken.</div>'), cookie)
                return
            new_cookie = self._new_user_session(new_user_id)
            self._redirect("/panel", new_cookie)
            return

        if path == "/login":
            guest, cookie = self._get_session(create=True)
            if not self._csrf_ok(form, guest):
                self._send(403, self._login_page(guest, '<div class="note error">Form expired. Reload and try again.</div>'), cookie)
                return
            if not rate_allowed(ip, "user_login", 8, 300):
                self._send(429, self._login_page(guest, '<div class="note error">Too many login attempts. Wait a few minutes.</div>'), cookie)
                return
            username = form.get("username", "").strip()
            password = form.get("password", "")
            with db_connect() as conn:
                user = conn.execute("SELECT id, password_hash FROM users WHERE username = ? COLLATE NOCASE", (username,)).fetchone()
            if not user or not verify_password_hash(password, str(user["password_hash"])):
                self._send(401, self._login_page(guest, '<div class="note error">Incorrect username or password.</div>'), cookie)
                return
            new_cookie = self._new_user_session(int(user["id"]))
            self._redirect("/panel", new_cookie)
            return

        if path in ("/account/toggle", "/account/new-number", "/account/password", "/account/logout"):
            if not session or session.get("role") != "user":
                self._send(403, page("Forbidden", '<div class="panel"><div class="panel-body">Sign in to manage your account.</div></div>'))
                return
            if not self._csrf_ok(form, session):
                self._send(403, self._account_page(session, '<div class="note error">Security token mismatch. Reload the page.</div>'))
                return
            user_id = int(session["user_id"])
            if path == "/account/logout":
                remove_sessions(lambda value: value is session)
                self._redirect("/login", "pysip_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
                return
            if path == "/account/toggle":
                with db_connect() as conn:
                    user = conn.execute("SELECT enabled FROM users WHERE id = ?", (user_id,)).fetchone()
                    if not user:
                        self._send(404, self._account_page(session, '<div class="note error">Account not found.</div>'))
                        return
                    new_status = 0 if int(user["enabled"]) else 1
                    conn.execute("UPDATE users SET enabled = ? WHERE id = ?", (new_status, user_id))
                    if not new_status:
                        conn.execute("DELETE FROM registrations WHERE user_id = ?", (user_id,))
                        conn.execute("DELETE FROM sip_contacts WHERE user_id = ?", (user_id,))
                status_message = "Your account is now enabled." if new_status else "Your account is disabled. SIP registration has been removed."
                self._send(200, self._account_page(session, f'<div class="note success">{status_message}</div>'))
                return
            if path == "/account/new-number":
                with db_connect() as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    new_number = generate_phone_number(conn)
                    conn.execute("UPDATE users SET phone_number = ? WHERE id = ?", (new_number, user_id))
                    conn.commit()
                self._send(200, self._account_page(session, f'<div class="note success">Your new SIP number is <span class="code">{html.escape(new_number)}</span>.</div>'))
                return
            if path == "/account/password":
                current_password = form.get("current_password", "")
                new_password = form.get("new_password", "")
                confirm_password = form.get("confirm_password", "")
                with db_connect() as conn:
                    user = conn.execute("SELECT username, password_hash FROM users WHERE id = ?", (user_id,)).fetchone()
                    if not user or not verify_password_hash(current_password, str(user["password_hash"])):
                        self._send(400, self._account_page(session, '<div class="note error">Current password is incorrect.</div>'))
                        return
                    if len(new_password) < 12 or len(new_password) > 128:
                        self._send(400, self._account_page(session, '<div class="note error">New password must be 12-128 characters.</div>'))
                        return
                    if new_password != confirm_password:
                        self._send(400, self._account_page(session, '<div class="note error">New passwords do not match.</div>'))
                        return
                    username = str(user["username"])
                    conn.execute("UPDATE users SET password_hash=?, sip_ha1=? WHERE id=?",
                                 (make_password_hash(new_password), sip_ha1(username, new_password), user_id))
                    conn.execute("DELETE FROM registrations WHERE user_id = ?", (user_id,))
                    conn.execute("DELETE FROM sip_contacts WHERE user_id = ?", (user_id,))
                remove_sessions(lambda value: value.get("role") == "user" and value.get("user_id") == user_id)
                new_cookie = self._new_user_session(user_id)
                new_token = new_cookie.split("=", 1)[1].split(";", 1)[0]
                with SESSION_LOCK:
                    new_session = SESSIONS.get(new_token)
                self._send(200, self._account_page(new_session, '<div class="note success">Password changed. Register your SIP app again using the new password.</div>'), new_cookie)
                return

        if path == "/admin/login":
            session, cookie = self._get_session(create=True)
            if not self._csrf_ok(form, session):
                self._send(403, self._admin_login_page(session, '<div class="note error">Form expired. Reload and try again.</div>'), cookie)
                return
            if not rate_allowed(ip, "admin_login", 5, 300):
                self._send(429, self._admin_login_page(session, '<div class="note error">Too many login attempts. Wait five minutes.</div>'), cookie)
                return
            supplied_user = form.get("username", "")
            supplied_password = form.get("password", "")
            valid = hmac.compare_digest(supplied_user, ADMIN_USERNAME) and hmac.compare_digest(supplied_password, ADMIN_PASSWORD or "")
            if not valid:
                self._send(401, self._admin_login_page(session, '<div class="note error">Incorrect administrator credentials.</div>'), cookie)
                return
            new_cookie = self._new_admin_session()
            self._redirect("/admin", new_cookie)
            return

        if path in ("/admin/toggle", "/admin/new-number", "/admin/logout"):
            if not session or session.get("role") != "admin":
                self._send(403, page("Forbidden", '<div class="panel"><div class="panel-body">Administrator login required.</div></div>'))
                return
            if not self._csrf_ok(form, session):
                self._send(403, self._admin_page(session, '<div class="note error">Security token mismatch. Reload the page.</div>'))
                return
            if path == "/admin/logout":
                remove_sessions(lambda value: value is session)
                self._redirect("/admin", "pysip_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
                return
            try:
                user_id = int(form.get("user_id", "0"))
            except ValueError:
                user_id = 0
            with db_connect() as conn:
                user = conn.execute("SELECT id, enabled FROM users WHERE id = ?", (user_id,)).fetchone()
                if not user:
                    message = '<div class="note error">Account not found.</div>'
                elif path == "/admin/toggle":
                    new_status = 0 if int(user["enabled"]) else 1
                    conn.execute("UPDATE users SET enabled = ? WHERE id = ?", (new_status, user_id))
                    if not new_status:
                        conn.execute("DELETE FROM registrations WHERE user_id = ?", (user_id,))
                        conn.execute("DELETE FROM sip_contacts WHERE user_id = ?", (user_id,))
                    message = '<div class="note success">Account status updated.</div>'
                else:
                    conn.execute("BEGIN IMMEDIATE")
                    new_number = generate_phone_number(conn)
                    conn.execute("UPDATE users SET phone_number = ? WHERE id = ?", (new_number, user_id))
                    conn.commit()
                    message = f'<div class="note success">New generated number: <span class="code">{html.escape(new_number)}</span></div>'
            self._send(200, self._admin_page(session, message))
            return

        self._send(404, page("Not found", '<div class="panel"><div class="panel-body">Unknown action.</div></div>'))

    @staticmethod
    def _redirect_page(location: str) -> str:
        safe_location = html.escape(location, quote=True)
        return f'<!doctype html><html><head><meta http-equiv="refresh" content="0;url={safe_location}"></head><body><a href="{safe_location}">Continue</a></body></html>'

    def _signup_page(self, session: Optional[dict], message: str) -> str:
        csrf = html.escape(session["csrf"] if session else "", quote=True)
        body = f"""
<div class="panel"><div class="panel-title">Create a SIP account</div><div class="panel-body">
<p>Create your PySIP account. A phone number is generated automatically; after sign-up you'll enter your personal account panel.</p>
{message}
<form method="post" action="/signup">
<input type="hidden" name="csrf" value="{csrf}">
<label for="username">Account username</label><input id="username" name="username" type="text" minlength="3" maxlength="32" pattern="[A-Za-z0-9_.-]+" required autocomplete="username">
<label for="password">Password</label><input id="password" name="password" type="password" minlength="12" maxlength="128" required autocomplete="new-password">
<label for="confirm">Confirm password</label><input id="confirm" name="confirm" type="password" minlength="12" maxlength="128" required autocomplete="new-password">
<br><button type="submit">Create account</button>
</form>
<div class="note warn"><b>Private-network service:</b> sign up only if the server owner invited you. Do not reuse a password from another site. Already registered? <a href="/login">Sign in here</a>.</div>
</div></div>
<div class="panel"><div class="panel-title">Connection details</div><div class="panel-body">
SIP transport: <b>UDP</b><br>Port: <b>{SIP_PORT}</b><br>Authentication: <b>SIP Digest (MD5)</b><br>Generated number prefix: <b>+190</b><br>
<div class="small">The +190 number is an internal SIP identifier, not a mobile number and not a number that can call the public telephone network.</div>
</div></div>"""
        return page("Sign up", body)

    def _login_page(self, session: Optional[dict], message: str) -> str:
        csrf = html.escape(session["csrf"] if session else "", quote=True)
        body = f"""
<div class="panel"><div class="panel-title">Member sign in</div><div class="panel-body">
{message}
<form method="post" action="/login">
<input type="hidden" name="csrf" value="{csrf}">
<label for="username">Account username</label><input id="username" name="username" type="text" maxlength="32" required autocomplete="username">
<label for="password">Account password</label><input id="password" name="password" type="password" required autocomplete="current-password">
<br><button type="submit">Sign in</button>
</form>
<p class="small">Use your PySIP account username and website password. Your SIP phone number is not the login name.</p>
</div></div>"""
        return page("Member sign in", body)

    def _account_page(self, session: dict, message: str) -> str:
        user_id = int(session.get("user_id", 0))
        csrf = html.escape(session["csrf"], quote=True)
        with db_connect() as conn:
            user = conn.execute(
                """SELECT u.id, u.username, u.phone_number, u.enabled, u.created_at,
                          r.source_ip, r.source_port, r.expires_at, r.user_agent
                   FROM users u LEFT JOIN registrations r ON r.user_id = u.id WHERE u.id = ?""",
                (user_id,),
            ).fetchone()
            calls = conn.execute(
                """SELECT * FROM calls WHERE caller_username = ? OR callee_username = ?
                   ORDER BY updated_at DESC LIMIT 30""",
                (str(user["username"]) if user else "", str(user["username"]) if user else ""),
            ).fetchall()
            devices = conn.execute(
                """SELECT contact_uri, source_ip, source_port, user_agent, expires_at, updated_at
                   FROM sip_contacts WHERE user_id = ? AND expires_at > ?
                   ORDER BY updated_at DESC LIMIT 16""",
                (user_id, int(time.time())),
            ).fetchall()
        if not user:
            return page("Account", '<div class="panel"><div class="panel-body">Account not found. Please sign in again.</div></div>')
        enabled = bool(int(user["enabled"]))
        state_html = '<span class="status-on">ENABLED</span>' if enabled else '<span class="status-off">DISABLED</span>'
        registered = f"{len(devices)} device(s) currently registered" if devices else "Not currently registered in a SIP app"
        device_rows = []
        for device in devices:
            expiry = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(device["expires_at"])))
            device_rows.append(
                f'<tr><td>{html.escape(str(device["source_ip"]))}:{int(device["source_port"])}</td>'
                f'<td>{html.escape(str(device["user_agent"])[:80] or "Unknown")}</td>'
                f'<td>{html.escape(expiry)}</td></tr>'
            )
        devices_table = "".join(device_rows) or '<tr><td colspan="3">No active devices.</td></tr>' 
        action = "Disable account" if enabled else "Enable account"
        action_class = "danger" if enabled else ""
        number = html.escape(str(user["phone_number"]))
        call_rows = []
        for call in calls:
            outgoing = str(call["caller_username"]).lower() == str(user["username"]).lower()
            other_name = str(call["callee_username"] if outgoing else call["caller_username"])
            other_number = str(call["callee_number"] if outgoing else call["caller_number"])
            direction = "Outgoing" if outgoing else "Incoming"
            state = str(call["state"])
            color = "call-active" if state in ("answered", "ringing", "trying", "cancelling", "ending") else ("call-good" if state == "ended" else "call-bad")
            when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(call["updated_at"])))
            call_rows.append(
                f'<tr><td>{direction}</td><td><b>{html.escape(other_name)}</b><br><span class="small">{html.escape(other_number)}</span></td>'
                f'<td><span class="call-state {color}">{html.escape(state.upper())}</span></td>'
                f'<td>{int(call["sip_code"] or 0) or "-"}</td><td>{html.escape(when)}</td></tr>'
            )
        calls_table = "".join(call_rows) or '<tr><td colspan="5">No calls recorded for your account yet.</td></tr>'
        body = f"""
<div class="panel"><div class="panel-title">My PySIP account</div><div class="panel-body">
{message}
<div class="cols"><div>
<p><b>Username</b><br><span class="code">{html.escape(str(user['username']))}</span></p>
<p><b>Your generated SIP number</b><br><span class="code" style="font-size:18px">{number}</span></p>
<p><b>Account status</b><br>{state_html}</p>
<p><b>SIP registration</b><br>{registered}</p>
</div><div>
<div class="note"><b>SIP client settings</b><br>Username: <span class="code">{html.escape(str(user['username']))}</span><br>Auth username: <span class="code">{html.escape(str(user['username']))}</span><br>Domain / realm: <span class="code">{html.escape(SIP_REALM)}</span><br>Server: <span class="code">{html.escape(current_advertised_host())}</span><br>Port: <b>{SIP_PORT} / UDP</b><br>Audio: <b>RTP/RTCP UDP {RTP_PORT_MIN}-{RTP_PORT_MAX}</b><br>Transport: <b>UDP</b><br>Dial friends using their generated +190 number.</div>
</div></div>
<div class="panel"><div class="panel-title">Registered devices</div><div class="panel-body"><table><thead><tr><th>Network endpoint</th><th>Client</th><th>Expires</th></tr></thead><tbody>{devices_table}</tbody></table></div></div>
<form method="post" action="/account/toggle"><input type="hidden" name="csrf" value="{csrf}"><button class="{action_class}" type="submit">{action}</button></form>
<form method="post" action="/account/new-number" ><input type="hidden" name="csrf" value="{csrf}"><button type="submit">Generate new phone number</button></form>
<form method="post" action="/account/logout"><input type="hidden" name="csrf" value="{csrf}"><button type="submit">Sign out</button></form>
</div></div>
<div class="panel"><div class="panel-title">Change account password</div><div class="panel-body">
<p>Changing this password also changes your SIP authentication password and unregisters your current SIP client.</p>
<form method="post" action="/account/password"><input type="hidden" name="csrf" value="{csrf}">
<label for="current_password">Current password</label><input id="current_password" name="current_password" type="password" required autocomplete="current-password">
<label for="new_password">New password</label><input id="new_password" name="new_password" type="password" minlength="12" maxlength="128" required autocomplete="new-password">
<label for="confirm_password">Confirm new password</label><input id="confirm_password" name="confirm_password" type="password" minlength="12" maxlength="128" required autocomplete="new-password">
<br><button type="submit">Change password</button></form>
</div></div>
<div class="panel"><div class="panel-title">My call history</div><div class="panel-body">
<p>Latest 30 calls involving your account. Refresh this page to update.</p>
<table><thead><tr><th>Direction</th><th>Other party</th><th>Status</th><th>SIP</th><th>Updated</th></tr></thead><tbody>{calls_table}</tbody></table>
</div></div>
<div class="panel"><div class="panel-title">A note about your number</div><div class="panel-body">Your generated +190 number is an internal PySIP extension. Calling it routes to your account; it is not a mobile/PSTN number and cannot receive ordinary cellular calls.</div></div>"""
        return page("My account", body)

    def _admin_login_page(self, session: Optional[dict], message: str) -> str:
        csrf = html.escape(session["csrf"] if session else "", quote=True)
        body = f"""
<div class="panel"><div class="panel-title">Administrator sign in</div><div class="panel-body">
{message}
<form method="post" action="/admin/login">
<input type="hidden" name="csrf" value="{csrf}">
<label for="username">Administrator username</label><input id="username" name="username" type="text" required autocomplete="username" value="{html.escape(ADMIN_USERNAME, quote=True)}">
<label for="password">Administrator password</label><input id="password" name="password" type="password" required autocomplete="current-password">
<br><button type="submit">Sign in</button>
</form>
<p class="small">The administrator password is printed in the web panel terminal at first startup unless PYSIP_ADMIN_PASSWORD is set.</p>
</div></div>"""
        return page("Administrator login", body)

    def _admin_page(self, session: dict, message: str) -> str:
        csrf = html.escape(session["csrf"], quote=True)
        with db_connect() as conn:
            users = conn.execute(
                """SELECT u.id, u.username, u.phone_number, u.enabled, u.created_at,
                          r.source_ip, r.source_port, r.expires_at,
                          (SELECT COUNT(*) FROM sip_contacts c WHERE c.user_id=u.id AND c.expires_at > ?) AS device_count
                   FROM users u LEFT JOIN registrations r ON r.user_id = u.id
                   ORDER BY u.id""", (int(time.time()),)
            ).fetchall()
            calls = conn.execute("SELECT * FROM calls ORDER BY updated_at DESC LIMIT 40").fetchall()
        rows = []
        now = int(time.time())
        for user in users:
            enabled = int(user["enabled"])
            status = '<span class="status-on">ENABLED</span>' if enabled else '<span class="status-off">DISABLED</span>'
            registered = f"{int(user['device_count'] or 0)} active device(s)"
            uid = int(user["id"])
            toggle_label = "Disable" if enabled else "Enable"
            toggle_class = "danger" if enabled else ""
            rows.append(f"""
<tr><td>{uid}</td><td><b>{html.escape(str(user['username']))}</b></td><td><span class="code">{html.escape(str(user['phone_number']))}</span></td><td>{status}</td><td>{html.escape(registered)}</td><td>
<form style="display:inline" method="post" action="/admin/toggle"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="user_id" value="{uid}"><button class="{toggle_class}" type="submit">{toggle_label}</button></form>
<form style="display:inline" method="post" action="/admin/new-number"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="user_id" value="{uid}"><button type="submit">Generate new number</button></form>
</td></tr>""")
        table = "".join(rows) or '<tr><td colspan="6">No accounts created yet.</td></tr>'

        call_rows = []
        for call in calls:
            state = str(call["state"])
            if state in ("answered", "ringing", "trying", "early", "cancelling", "ending"):
                state_class = "call-active"
            elif state in ("ended",):
                state_class = "call-good"
            else:
                state_class = "call-bad"
            code = int(call["sip_code"] or 0)
            code_label = str(code) if code else "-"
            updated = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(call["updated_at"])))
            call_rows.append(
                f'<tr><td>{html.escape(str(call["caller_username"]))} '
                f'<span class="small">({html.escape(str(call["caller_number"]))})</span></td>'
                f'<td>{html.escape(str(call["callee_username"]))} '
                f'<span class="small">({html.escape(str(call["callee_number"]))})</span></td>'
                f'<td><span class="call-state {state_class}">{html.escape(state.upper())}</span></td>'
                f'<td>{code_label}</td><td>{html.escape(updated)}</td>'
                f'<td>{html.escape(str(call["detail"]))}</td></tr>'
            )
        calls_table = "".join(call_rows) or '<tr><td colspan="6">No calls yet.</td></tr>'
        body = f"""
<div class="panel"><div class="panel-title">Server administrator</div><div class="panel-body">
{message}
<p>Manage account access and generated SIP numbers. Disabling an account removes every active device registration.</p>
<div class="note"><b>SIP endpoint:</b> <span class="code">{html.escape(current_advertised_host())}:{SIP_PORT}/UDP</span> &nbsp; <b>Realm:</b> <span class="code">{html.escape(SIP_REALM)}</span></div>
<table><thead><tr><th>ID</th><th>Username</th><th>Phone number</th><th>Status</th><th>Devices</th><th>Actions</th></tr></thead><tbody>{table}</tbody></table>
<form method="post" action="/admin/logout"><input type="hidden" name="csrf" value="{csrf}"><button type="submit">Sign out</button></form>
</div></div>
<div class="panel"><div class="panel-title">Call monitor</div><div class="panel-body">
<p>Latest 40 calls. Refresh this page to update the list. Answering and declining happen in the registered SIP phone app, not in this monitor.</p>
<table><thead><tr><th>From</th><th>To</th><th>State</th><th>SIP</th><th>Updated</th><th>Details</th></tr></thead><tbody>{calls_table}</tbody></table>
<div class="note">Audio relay: RTP and RTCP packets are forwarded unchanged through the server. UDP media range: <b>{RTP_PORT_MIN}-{RTP_PORT_MAX}</b>. No recording or transcoding is performed.</div>
</div></div>
<div class="panel"><div class="panel-title">Server notes</div><div class="panel-body">
<ul><li>REGISTER and OPTIONS are handled locally. INVITE, ACK, CANCEL, BYE, PRACK, UPDATE, INFO, REFER, MESSAGE, SUBSCRIBE, NOTIFY and PUBLISH are routed to registered endpoints where applicable.</li><li>Multiple device contacts can register to one account; incoming INVITEs ring registered devices and the first 2xx answer wins.</li><li>One IPv4 audio m-line with RTP/RTCP relay is supported on UDP {RTP_PORT_MIN}-{RTP_PORT_MAX}; no video, transcoding, voicemail, conference calling, presence service or PSTN connectivity.</li><li>Generated +190 numbers are internal SIP identifiers only.</li><li>This panel is plain HTTP. It binds to 127.0.0.1 by default; only expose it on a trusted VPN/private network.</li></ul>
</div></div>"""
        return page("Control panel", body)



def main() -> None:
    ensure_schema()
    server = PySIPHTTPServer((WEB_HOST, WEB_PORT), Handler)
    server.timeout = 0.5
    LOG.info("Web panel listening on http://%s:%s", WEB_HOST, WEB_PORT)
    LOG.warning("Keep this HTTP panel on a trusted VPN/private network; it has no TLS.")
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        LOG.info("Stopping web panel")
    finally:
        server.server_close()


if __name__ == "__main__":
    try:
        main()
    except OSError as exc:
        LOG.error("Could not bind %s:%s: %s", WEB_HOST, WEB_PORT, exc)
        raise SystemExit(1)
