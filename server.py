#!/usr/bin/env python3
"""Tulika - a zero-dependency web service (Python standard library only).

Everything below is written by hand on top of raw sockets:
  1. HTTP request parsing (request line, headers, JSON and form bodies)
  2. A router with path parameters, 404 and 405 (with Allow header)
  3. Sessions: scrypt password hashing + random bearer/cookie tokens
  4. Persistence: JSON file with atomic, fsync'd writes
  5. Token-bucket rate limiting, path-traversal and body-size protection
"""
import hashlib
import hmac
import json
import math
import mimetypes
import os
import re
import secrets
import socket
import socketserver
import sys
import tempfile
import threading
import time
import traceback
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DATA_FILE = Path(os.environ.get("DATA_FILE", BASE_DIR / "data" / "db.json"))
TRUST_PROXY = os.environ.get("TRUST_PROXY") == "1"  # only behind a proxy you control

MAX_REQUEST_LINE = 4096
MAX_HEADER_BYTES = 16 * 1024
MAX_HEADERS = 64
MAX_BODY = 64 * 1024
MAX_STATIC = 2 * 1024 * 1024
SOCKET_TIMEOUT = 10
MAX_CONNECTIONS = 100
SESSION_TTL = 24 * 3600
MAX_TASKS_PER_USER = 500
SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1, "dklen": 32}

REASONS = {
    200: "OK", 201: "Created", 204: "No Content", 400: "Bad Request",
    401: "Unauthorized", 404: "Not Found", 405: "Method Not Allowed",
    408: "Request Timeout", 409: "Conflict", 413: "Payload Too Large",
    414: "URI Too Long", 415: "Unsupported Media Type", 429: "Too Many Requests",
    431: "Request Header Fields Too Large", 500: "Internal Server Error",
    501: "Not Implemented", 503: "Service Unavailable", 505: "HTTP Version Not Supported",
}


class HttpError(Exception):
    def __init__(self, status, message, headers=None):
        super().__init__(message)
        self.status, self.message, self.headers = status, message, headers or {}


class Response:
    def __init__(self, status=200, body=b"", headers=None):
        self.status, self.body, self.headers = status, body, headers or {}


def json_response(obj, status=200, headers=None):
    h = {"Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store"}
    h.update(headers or {})
    return Response(status, json.dumps(obj).encode("utf-8"), h)


def log(*a):
    print(*a, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------
# 1. Request parsing
# --------------------------------------------------------------------------
_PCT = re.compile(rb"%([0-9A-Fa-f]{2})")


def pct_decode(s, plus=False):
    if plus:
        s = s.replace("+", " ")
    raw = _PCT.sub(lambda m: bytes([int(m.group(1), 16)]), s.encode("utf-8"))
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise HttpError(400, "invalid percent-encoding")


def parse_query(qs):
    out = {}
    for i, pair in enumerate(qs.split("&")):
        if not pair:
            continue
        if i >= 100:
            raise HttpError(400, "too many parameters")
        k, _, v = pair.partition("=")
        out[pct_decode(k, plus=True)] = pct_decode(v, plus=True)
    return out


class Request:
    def __init__(self, method, path, query, headers, body, ip):
        self.method, self.path, self.query = method, path, query
        self.headers, self.body, self.ip = headers, body, ip
        self.params, self.user, self.token_hash = {}, None, None

    def data(self):
        """Body as a dict, from JSON or urlencoded form."""
        if not self.body:
            return {}
        ctype = self.headers.get("content-type", "").split(";")[0].strip().lower()
        if ctype == "application/json":
            try:
                obj = json.loads(self.body.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                raise HttpError(400, "invalid JSON body")
            if not isinstance(obj, dict):
                raise HttpError(400, "JSON body must be an object")
            return obj
        if ctype == "application/x-www-form-urlencoded":
            return parse_query(self.body.decode("utf-8", errors="replace"))
        raise HttpError(415, "use application/json or application/x-www-form-urlencoded")


def read_request(conn, rfile, ip):
    line = rfile.readline(MAX_REQUEST_LINE + 1)
    if not line:
        return None
    if len(line) > MAX_REQUEST_LINE:
        raise HttpError(414, "request line too long")
    try:
        method, target, version = line.decode("ascii").strip().split(" ")
    except (UnicodeDecodeError, ValueError):
        raise HttpError(400, "malformed request line")
    if version not in ("HTTP/1.0", "HTTP/1.1"):
        raise HttpError(505, "unsupported HTTP version")
    if not method.isalpha() or not method.isupper():
        raise HttpError(400, "bad method")

    headers, total = {}, 0
    while True:
        h = rfile.readline(MAX_REQUEST_LINE + 1)
        total += len(h)
        if len(h) > MAX_REQUEST_LINE or total > MAX_HEADER_BYTES:
            raise HttpError(431, "headers too large")
        if not h:
            raise HttpError(400, "unexpected end of headers")
        if h in (b"\r\n", b"\n"):
            break
        name, sep, value = h.decode("latin-1").rstrip("\r\n").partition(":")
        if not sep or not name or name != name.strip():
            raise HttpError(400, "malformed header")
        name = name.lower()
        if name not in headers and len(headers) >= MAX_HEADERS:
            raise HttpError(431, "too many headers")
        value = value.strip()
        headers[name] = headers[name] + ", " + value if name in headers else value

    if "transfer-encoding" in headers:
        raise HttpError(501, "Transfer-Encoding is not supported; send Content-Length")
    body = b""
    cl = headers.get("content-length")
    if cl is not None:
        if not re.fullmatch(r"[0-9]{1,10}", cl):
            raise HttpError(400, "bad Content-Length")
        n = int(cl)
        if n > MAX_BODY:
            raise HttpError(413, "body too large (max %d bytes)" % MAX_BODY)
        if n and headers.get("expect", "").lower() == "100-continue":
            conn.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
        body = rfile.read(n)
        if len(body) != n:
            raise HttpError(400, "body shorter than Content-Length")

    path_raw, _, qs = target.partition("?")
    if not path_raw.startswith("/"):
        raise HttpError(400, "bad request target")
    path = pct_decode(path_raw)
    if "\x00" in path:
        raise HttpError(400, "bad path")
    return Request(method, path, parse_query(qs), headers, body, ip)


# --------------------------------------------------------------------------
# 4. Persistence (atomic JSON file)
# --------------------------------------------------------------------------
class Store:
    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.RLock()
        self.data = {"users": {}, "sessions": {}, "tasks": {}, "next_task_id": 1}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            try:
                loaded = json.loads(self.path.read_text("utf-8"))
                if not all(k in loaded for k in self.data):
                    raise ValueError("missing keys")
                self.data = loaded
            except (ValueError, OSError):
                bad = self.path.with_name(self.path.name + ".corrupt-%d" % int(time.time()))
                os.replace(self.path, bad)
                log("db unreadable; moved to", bad)

    def save(self):
        """Caller must hold self.lock. Write temp file, fsync, atomic rename."""
        payload = json.dumps(self.data, separators=(",", ":")).encode("utf-8")
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".db-", suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        try:  # make the rename itself durable (not possible on Windows)
            dfd = os.open(self.path.parent, os.O_RDONLY)
            os.fsync(dfd)
            os.close(dfd)
        except OSError:
            pass


STORE = None


# --------------------------------------------------------------------------
# 5. Rate limiting (token bucket per key)
# --------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, capacity, per_seconds):
        self.capacity, self.rate = capacity, capacity / per_seconds
        self.buckets, self.lock, self.last_sweep = {}, threading.Lock(), time.monotonic()

    def check(self, key):
        """Return (allowed, retry_after_seconds)."""
        now = time.monotonic()
        with self.lock:
            if now - self.last_sweep > 60:  # drop idle, fully refilled buckets
                idle = self.capacity / self.rate
                self.buckets = {k: v for k, v in self.buckets.items() if now - v[1] < idle}
                self.last_sweep = now
            tokens, ts = self.buckets.get(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - ts) * self.rate)
            if tokens >= 1:
                self.buckets[key] = (tokens - 1, now)
                return True, 0
            self.buckets[key] = (tokens, now)
            return False, math.ceil((1 - tokens) / self.rate)


LIMITERS = {
    "global": RateLimiter(120, 60),  # 120 requests/minute per IP
    "auth": RateLimiter(5, 60),      # 5 login/register attempts/minute per IP
}


# --------------------------------------------------------------------------
# 3. Passwords and sessions
# --------------------------------------------------------------------------
def hash_password(password, salt=None, params=None):
    params = params or SCRYPT
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, **params)
    return {"salt": salt.hex(), "hash": dk.hex(), "params": params}


def verify_password(password, rec):
    dk = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(rec["salt"]), **rec["params"])
    return hmac.compare_digest(dk.hex(), rec["hash"])


DUMMY_RECORD = hash_password("not-a-real-password")  # equalises timing for unknown users
USERNAME_RE = re.compile(r"[A-Za-z0-9_]{3,32}")


def sha(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def authenticate(req):
    token = None
    auth = req.headers.get("authorization", "")
    if auth[:7].lower() == "bearer ":
        token = auth[7:].strip()
    else:
        for part in req.headers.get("cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "session":
                token = v
    if not token:
        return None
    h = sha(token)
    with STORE.lock:
        s = STORE.data["sessions"].get(h)
        if not s or s["exp"] < time.time():
            return None
        req.token_hash = h
        return s["user"]


# --------------------------------------------------------------------------
# 2. Router
# --------------------------------------------------------------------------
ROUTES = []


def route(method, pattern, limit=None, auth=False):
    def conv(m):
        kind, name = m.group(1), m.group(2)
        if kind == "int":
            return "(?P<%s>[0-9]{1,9})" % name
        if kind == "path":
            return "(?P<%s>.+)" % name
        return "(?P<%s>[^/]+)" % name

    regex = re.compile("^" + re.sub(r"<(?:(int|path):)?(\w+)>", conv, pattern) + "$")

    def deco(fn):
        ROUTES.append((method, regex, fn, limit, auth))
        return fn
    return deco


def dispatch(req):
    allowed = []
    for method, regex, fn, limit, auth in ROUTES:
        m = regex.match(req.path)
        if not m:
            continue
        if method != req.method:
            allowed.append(method)
            continue
        req.params = m.groupdict()
        if limit:
            ok, wait = LIMITERS[limit].check(req.ip)
            if not ok:
                raise HttpError(429, "too many attempts", {"Retry-After": str(wait)})
        if auth:
            req.user = authenticate(req)
            if not req.user:
                raise HttpError(401, "authentication required", {"WWW-Authenticate": "Bearer"})
        return fn(req)
    if allowed:
        raise HttpError(405, "method not allowed", {"Allow": ", ".join(sorted(set(allowed)))})
    raise HttpError(404, "not found")


# --------------------------------------------------------------------------
# Handlers
# --------------------------------------------------------------------------
@route("GET", "/api/health")
def health(req):
    return json_response({"status": "ok"})


@route("POST", "/api/register", limit="auth")
def register(req):
    d = req.data()
    username, password = d.get("username"), d.get("password")
    if not isinstance(username, str) or not USERNAME_RE.fullmatch(username):
        raise HttpError(400, "username must be 3-32 characters: letters, digits, underscore")
    if not isinstance(password, str) or not 8 <= len(password) <= 128:
        raise HttpError(400, "password must be 8-128 characters")
    rec = hash_password(password)  # slow on purpose, so done outside the lock
    rec.update(username=username, created=int(time.time()))
    with STORE.lock:
        if username.lower() in STORE.data["users"]:
            raise HttpError(409, "username already taken")
        STORE.data["users"][username.lower()] = rec
        STORE.save()
    return json_response({"username": username}, 201)


@route("POST", "/api/login", limit="auth")
def login(req):
    d = req.data()
    username, password = d.get("username"), d.get("password")
    if not isinstance(username, str) or not isinstance(password, str) or len(password) > 128:
        raise HttpError(400, "username and password are required")
    with STORE.lock:
        rec = STORE.data["users"].get(username.lower())
    ok = verify_password(password, rec or DUMMY_RECORD) and rec is not None
    if not ok:
        raise HttpError(401, "invalid username or password")
    token = secrets.token_urlsafe(32)
    now = time.time()
    with STORE.lock:
        sessions = STORE.data["sessions"]
        for k in [k for k, s in sessions.items() if s["exp"] < now]:
            del sessions[k]
        sessions[sha(token)] = {"user": rec["username"], "exp": now + SESSION_TTL}
        STORE.save()
    cookie = "session=%s; HttpOnly; SameSite=Strict; Path=/; Max-Age=%d" % (token, SESSION_TTL)
    if TRUST_PROXY and req.headers.get("x-forwarded-proto") == "https":
        cookie += "; Secure"
    return json_response({"username": rec["username"], "token": token, "expires_in": SESSION_TTL},
                         headers={"Set-Cookie": cookie})


@route("POST", "/api/logout", auth=True)
def logout(req):
    with STORE.lock:
        STORE.data["sessions"].pop(req.token_hash, None)
        STORE.save()
    return json_response({"ok": True}, headers={"Set-Cookie": "session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"})


@route("GET", "/api/me", auth=True)
def me(req):
    return json_response({"username": req.user})


def valid_title(t):
    if not isinstance(t, str) or not 1 <= len(t.strip()) <= 200:
        raise HttpError(400, "title must be 1-200 characters")
    return t.strip()


def to_bool(v):
    if isinstance(v, bool):
        return v
    if isinstance(v, str) and v.lower() in ("true", "false", "on", "1", "0"):
        return v.lower() in ("true", "on", "1")
    raise HttpError(400, "done must be true or false")


def mine(req, task_id):
    t = STORE.data["tasks"].get(str(task_id))
    if not t or t["owner"] != req.user:
        raise HttpError(404, "task not found")  # 404, not 403: don't reveal other users' ids
    return t


@route("GET", "/api/tasks", auth=True)
def list_tasks(req):
    with STORE.lock:
        items = [t for t in STORE.data["tasks"].values() if t["owner"] == req.user]
    if "done" in req.query:
        want = to_bool(req.query["done"])
        items = [t for t in items if t["done"] == want]
    if req.query.get("q"):
        items = [t for t in items if req.query["q"].lower() in t["title"].lower()]
    items.sort(key=lambda t: t["id"])
    return json_response({"tasks": items, "count": len(items)})


@route("POST", "/api/tasks", auth=True)
def create_task(req):
    d = req.data()
    title = valid_title(d.get("title"))
    done = to_bool(d["done"]) if "done" in d else False
    with STORE.lock:
        if sum(1 for t in STORE.data["tasks"].values() if t["owner"] == req.user) >= MAX_TASKS_PER_USER:
            raise HttpError(409, "task limit reached")
        tid = STORE.data["next_task_id"]
        STORE.data["next_task_id"] = tid + 1
        task = {"id": tid, "owner": req.user, "title": title, "done": done, "created": int(time.time())}
        STORE.data["tasks"][str(tid)] = task
        STORE.save()
    return json_response(task, 201, {"Location": "/api/tasks/%d" % tid})


@route("GET", "/api/tasks/<int:id>", auth=True)
def get_task(req):
    with STORE.lock:
        return json_response(mine(req, req.params["id"]))


def update_task(req):
    d = req.data()
    with STORE.lock:
        t = mine(req, req.params["id"])
        if "title" in d:
            t["title"] = valid_title(d["title"])
        if "done" in d:
            t["done"] = to_bool(d["done"])
        STORE.save()
        return json_response(t)


route("PUT", "/api/tasks/<int:id>", auth=True)(update_task)
route("PATCH", "/api/tasks/<int:id>", auth=True)(update_task)


@route("DELETE", "/api/tasks/<int:id>", auth=True)
def delete_task(req):
    with STORE.lock:
        mine(req, req.params["id"])
        del STORE.data["tasks"][str(req.params["id"])]
        STORE.save()
    return Response(204)


def serve_static(rel):
    target = (STATIC_DIR / rel).resolve()  # resolves "..", symlinks and absolute-path tricks
    if "\\" in rel or not target.is_relative_to(STATIC_DIR) or not target.is_file():
        raise HttpError(404, "not found")
    if target.stat().st_size > MAX_STATIC:
        raise HttpError(404, "not found")
    ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
    if ctype.startswith("text/") or ctype in ("application/javascript", "application/json"):
        ctype += "; charset=utf-8"
    return Response(200, target.read_bytes(), {"Content-Type": ctype})


@route("GET", "/")
def index(req):
    return serve_static("index.html")


@route("GET", "/static/<path:rest>")
def static_file(req):
    return serve_static(req.params["rest"])


# --------------------------------------------------------------------------
# Connection handling
# --------------------------------------------------------------------------
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
}


def send(conn, resp):
    headers = {"Content-Length": str(len(resp.body)), "Connection": "close", **SECURITY_HEADERS, **resp.headers}
    lines = ["HTTP/1.1 %d %s" % (resp.status, REASONS.get(resp.status, "Unknown"))]
    for k, v in headers.items():
        if "\r" in v or "\n" in v:
            raise ValueError("header injection attempt")
        lines.append("%s: %s" % (k, v))
    conn.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + resp.body)


def error_response(e):
    return json_response({"error": e.message}, e.status, e.headers)


def client_ip(req, peer):
    if TRUST_PROXY:
        xff = req.headers.get("x-forwarded-for", "")
        if xff:
            return xff.split(",")[-1].strip()  # the entry our own proxy appended
    return peer


CONN_SLOTS = threading.BoundedSemaphore(MAX_CONNECTIONS)


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        conn, peer = self.request, self.client_address[0]
        if not CONN_SLOTS.acquire(blocking=False):
            try:
                send(conn, error_response(HttpError(503, "server busy")))
            except OSError:
                pass
            return
        start, method, path, status, rfile = time.monotonic(), "-", "-", 500, None
        try:
            conn.settimeout(SOCKET_TIMEOUT)
            rfile = conn.makefile("rb")
            try:
                req = read_request(conn, rfile, peer)
                if req is None:
                    return
                method, path = req.method, req.path
                req.ip = client_ip(req, peer)
                ok, wait = LIMITERS["global"].check(req.ip)
                if not ok:
                    raise HttpError(429, "rate limit exceeded", {"Retry-After": str(wait)})
                resp = dispatch(req)
            except HttpError as e:
                resp = error_response(e)
            except socket.timeout:
                resp = error_response(HttpError(408, "request timed out"))
            except OSError:
                return
            except Exception:
                log(traceback.format_exc())
                resp = error_response(HttpError(500, "internal server error"))
            status = resp.status
            try:
                send(conn, resp)
            except OSError:
                pass
        finally:
            CONN_SLOTS.release()
            if rfile:
                rfile.close()
            if method != "-":
                log("%s %s %s -> %d (%.0f ms)" % (peer, method, path, status, (time.monotonic() - start) * 1000))


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 64


def init_store(path=None):
    global STORE
    STORE = Store(path or DATA_FILE)
    return STORE


def main():
    init_store()
    host, port = os.environ.get("HOST", "0.0.0.0"), int(os.environ.get("PORT", "8000"))
    with Server((host, port), Handler) as srv:
        log("Tulika listening on http://%s:%d  (data: %s)" % (host, port, DATA_FILE))
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            log("bye")


if __name__ == "__main__":
    main()
