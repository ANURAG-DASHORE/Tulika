"""Run with:  python3 test_server.py   (standard library only)"""
import http.client
import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

import server


def request(port, method, path, body=None, headers=None, raw_body=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    h = dict(headers or {})
    if body is not None:
        raw_body = json.dumps(body)
        h.setdefault("Content-Type", "application/json")
    c.request(method, path, body=raw_body, headers=h)
    r = c.getresponse()
    data = r.read()
    c.close()
    try:
        return r.status, json.loads(data) if data else None, r
    except ValueError:
        return r.status, data, r


def raw(port, payload):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(payload)
    out = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        out += chunk
    s.close()
    return out


class ServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = os.path.join(cls.tmp.name, "db.json")
        server.init_store(cls.db)
        server.LIMITERS["global"] = server.RateLimiter(100000, 60)
        server.LIMITERS["auth"] = server.RateLimiter(100000, 60)
        cls.srv = server.Server(("127.0.0.1", 0), server.Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        request(cls.port, "POST", "/api/register", {"username": "alice", "password": "correct horse"})
        _, d, _ = request(cls.port, "POST", "/api/login", {"username": "alice", "password": "correct horse"})
        cls.tok = {"Authorization": "Bearer " + d["token"]}

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.tmp.cleanup()

    # --- router ---------------------------------------------------------
    def test_health(self):
        s, d, _ = request(self.port, "GET", "/api/health")
        self.assertEqual((s, d), (200, {"status": "ok"}))

    def test_404(self):
        self.assertEqual(request(self.port, "GET", "/api/nope")[0], 404)

    def test_405_has_allow_header(self):
        s, _, r = request(self.port, "DELETE", "/api/health")
        self.assertEqual(s, 405)
        self.assertEqual(r.getheader("Allow"), "GET")
        s, _, r = request(self.port, "POST", "/api/tasks/1", {}, self.tok)
        self.assertEqual(s, 405)
        self.assertIn("DELETE", r.getheader("Allow"))

    def test_path_param_must_be_int(self):
        self.assertEqual(request(self.port, "GET", "/api/tasks/abc", headers=self.tok)[0], 404)

    # --- parsing --------------------------------------------------------
    def test_invalid_json_400(self):
        s, _, _ = request(self.port, "POST", "/api/tasks", raw_body="{bad", headers={**self.tok, "Content-Type": "application/json"})
        self.assertEqual(s, 400)

    def test_json_must_be_object(self):
        s, _, _ = request(self.port, "POST", "/api/tasks", raw_body="[1]", headers={**self.tok, "Content-Type": "application/json"})
        self.assertEqual(s, 400)

    def test_unsupported_media_type_415(self):
        s, _, _ = request(self.port, "POST", "/api/tasks", raw_body="title=x", headers={**self.tok, "Content-Type": "text/plain"})
        self.assertEqual(s, 415)

    def test_form_body_with_percent_and_plus(self):
        s, d, _ = request(self.port, "POST", "/api/tasks", raw_body="title=Buy+milk%21+%E2%9C%93",
                          headers={**self.tok, "Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(s, 201)
        self.assertEqual(d["title"], "Buy milk! \u2713")

    def test_query_parsing_filters(self):
        request(self.port, "POST", "/api/tasks", {"title": "findme-xyz", "done": True}, self.tok)
        s, d, _ = request(self.port, "GET", "/api/tasks?q=FINDME-XYZ&done=true", headers=self.tok)
        self.assertEqual(s, 200)
        self.assertTrue(d["count"] >= 1 and all(t["done"] for t in d["tasks"]))

    # --- limits and security -------------------------------------------
    def test_oversized_body_413(self):
        s, _, _ = request(self.port, "POST", "/api/tasks", raw_body="x" * (server.MAX_BODY + 1), headers={**self.tok, "Content-Type": "application/json"})
        self.assertEqual(s, 413)

    def test_oversized_body_rejected_before_reading(self):
        out = raw(self.port, b"POST /api/tasks HTTP/1.1\r\nContent-Length: 999999999\r\n\r\n")
        self.assertTrue(out.startswith(b"HTTP/1.1 413"))

    def test_request_line_too_long_414(self):
        out = raw(self.port, b"GET /" + b"a" * 5000 + b" HTTP/1.1\r\n\r\n")
        self.assertTrue(out.startswith(b"HTTP/1.1 414"))

    def test_headers_too_large_431(self):
        hdrs = b"".join(b"X-%d: %s\r\n" % (i, b"v" * 500) for i in range(40))
        out = raw(self.port, b"GET /api/health HTTP/1.1\r\n" + hdrs + b"\r\n")
        self.assertTrue(out.startswith(b"HTTP/1.1 431"))

    def test_malformed_request_400(self):
        self.assertTrue(raw(self.port, b"garbage\r\n\r\n").startswith(b"HTTP/1.1 400"))

    # --- chunked request bodies ----------------------------------------
    def chunked(self, chunks, extra=b""):
        body = b"".join(b"%x\r\n%s\r\n" % (len(c), c) for c in chunks) + b"0\r\n\r\n"
        auth = self.tok["Authorization"].encode()
        head = (b"POST /api/tasks HTTP/1.1\r\nAuthorization: " + auth +
                b"\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n"
                b"Connection: close\r\n" + extra + b"\r\n")
        return raw(self.port, head + body)

    def test_chunked_body_is_reassembled(self):
        out = self.chunked([b'{"title":', b'"chunk', b'ed task"}'])
        self.assertTrue(out.startswith(b"HTTP/1.1 201"))
        self.assertIn(b"chunked task", out)

    def test_chunked_with_extension_and_trailer(self):
        body = b'5;ext=1\r\n{"tit\r\n' + b'0f\r\nle":"trailers"}\r\n' + b"0\r\nX-Trailer: ignored\r\n\r\n"
        auth = self.tok["Authorization"].encode()
        out = raw(self.port, b"POST /api/tasks HTTP/1.1\r\nAuthorization: " + auth +
                  b"\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n"
                  b"Connection: close\r\n\r\n" + body)
        self.assertTrue(out.startswith(b"HTTP/1.1 201"), out[:80])
        self.assertIn(b"trailers", out)

    def test_chunked_oversize_413(self):
        out = self.chunked([b"x" * 40000, b"y" * 40000])
        self.assertTrue(out.startswith(b"HTTP/1.1 413"))

    def test_chunked_bad_size_400(self):
        out = raw(self.port, b"POST /api/tasks HTTP/1.1\r\nTransfer-Encoding: chunked\r\n"
                             b"Connection: close\r\n\r\nzz\r\nabc\r\n0\r\n\r\n")
        self.assertTrue(out.startswith(b"HTTP/1.1 400"))

    def test_chunked_plus_content_length_400(self):
        out = raw(self.port, b"POST /api/tasks HTTP/1.1\r\nTransfer-Encoding: chunked\r\n"
                             b"Content-Length: 4\r\nConnection: close\r\n\r\n0\r\n\r\n")
        self.assertTrue(out.startswith(b"HTTP/1.1 400"))

    def test_unsupported_transfer_encoding_501(self):
        out = raw(self.port, b"POST /api/tasks HTTP/1.1\r\nTransfer-Encoding: gzip\r\n"
                             b"Connection: close\r\n\r\n")
        self.assertTrue(out.startswith(b"HTTP/1.1 501"))

    # --- keep-alive ------------------------------------------------------
    def test_keep_alive_reuses_connection(self):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            for _ in range(3):
                c.request("GET", "/api/health")
                r = c.getresponse()
                r.read()
                self.assertEqual(r.status, 200)
                self.assertEqual(r.getheader("Connection"), "keep-alive")
                self.assertIsNotNone(c.sock)  # still the same open connection
        finally:
            c.close()

    def test_pipelined_requests(self):
        one = b"GET /api/health HTTP/1.1\r\n\r\n"
        out = raw(self.port, one * 2 + b"GET /api/health HTTP/1.1\r\nConnection: close\r\n\r\n")
        self.assertEqual(out.count(b"HTTP/1.1 200"), 3)

    def test_connection_close_is_honoured(self):
        out = raw(self.port, b"GET /api/health HTTP/1.1\r\nConnection: close\r\n\r\n")
        self.assertIn(b"Connection: close", out)

    def test_http10_closes_by_default(self):
        out = raw(self.port, b"GET /api/health HTTP/1.0\r\n\r\n")
        self.assertIn(b"Connection: close", out)

    def test_ordinary_errors_keep_the_connection(self):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            c.request("GET", "/nope")
            r = c.getresponse()
            r.read()
            self.assertEqual(r.status, 404)
            self.assertIsNotNone(c.sock)
            c.request("GET", "/api/health")
            r = c.getresponse()
            r.read()
            self.assertEqual(r.status, 200)
        finally:
            c.close()

    def test_framing_errors_close_the_connection(self):
        out = raw(self.port, b"POST /api/tasks HTTP/1.1\r\nContent-Length: 999999999\r\n\r\n")
        self.assertIn(b"Connection: close", out)

    def test_idle_connection_is_closed(self):
        old, server.KEEPALIVE_TIMEOUT = server.KEEPALIVE_TIMEOUT, 0.3
        try:
            s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
            s.sendall(b"GET /api/health HTTP/1.1\r\n\r\n")
            self.assertIn(b"200", s.recv(4096))
            time.sleep(0.8)
            self.assertEqual(s.recv(4096), b"")  # server hung up on us
            s.close()
        finally:
            server.KEEPALIVE_TIMEOUT = old

    def test_max_requests_per_connection(self):
        old, server.MAX_REQUESTS_PER_CONN = server.MAX_REQUESTS_PER_CONN, 2
        try:
            out = raw(self.port, b"GET /api/health HTTP/1.1\r\n\r\n" * 2)
        finally:
            server.MAX_REQUESTS_PER_CONN = old
        self.assertEqual(out.count(b"HTTP/1.1 200"), 2)
        self.assertEqual(out.count(b"Connection: close"), 1)  # only the last one

    def test_path_traversal_blocked(self):
        for p in (b"/static/../server.py", b"/static/%2e%2e/server.py", b"/static/..%2fserver.py",
                  b"/static//etc/passwd", b"/static/%2e%2e%2f%2e%2e%2fetc%2fpasswd", b"/static/..%5cserver.py"):
            out = raw(self.port, b"GET " + p + b" HTTP/1.1\r\nConnection: close\r\n\r\n")
            self.assertTrue(out.startswith(b"HTTP/1.1 404"), p)
            self.assertNotIn(b"import hashlib", out, p)

    def test_static_served_with_security_headers(self):
        s, body, r = request(self.port, "GET", "/")
        self.assertEqual(s, 200)
        self.assertIn(b"Tulika", body)
        self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")
        self.assertIn("text/html", r.getheader("Content-Type"))

    def test_rate_limiter_unit(self):
        rl = server.RateLimiter(3, 60)
        results = [rl.check("ip")[0] for _ in range(5)]
        self.assertEqual(results, [True, True, True, False, False])
        self.assertTrue(rl.check("other-ip")[0])
        self.assertGreaterEqual(rl.check("ip")[1], 1)

    def test_rate_limit_429_over_http(self):
        old = server.LIMITERS["auth"]
        server.LIMITERS["auth"] = server.RateLimiter(3, 60)
        try:
            codes = [request(self.port, "POST", "/api/login", {"username": "alice", "password": "wrong-pass"})[0] for _ in range(5)]
            _, _, r = request(self.port, "POST", "/api/login", {"username": "alice", "password": "x"})
        finally:
            server.LIMITERS["auth"] = old
        self.assertEqual(codes, [401, 401, 401, 429, 429])
        self.assertTrue(int(r.getheader("Retry-After")) >= 1)

    # --- auth -----------------------------------------------------------
    def test_register_validation(self):
        self.assertEqual(request(self.port, "POST", "/api/register", {"username": "a", "password": "longenough"})[0], 400)
        self.assertEqual(request(self.port, "POST", "/api/register", {"username": "bob_ok", "password": "short"})[0], 400)
        self.assertEqual(request(self.port, "POST", "/api/register", {"username": "bad name!", "password": "longenough"})[0], 400)
        self.assertEqual(request(self.port, "POST", "/api/register", {"username": 123, "password": "longenough"})[0], 400)

    def test_duplicate_username_case_insensitive_409(self):
        self.assertEqual(request(self.port, "POST", "/api/register", {"username": "ALICE", "password": "whatever123"})[0], 409)

    def test_login_failures_are_identical(self):
        a = request(self.port, "POST", "/api/login", {"username": "alice", "password": "wrong-password"})
        b = request(self.port, "POST", "/api/login", {"username": "ghost", "password": "wrong-password"})
        self.assertEqual((a[0], a[1]), (b[0], b[1]))
        self.assertEqual(a[0], 401)

    def test_requires_auth(self):
        s, _, r = request(self.port, "GET", "/api/tasks")
        self.assertEqual(s, 401)
        self.assertEqual(r.getheader("WWW-Authenticate"), "Bearer")
        self.assertEqual(request(self.port, "GET", "/api/tasks", headers={"Authorization": "Bearer nonsense"})[0], 401)

    def test_cookie_auth_and_flags(self):
        _, _, r = request(self.port, "POST", "/api/login", {"username": "alice", "password": "correct horse"})
        cookie = r.getheader("Set-Cookie")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        session = cookie.split(";")[0]
        s, d, _ = request(self.port, "GET", "/api/me", headers={"Cookie": session})
        self.assertEqual((s, d["username"]), (200, "alice"))

    def test_logout_invalidates_token(self):
        _, d, _ = request(self.port, "POST", "/api/login", {"username": "alice", "password": "correct horse"})
        h = {"Authorization": "Bearer " + d["token"]}
        self.assertEqual(request(self.port, "GET", "/api/me", headers=h)[0], 200)
        self.assertEqual(request(self.port, "POST", "/api/logout", headers=h)[0], 200)
        self.assertEqual(request(self.port, "GET", "/api/me", headers=h)[0], 401)

    def test_expired_session_rejected(self):
        _, d, _ = request(self.port, "POST", "/api/login", {"username": "alice", "password": "correct horse"})
        with server.STORE.lock:
            server.STORE.data["sessions"][server.sha(d["token"])]["exp"] = 0
        self.assertEqual(request(self.port, "GET", "/api/me", headers={"Authorization": "Bearer " + d["token"]})[0], 401)

    def test_password_hashing(self):
        a, b = server.hash_password("pw-12345678"), server.hash_password("pw-12345678")
        self.assertNotEqual(a["salt"], b["salt"])
        self.assertNotEqual(a["hash"], b["hash"])
        self.assertTrue(server.verify_password("pw-12345678", a))
        self.assertFalse(server.verify_password("pw-12345679", a))

    # --- tasks ----------------------------------------------------------
    def test_task_crud(self):
        s, t, r = request(self.port, "POST", "/api/tasks", {"title": "  write tests  "}, self.tok)
        self.assertEqual(s, 201)
        self.assertEqual(t["title"], "write tests")
        self.assertEqual(r.getheader("Location"), "/api/tasks/%d" % t["id"])
        path = "/api/tasks/%d" % t["id"]
        self.assertEqual(request(self.port, "GET", path, headers=self.tok)[1]["done"], False)
        s, t2, _ = request(self.port, "PATCH", path, {"done": True}, self.tok)
        self.assertEqual((s, t2["done"], t2["title"]), (200, True, "write tests"))
        s, t3, _ = request(self.port, "PUT", path, {"title": "renamed"}, self.tok)
        self.assertEqual(t3["title"], "renamed")
        self.assertEqual(request(self.port, "DELETE", path, headers=self.tok)[0], 204)
        self.assertEqual(request(self.port, "GET", path, headers=self.tok)[0], 404)

    def test_task_validation(self):
        for bad in ({}, {"title": ""}, {"title": "   "}, {"title": "x" * 201}, {"title": 5}, {"title": "ok", "done": "maybe"}):
            self.assertEqual(request(self.port, "POST", "/api/tasks", bad, self.tok)[0], 400, bad)

    def test_users_cannot_touch_each_others_tasks(self):
        request(self.port, "POST", "/api/register", {"username": "mallory", "password": "evil-pass-1"})
        _, d, _ = request(self.port, "POST", "/api/login", {"username": "mallory", "password": "evil-pass-1"})
        mal = {"Authorization": "Bearer " + d["token"]}
        _, t, _ = request(self.port, "POST", "/api/tasks", {"title": "alice secret"}, self.tok)
        path = "/api/tasks/%d" % t["id"]
        for method in ("GET", "DELETE"):
            self.assertEqual(request(self.port, method, path, headers=mal)[0], 404)
        self.assertEqual(request(self.port, "PATCH", path, {"done": True}, mal)[0], 404)
        titles = [x["title"] for x in request(self.port, "GET", "/api/tasks", headers=mal)[1]["tasks"]]
        self.assertNotIn("alice secret", titles)

    # --- persistence ----------------------------------------------------
    def test_persistence_atomic_and_no_plaintext(self):
        request(self.port, "POST", "/api/tasks", {"title": "persist-me"}, self.tok)
        with open(self.db, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("persist-me", text)
        self.assertNotIn("correct horse", text)  # passwords never stored in clear
        data = json.loads(text)                  # always valid JSON, never half-written
        self.assertIn("alice", data["users"])
        leftovers = [f for f in os.listdir(os.path.dirname(self.db)) if f.endswith(".tmp")]
        self.assertEqual(leftovers, [])
        reloaded = server.Store(self.db)         # survives a "restart"
        self.assertIn("alice", reloaded.data["users"])

    def test_corrupt_db_is_quarantined_not_crashed(self):
        p = os.path.join(self.tmp.name, "corrupt.json")
        with open(p, "w") as f:
            f.write("{not json")
        s = server.Store(p)
        self.assertEqual(s.data["users"], {})
        self.assertTrue(any(f.startswith("corrupt.json.corrupt-") for f in os.listdir(self.tmp.name)))

    def test_concurrent_creates_are_safe(self):
        def work():
            for _ in range(5):
                request(self.port, "POST", "/api/tasks", {"title": "race"}, self.tok)
        threads = [threading.Thread(target=work) for _ in range(6)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        ids = [t["id"] for t in request(self.port, "GET", "/api/tasks?q=race", headers=self.tok)[1]["tasks"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreaterEqual(len(ids), 30)


@unittest.skipUnless(shutil.which("openssl"), "openssl not installed")
class TlsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cert, key = os.path.join(cls.tmp.name, "c.pem"), os.path.join(cls.tmp.name, "k.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
                        "-days", "1", "-subj", "/CN=localhost"], check=True, capture_output=True)
        server.init_store(os.path.join(cls.tmp.name, "db.json"))
        server.LIMITERS["global"] = server.RateLimiter(100000, 60)
        server.LIMITERS["auth"] = server.RateLimiter(100000, 60)
        cls.srv = server.make_server("127.0.0.1", 0, cert, key)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.ctx = ssl._create_unverified_context()  # self-signed test certificate

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.tmp.cleanup()

    def call(self, method, path, body=None):
        c = http.client.HTTPSConnection("127.0.0.1", self.port, timeout=5, context=self.ctx)
        c.request(method, path, body=json.dumps(body) if body else None,
                  headers={"Content-Type": "application/json"} if body else {})
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, json.loads(data), r

    def test_https_works_and_cookie_is_secure(self):
        self.assertEqual(self.call("GET", "/api/health")[0], 200)
        self.call("POST", "/api/register", {"username": "tlsuser", "password": "tls-pass-123"})
        s, _, r = self.call("POST", "/api/login", {"username": "tlsuser", "password": "tls-pass-123"})
        self.assertEqual(s, 200)
        self.assertIn("Secure", r.getheader("Set-Cookie"))

    def test_plain_http_is_refused_on_tls_port(self):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        s.sendall(b"GET /api/health HTTP/1.1\r\nConnection: close\r\n\r\n")
        try:
            data = s.recv(4096)
        except OSError:
            data = b""
        s.close()
        self.assertNotIn(b"200 OK", data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
