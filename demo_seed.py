"""Fill a running Tulika server with demo data and show the edge cases.

    python server.py              (terminal 1)
    python demo_seed.py           (terminal 2)
    python demo_seed.py --ratelimit   (optional: also trigger the 429 limiter)

Login/register is limited to 5 attempts per minute per IP, and this script uses 3,
so wait about a minute between runs.

Then open http://localhost:8000 and log in as  tulip_demo / Tulip@2026!
"""
import http.client
import json
import sys

HOST, PORT = "127.0.0.1", int(__import__("os").environ.get("PORT", "8000"))
USER, PASSWORD = "tulip_demo", "Tulip@2026!"

TASKS = [
    {"title": "Record the demo video"},
    {"title": "Push Tulika to GitHub"},
    {"title": "Deploy on Render", "done": True},
    {"title": "Submit the GDGoC technical task"},
    {"title": "Write README: design notes \u2713"},
]


def call(method, path, body=None, token=None):
    c = http.client.HTTPConnection(HOST, PORT, timeout=5)
    headers = {}
    if body is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(body)
    if token:
        headers["Authorization"] = "Bearer " + token
    c.request(method, path, body=body, headers=headers)
    r = c.getresponse()
    raw = r.read()
    c.close()
    try:
        return r.status, json.loads(raw) if raw else None
    except ValueError:
        return r.status, raw[:60]


def show(label, result, expect):
    status, data = result
    mark = "ok  " if status == expect else "FAIL"
    print("[%s] %-34s -> %s %s" % (mark, label, status, data if status >= 400 else ""))


def main():
    print("== Demo data ==")
    status, _ = call("POST", "/api/register", {"username": USER, "password": PASSWORD})
    print("register %s: %s" % (USER, "created" if status == 201 else "already exists" if status == 409 else status))
    status, data = call("POST", "/api/login", {"username": USER, "password": PASSWORD})
    if status != 200:
        sys.exit("login failed (%s): %s. If 429, wait a minute and retry." % (status, data))
    token = data["token"]
    for t in TASKS:
        s, d = call("POST", "/api/tasks", t, token)
        print("  task #%s %-40s done=%s" % (d.get("id"), d.get("title"), d.get("done")))
    s, d = call("PATCH", "/api/tasks/%d" % d["id"], {"done": True}, token)
    print("  marked last task done:", d["done"])

    print("\n== Edge cases (all should say ok) ==")
    show("wrong password", call("POST", "/api/login", {"username": USER, "password": "nope-nope"}), 401)
    show("no token", call("GET", "/api/tasks"), 401)
    show("bad token", call("GET", "/api/tasks", token="garbage"), 401)
    show("unknown route", call("GET", "/api/nothing"), 404)
    show("wrong method (DELETE /api/health)", call("DELETE", "/api/health"), 405)
    show("empty title", call("POST", "/api/tasks", {"title": "  "}, token), 400)
    show("short password", call("POST", "/api/register", {"username": "newbie", "password": "abc"}), 400)
    show("duplicate username", call("POST", "/api/register", {"username": USER.upper(), "password": PASSWORD}), 409)
    show("path traversal", call("GET", "/static/../server.py"), 404)
    show("encoded traversal", call("GET", "/static/%2e%2e%2fserver.py"), 404)
    show("oversized body", call("POST", "/api/tasks", {"title": "x" * 70000}, token), 413)

    if "--ratelimit" in sys.argv:
        print("\n== Rate limiter: 14 rapid wrong logins (limit is 10 per minute) ==")
        codes = [call("POST", "/api/login", {"username": USER, "password": "bad-bad-bad"})[0] for _ in range(14)]
        print("status codes:", codes, "(expect 401s first, then 429 once past 10)")
        print("Login is blocked for about a minute for this IP; the UI will say 'too many attempts'.")

    print("\nOpen http://localhost:%d and log in as %s / %s" % (PORT, USER, PASSWORD))


if __name__ == "__main__":
    main()
