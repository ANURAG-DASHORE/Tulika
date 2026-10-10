<p align="center"><img src="static/logo.svg" height="120" alt="Tulika logo"></p>

# Tulika: a zero-dependency web service

A small multi-user task service written with **only the Python standard library**.
No pip, no npm, no frameworks. Every piece below is hand-written in `server.py`.

| Requirement | Where it lives |
|---|---|
| Hand-written router (path params, 404 / 405 with `Allow`) | `route()`, `dispatch()` |
| Request parsing (headers, JSON and form bodies, query string) | `read_request()`, `Request.data()`, `parse_query()` |
| Login with password hashing, sessions | `hash_password()` (scrypt + per-user salt), `authenticate()`, `/api/login` |
| Persistence with safe writes | `Store.save()`: temp file, `fsync`, atomic `os.replace` |
| Rate limiter | `RateLimiter` (token bucket): 120 req/min per IP, 10 login/register per min |
| Persistent connections | HTTP/1.1 keep-alive with idle timeout (5 s) and a per-connection request cap (100); `Connection: close` and HTTP/1.0 honoured |
| Chunked request bodies | `read_chunked()`: hand-written decoder that enforces the body cap as chunks arrive |
| Optional HTTPS | set `TLS_CERT` and `TLS_KEY`; TLS 1.2+, handshake done in the worker thread |
| Security | path traversal guard, 64 KB body cap (413), header/line caps (431/414), timeouts (408), connection cap (503) |

HTTP itself is parsed from raw sockets (`socketserver` is only used to accept connections and spawn threads).

## Run

```
python3 server.py            # http://localhost:8000
python3 test_server.py       # 48 tests, standard library only
python3 demo_seed.py         # with the server running: adds demo data, shows edge cases
```

Demo login after seeding: `tulip_demo` / `Tulip@2026!`

Env vars: `PORT`, `HOST`, `DATA_FILE`, `TLS_CERT` + `TLS_KEY` (serve HTTPS), `TRUST_PROXY=1` (only behind a proxy you control, so the real client IP is used for rate limiting and cookies get `Secure`).
Needs Python 3.9+.

## API

| Method | Path | Notes |
|---|---|---|
| GET | `/api/health` | |
| POST | `/api/register` | `{"username","password"}`, 3-32 chars `[A-Za-z0-9_]`, password 8-128 |
| POST | `/api/login` | returns `token`, also sets an HttpOnly, SameSite=Strict cookie |
| POST | `/api/logout` | |
| GET | `/api/me` | |
| GET / POST | `/api/tasks` | list supports `?done=true&q=text` |
| GET / PUT / PATCH / DELETE | `/api/tasks/<id>` | per-user; other users' ids return 404 |

Authenticate with `Authorization: Bearer <token>` or the session cookie. Bodies may be JSON or `application/x-www-form-urlencoded`.

```
curl -X POST localhost:8000/api/register -H 'Content-Type: application/json' -d '{"username":"demo","password":"demo-pass-123"}'
curl -X POST localhost:8000/api/login -d 'username=demo&password=demo-pass-123'
curl localhost:8000/api/tasks -H 'Authorization: Bearer <token>'
```

A demo front-end (plain HTML/JS, served by the same server) is at `/`.

## Design notes and known limits

- Passwords: scrypt (n=2^14, r=8, p=1), 16-byte random salt, `hmac.compare_digest`. Unknown usernames still run a dummy hash so timing does not reveal which users exist.
- Sessions: 32 random bytes; only the SHA-256 of the token is stored, so a leaked database does not leak live sessions. 24 h expiry; logout deletes server-side.
- CSRF: cookie is `SameSite=Strict`; state changes need a JSON/form body.
- Storage is one JSON file guarded by a lock (the brief asks for a file-based or hand-built store), which is fine for a demo or small team. Swap `Store` for a real database to scale.
- TLS is optional and off by default. On Render/Fly/nginx the platform terminates TLS for you, so leave it off there and set `TRUST_PROXY=1`. To try HTTPS locally: `openssl req -x509 -newkey rsa:2048 -nodes -keyout k.pem -out c.pem -days 30 -subj /CN=localhost`, then `TLS_CERT=c.pem TLS_KEY=k.pem python3 server.py`.
- A request that breaks HTTP framing (oversized, malformed, bad chunking) gets its error reply and the connection is closed, after draining what the client is still sending so the reply isn't lost. Ordinary errors (404, 401, 400 for bad input) keep the connection open.
- Uploads are limited to 64 KB whether sent with `Content-Length` or chunked; a request with both headers is rejected (request-smuggling guard).

## Deploy (Render, free tier)

The repo includes `render.yaml` and an empty `requirements.txt`. In Render: New, Web Service, pick this repo, Language Python 3, Build Command `pip install -r requirements.txt`, Start Command `python server.py`, Instance Type Free, and add env var `TRUST_PROXY=1`. Render supplies `PORT` itself.

Free-tier behaviour to expect: the service sleeps after 15 minutes without traffic and the first request afterwards can take 30 to 60 seconds. The disk is ephemeral, so accounts and tasks may disappear when the service restarts or redeploys. That is fine for a demo; use a real database for anything permanent.
