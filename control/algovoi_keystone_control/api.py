"""algovoi_keystone_control — open Apache-2.0 keystone settings panel.

Auto-detects installed algovoi packages, shows all configurable settings,
no hidden tiers. Run with:  uvicorn algovoi_keystone_control.api:app --reload
"""
from __future__ import annotations

import html
import json
import os
import re
import secrets
import sys
import time
from typing import Any

from collections import defaultdict

from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware
from urllib.parse import urlsplit

from .detect import detect, all_known
from .licensing import verify_license_offline
from .store import SettingsStore, _load_json, _save_json

_store = SettingsStore(os.environ.get("ALGV_SETTINGS_PATH"))
_DATA_DIR = os.environ.get("ALGV_DATA_DIR", ".")


def _esc(value: object) -> str:
    """HTML-escape any value (incl. quotes) for safe interpolation into the panel markup.

    Descriptor fields (step / ref / posture / package / version) come from arbitrary installed
    third-party bolt-ons and MUST be treated as untrusted before reaching the DOM.
    """
    return html.escape(str(value), quote=True)


# ── auth ───────────────────────────────────────────────────────────────────────
_TOKEN = os.environ.get("ALGV_ADMIN_TOKEN") or secrets.token_hex(16)
_COOKIE = "algv_kc_session"
_SESSION_MAX_AGE = 12 * 3600  # 12 hours

# Per-login random session tokens -> {"exp": epoch, "csrf": token}.
# Not derived from _TOKEN; pruned on use; every session carries a per-session
# CSRF token for double-submit defence on cookie-authenticated state changes.
_SESSIONS: dict[str, dict] = {}
_MAX_SESSIONS = 1024

# Simple in-memory rate limiter for /login: max 5 attempts per IP per 60 s.
_LOGIN_ATTEMPTS: dict[str, list[float]] = defaultdict(list)
_LOGIN_RATE_WINDOW = 60
_LOGIN_RATE_LIMIT = 5
_MAX_TRACKED_IPS = 4096

# Rate limiter for the unauthenticated /pin endpoint (Falcon verification is
# CPU-bound; without a cap it is an amplification DoS).
_PIN_ATTEMPTS: dict[str, list[float]] = defaultdict(list)
_PIN_RATE_LIMIT = 5
_PIN_RATE_WINDOW = 60


def _prune_sessions() -> None:
    now = time.time()
    for tok in [t for t, s in _SESSIONS.items() if s["exp"] <= now]:
        _SESSIONS.pop(tok, None)


def _valid_session(token: str | None) -> bool:
    if not token:
        return False
    sess = _SESSIONS.get(token)
    if sess is None:
        return False
    if sess["exp"] <= time.time():
        _SESSIONS.pop(token, None)
        return False
    return True


def _session_csrf(token: str | None) -> str:
    sess = _SESSIONS.get(token) if token else None
    return sess["csrf"] if sess else ""


def _add_session() -> str:
    _prune_sessions()
    if len(_SESSIONS) >= _MAX_SESSIONS:  # backstop against unbounded growth
        for tok in list(_SESSIONS)[: len(_SESSIONS) - _MAX_SESSIONS + 1]:
            _SESSIONS.pop(tok, None)
    token = secrets.token_hex(32)
    _SESSIONS[token] = {"exp": time.time() + _SESSION_MAX_AGE,
                        "csrf": secrets.token_urlsafe(24)}
    return token


def _check_rate_limit(ip: str, store: dict, limit: int, window: int) -> bool:
    """Return True if the IP is within the allowed rate. Prune stale entries."""
    now = time.monotonic()
    attempts = [t for t in store.get(ip, []) if now - t < window]
    if attempts:
        store[ip] = attempts
    elif ip in store:
        store.pop(ip, None)
    return len(attempts) < limit


def _record_attempt(ip: str, store: dict) -> None:
    if ip not in store and len(store) >= _MAX_TRACKED_IPS:
        return  # backstop against memory exhaustion from IP rotation
    store.setdefault(ip, []).append(time.monotonic())


# Pin gate — set ALGV_PIN_GATE=1 to require a Falcon-signed licence key to
# unlock editing. Explicit truthy values only: ALGV_PIN_GATE=0 means off.
_PIN_GATE = str(os.environ.get("ALGV_PIN_GATE", "")).strip().lower() in {
    "1", "true", "yes", "on"}
_PIN_COOKIE = "algv_kc_pin"
_PIN_COOKIE_MAX_AGE = 90 * 24 * 3600  # 90 days

# Persist verified tokens to disk (under the data dir, never inside the package)
# so they survive server restarts. Map of token -> expiry epoch.
_PIN_SESSIONS_FILE = os.path.join(_DATA_DIR, ".keystone_pin_sessions.json")
_MAX_PINNED_SESSIONS = 4096


def _load_pins() -> dict[str, float]:
    raw = _load_json(_PIN_SESSIONS_FILE)
    pins: dict[str, float] = {}
    now = time.time()
    for k, v in raw.items():
        try:
            exp = float(v)
        except (TypeError, ValueError):
            continue
        if exp > now:
            pins[str(k)] = exp
    return pins


def _save_pins(pins: dict[str, float]) -> None:
    try:
        _save_json(_PIN_SESSIONS_FILE, pins)
    except OSError:
        pass


_PINNED_SESSIONS: dict[str, float] = _load_pins()

_OPEN = {"/health", "/login", "/logout", "/pin"}


def _is_pinned(request: Request) -> bool:
    """True when the session carries a valid (unexpired) licence token (or pin gate is off).

    Expired pins are pruned lazily so the persisted map cannot grow without bound.
    """
    if not _PIN_GATE:
        return True
    token = request.cookies.get(_PIN_COOKIE) if request else None
    if not token:
        return False
    exp = _PINNED_SESSIONS.get(token)
    if exp is None:
        return False
    if time.time() >= exp:
        _PINNED_SESSIONS.pop(token, None)
        _save_pins(_PINNED_SESSIONS)
        return False
    return True


_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_CSRF_HEADER = "x-algv-csrf"


def _request_host(request: Request) -> str:
    return (request.url.hostname or "").lower()


def _request_is_same_site(request: Request) -> bool:
    """Best-effort same-site check for state-changing requests.

    Browsers send Sec-Fetch-Site on navigations and form submissions; cross-site
    requests are rejected outright. Origin/Referer host is the fallback for clients
    that omit the header (curl, scripts); requests with no signalling headers at all
    are allowed so non-browser API clients (Bearer auth) keep working.
    """
    site = request.headers.get("sec-fetch-site")
    if site == "cross-site":
        return False
    host = _request_host(request)
    origin = request.headers.get("origin")
    if origin:
        return (urlsplit(origin).hostname or "").lower() == host
    referer = request.headers.get("referer")
    if referer:
        return (urlsplit(referer).hostname or "").lower() == host
    return True


def _csrf_ok(request: Request, session: dict) -> bool:
    provided = request.headers.get(_CSRF_HEADER) or ""
    return bool(provided) and secrets.compare_digest(provided, session.get("csrf", ""))


class _LoginGate(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: object) -> Response:
        method = (request.method or "GET").upper()
        unsafe = method in _UNSAFE_METHODS
        cookie = request.cookies.get(_COOKIE)
        if unsafe and cookie and not _request_is_same_site(request):
            return Response('{"detail":"cross-origin request rejected"}',
                            status_code=403, media_type="application/json")

        path = request.url.path
        if path in _OPEN:
            if path == "/pin" and method == "POST":
                ip = request.client.host if request.client else "unknown"
                if not _check_rate_limit(ip, _PIN_ATTEMPTS, _PIN_RATE_LIMIT,
                                         _PIN_RATE_WINDOW):
                    _record_attempt(ip, _PIN_ATTEMPTS)
                    return Response('{"detail":"too many attempts"}',
                                    status_code=429, media_type="application/json")
                _record_attempt(ip, _PIN_ATTEMPTS)
            return await call_next(request)

        cookie = request.cookies.get(_COOKIE)
        session = _SESSIONS.get(cookie) if cookie else None
        auth = request.headers.get("authorization") or ""
        bearer_ok = secrets.compare_digest(auth, f"Bearer {_TOKEN}")
        if unsafe and session is not None and not _csrf_ok(request, session):
            return Response('{"detail":"csrf token required"}',
                            status_code=403, media_type="application/json")
        if session is not None or bearer_ok:
            return await call_next(request)
        accept = request.headers.get("accept", "")
        if "text/html" in accept:
            return RedirectResponse("/login", status_code=303)
        return Response('{"detail":"unauthorized"}', status_code=401,
                        media_type="application/json")


class _SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: object) -> Response:
        nonce = secrets.token_urlsafe(16)
        request.state.csp_nonce = nonce
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            f"script-src 'nonce-{nonce}'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        return resp


# Interactive docs / schema disabled — a control panel should not publish its API surface.
app = FastAPI(title="AlgoVoi Keystone Control", version="0.1.1",
              docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(_LoginGate)
app.add_middleware(_SecurityHeaders)


def _nonce(request: Request) -> str:
    return getattr(request.state, "csp_nonce", "")


@app.on_event("startup")
def _startup() -> None:
    if not os.environ.get("ALGV_ADMIN_TOKEN"):
        print(f"\n  ALGV_ADMIN_TOKEN={_TOKEN}  (auto-generated; set env to persist)\n",
              file=sys.stderr)
    if _PIN_GATE:
        print("  Pin gate ACTIVE — edit requires a valid algovoi-keystone-control licence key\n")
    else:
        print("  Pin gate OFF — editing is open (set ALGV_PIN_GATE=1 to require licence key)\n")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request) -> str:
    return _render_login(_nonce(request))


@app.post("/login")
async def login_submit(request: Request) -> Response:
    ip = request.client.host if request.client else "unknown"
    if not _check_rate_limit(ip, _LOGIN_ATTEMPTS, _LOGIN_RATE_LIMIT,
                             _LOGIN_RATE_WINDOW):
        return Response('{"detail":"too many attempts"}', status_code=429,
                        media_type="application/json")
    form = await request.form()
    if secrets.compare_digest(str(form.get("password") or ""), _TOKEN):
        token = _add_session()
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie(_COOKIE, token, httponly=True, samesite="lax",
                        max_age=_SESSION_MAX_AGE, secure=True)
        return resp
    ip = request.client.host if request.client else "unknown"
    _record_attempt(ip, _LOGIN_ATTEMPTS)
    return HTMLResponse(_render_login(_nonce(request), error=True), status_code=401)


@app.post("/logout")
async def logout(request: Request) -> Response:
    cookie = request.cookies.get(_COOKIE)
    if cookie:
        sess = _SESSIONS.get(cookie)
        if sess is not None and not _csrf_ok(request, sess):
            return Response('{"detail":"csrf token required"}', status_code=403,
                            media_type="application/json")
        _SESSIONS.pop(cookie, None)
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(_COOKIE)
    resp.delete_cookie(_PIN_COOKIE)
    return resp


@app.post("/pin")
async def pin_submit(request: Request) -> Response:
    form = await request.form()
    key = (form.get("pin") or "").strip()
    ok, reason = verify_license_offline(key) if key else (False, "no key provided")
    if ok:
        token = secrets.token_hex(32)
        _PINNED_SESSIONS[token] = time.time() + _PIN_COOKIE_MAX_AGE
        _save_pins(_PINNED_SESSIONS)
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie(_PIN_COOKIE, token, httponly=True, samesite="lax",
                        max_age=_PIN_COOKIE_MAX_AGE, secure=True)
        return resp
    return Response(json.dumps({"detail": f"invalid licence key: {reason}"}), status_code=403,
                    media_type="application/json")


@app.get("/v1/steps")
def list_steps() -> dict:
    steps = detect()
    saved = _store.all()
    result = []
    for s in steps:
        active = saved.get(s["step"], s["default"])
        result.append({
            "step": s["step"],
            "order": s["order"],
            "package": s["package"],
            "version": s["version"],
            "ref": s["ref"],
            "posture": s["posture"],
            "settings": active,
            "is_default": s["step"] not in saved,
        })
    return {"steps": result}


@app.get("/v1/steps/{step}/settings")
def get_settings(step: str) -> dict:
    entry = _find(step)
    active = _store.get(step, entry["default"])
    return {
        "step": step,
        "package": entry["package"],
        "version": entry["version"],
        "settings": active,
        "default": entry["default"],
        "is_default": active == entry["default"],
    }


_MAX_SETTINGS_BYTES = 64 * 1024
_MAX_SETTINGS_DEPTH = 64


def _validate_settings_depth(obj: Any, depth: int = 0) -> None:
    """Reject absurdly deep settings JSON (recursion DoS on load/store)."""
    if depth > _MAX_SETTINGS_DEPTH:
        raise ValueError("settings nested too deeply")
    if isinstance(obj, dict):
        for v in obj.values():
            _validate_settings_depth(v, depth + 1)
    elif isinstance(obj, (list, tuple, set, frozenset)):
        for v in obj:
            _validate_settings_depth(v, depth + 1)


@app.put("/v1/steps/{step}/settings")
async def put_settings(step: str, request: Request) -> dict:
    if not _is_pinned(request):
        raise HTTPException(status_code=403, detail="pin required to edit settings")
    _find(step)
    body = await request.body()
    if len(body) > _MAX_SETTINGS_BYTES:
        raise HTTPException(status_code=413, detail="settings payload too large")
    try:
        settings = json.loads(body)
    except (ValueError, RecursionError):
        raise HTTPException(status_code=400, detail="settings must be a JSON object")
    if not isinstance(settings, dict):
        raise HTTPException(status_code=400, detail="settings must be a JSON object")
    try:
        _validate_settings_depth(settings)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    _store.put(step, settings)
    return {"step": step, "saved": True, "settings": settings}


@app.delete("/v1/steps/{step}/settings")
def reset_settings(step: str, request: Request) -> dict:
    if not _is_pinned(request):
        raise HTTPException(status_code=403, detail="pin required to reset settings")
    entry = _find(step)
    _store.reset(step, entry["default"])
    return {"step": step, "reset": True, "default": entry["default"]}


@app.get("/v1/catalogue")
def catalogue() -> dict:
    return {"packages": all_known()}


@app.get("/", response_class=HTMLResponse)
def panel(request: Request) -> str:
    return _render(_nonce(request), can_edit=_is_pinned(request),
                   csrf_token=_session_csrf(request.cookies.get(_COOKIE)))


def _find(step: str) -> dict:
    for s in detect():
        if s["step"] == step:
            return s
    raise HTTPException(status_code=404, detail=f"step {step!r} not installed")


# ── panel ──────────────────────────────────────────────────────────────────────

def _render_login(nonce: str, *, error: bool = False) -> str:
    msg = '<p class="err">Incorrect token — try again.</p>' if error else ""
    return f"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Sign in — AlgoVoi Keystone Control</title><style nonce="{nonce}">{_CSS}
.login{{max-width:380px;margin:14vh auto}}
.login .card{{padding:28px}}
.login .brand{{font-size:16px;font-weight:600;margin-bottom:3px}}
.login .tagline{{color:var(--mut);font-size:12px;margin-bottom:22px}}
input[type=text],input[type=password]{{width:100%;padding:11px 13px;background:#0a0e17!important;border:1px solid #1e2a3a;
border-radius:8px;color:#f1f5f9!important;font:14px system-ui,sans-serif;margin:6px 0 14px;
outline:none;transition:border-color .15s;-webkit-text-fill-color:#f1f5f9!important}}
input[type=text]:focus,input[type=password]:focus{{border-color:#3b82f6}}
input:-webkit-autofill,input:-webkit-autofill:focus{{-webkit-box-shadow:0 0 0 1000px #0a0e17 inset!important;-webkit-text-fill-color:#f1f5f9!important}}
.btn-submit{{width:100%;padding:11px;background:var(--accent);color:#fff;border:0;border-radius:8px;
font:600 14px system-ui,sans-serif;cursor:pointer;transition:opacity .15s}}
.btn-submit:hover{{opacity:.88}}.err{{color:var(--bad);font-size:12px;margin-top:8px}}
</style></head><body>
<div class=topbar>
  <span class=tb-brand>AlgoVoi <span class=tb-dim>Keystone Control</span></span>
  <span class="tb-pill open">Apache-2.0</span>
</div>
<div class=wrap><div class=login><div class=card>
<div class=brand>Keystone Control</div>
<div class=tagline>Sign in with your admin token to continue.</div>
<form method=post action="/login">
<input type=password name=password placeholder="Paste admin token here" autofocus autocomplete=off spellcheck=false>
<button type=submit class=btn-submit>Sign in</button>{msg}
</form></div></div></div></body></html>"""


_CSS = """
:root{--bg:#0a0e17;--card:#111827;--line:#1e2a3a;--fg:#f1f5f9;--mut:#94a3b8;--ok:#10b981;--bad:#ef4444;--accent:#3b82f6;--warn:#f59e0b;--ok-bg:rgba(16,185,129,.08);--bad-bg:rgba(239,68,68,.08);--warn-bg:rgba(245,158,11,.08)}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.6 system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}
.mono,code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
.topbar{background:var(--card);border-bottom:1px solid var(--line);padding:0 32px;display:flex;align-items:center;gap:12px;height:52px}
.tb-brand{font-size:15px;font-weight:600;letter-spacing:-.015em}.tb-dim{color:var(--mut);font-weight:400}
.tb-pill{font-size:11px;padding:2px 8px;border-radius:6px;font-weight:500}
.tb-pill.open{background:var(--ok-bg);color:var(--ok)}
.tb-spacer{flex:1}
.tb-count{color:var(--mut);font-size:12px}
.tb-link{color:var(--mut);font-size:12px;text-decoration:none;padding:4px 10px;border-radius:6px;border:1px solid var(--line);margin-left:8px}
.tb-link:hover{color:var(--fg);border-color:var(--fg)}
.wrap{max-width:1120px;margin:0 auto;padding:28px 24px 60px}
.sub{color:var(--mut);font-size:12px;margin-bottom:24px}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:24px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;box-shadow:0 1px 3px rgba(0,0,0,.4)}
.stat .n{font-size:28px;font-weight:700;letter-spacing:-.025em;line-height:1.1}
.stat .l{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.08em;margin-top:5px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,.4)}
.card h2{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.1em;color:var(--mut);margin:0 0 16px;padding-bottom:12px;border-bottom:1px solid var(--line)}
table{width:100%;border-collapse:collapse}
th{color:var(--mut);font-weight:500;font-size:11px;text-transform:uppercase;letter-spacing:.06em;padding:0 10px 10px;text-align:left}
td{padding:10px;font-size:13px;border-bottom:1px solid rgba(30,42,58,.6);vertical-align:top}
tr:last-child td{border-bottom:none}tr:hover td{background:rgba(255,255,255,.02)}
.badge{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600}
.ok{background:var(--ok-bg);color:var(--ok)}.missing{background:var(--warn-bg);color:var(--warn)}.custom{background:var(--accent-bg,rgba(59,130,246,.08));color:var(--accent)}
.badge.ok::before,.badge.custom::before{content:'';width:5px;height:5px;border-radius:50%;background:currentColor;flex-shrink:0}
.mono{color:var(--accent);word-break:break-all}.mut{color:var(--mut)}
button{cursor:pointer;padding:7px 16px;border-radius:8px;font:500 13px system-ui,sans-serif;border:none;transition:opacity .15s}
button:hover{opacity:.85}
button.primary{background:var(--accent);color:#fff}
button.secondary{background:rgba(59,130,246,.1);color:var(--accent);border:1px solid rgba(59,130,246,.2)}
button.ghost{background:transparent;color:var(--mut);border:1px solid var(--line)}
button.danger{background:transparent;color:var(--bad);border:1px solid rgba(239,68,68,.2);font-size:12px;padding:4px 10px}
button.tune{background:transparent;color:var(--accent);border:1px solid rgba(59,130,246,.2);font-size:12px;padding:4px 12px;border-radius:6px}
textarea{width:100%;height:260px;background:var(--bg);border:1px solid var(--line);border-radius:8px;color:var(--fg);font:12px ui-monospace,Menlo,Consolas,monospace;padding:12px;margin-top:8px;resize:vertical;outline:none;transition:border-color .15s}
textarea:focus{border-color:var(--accent)}
.row{display:flex;gap:8px;align-items:center;margin-top:12px;flex-wrap:wrap}.msg{color:var(--mut);font-size:12px;flex:1}
.foot{color:var(--mut);font-size:12px;padding-top:16px;border-top:1px solid var(--line)}
"""


# Shell-safe pip-install guidance: only a bare, normalised package name may ever be
# rendered into a "pip install ..." command. Vendor descriptors are untrusted input.
_PKG_NAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")


def _install_cmd(p: dict) -> str:
    """Render the pip-install guidance for a package descriptor, shell-safe.

    Vendor-supplied descriptor fields are attacker-controlled, so only a validated
    bare package name is ever rendered into a ``pip install ...`` command.
    """
    name = _install_pkg(p)
    if not name:
        return '<span class="mut">— no publishable package name —</span>'
    return f"pip install {_esc(name)}"


def _install_pkg(p: dict) -> str:
    """The package an adopter should pip install for this step. Prefer the open/lite
    variant (the commercial parent is not published to PyPI), else fall back to the
    primary. Returns "" when no candidate passes the name-safety check."""
    pkgs = p.get("packages") or [p.get("package", "")]
    for name in pkgs:
        if isinstance(name, str) and name.endswith("-lite") and _PKG_NAME_RE.match(name):
            return name
    for name in reversed(pkgs):
        if isinstance(name, str) and _PKG_NAME_RE.match(name):
            return name
    return ""


def _render(nonce: str, *, can_edit: bool = True, csrf_token: str = "") -> str:
    steps = detect()
    all_pkgs = all_known()
    saved = _store.all()
    missing_n = sum(1 for p in all_pkgs if not p["installed"])
    custom_n = sum(1 for s in steps if s["step"] in saved)

    rows = ""
    for s in steps:
        is_custom = s["step"] in saved
        src_badge = ('<span class="badge custom">custom</span>' if is_custom
                     else '<span class="mut">default</span>')
        step_name = _esc(s["step"])
        provider = _esc(s.get("provider") or s.get("package") or "—")
        if can_edit:
            reset_btn = (f"<button class=danger style='margin-left:4px' "
                         f"data-act=reset data-step=\"{step_name}\">Reset</button>") if is_custom else ""
            action_btn = (f"<button class=tune data-act=edit data-step=\"{step_name}\">Edit</button>"
                          f"{reset_btn}")
        else:
            action_btn = '<span class="mut" style="font-size:11px">view only</span>'
        rows += (f"<tr><td class=mut>{_esc(s['order'])}</td>"
                 f"<td><b>{step_name}</b><div class=mut style='font-size:11px;margin-top:2px'>{provider}</div></td>"
                 f"<td class=mono>{_esc(s['ref'])}</td><td class=mut>{_esc(s['posture'])}</td>"
                 f"<td><span class='badge ok'>{_esc(s['version'])}</span></td>"
                 f"<td>{src_badge}</td>"
                 f"<td>{action_btn}</td></tr>")

    not_installed = [p for p in all_pkgs if not p["installed"]]
    missing_rows = "".join(
        f"<tr><td class=mut>{_esc(p['order'])}</td><td>{_esc(p['step'])}</td>"
        f"<td class=mono>{_esc(p['ref'])}</td><td class=mut>{_esc(p['posture'])}</td>"
        f"<td><span class='badge missing'>not installed</span></td>"
        f"<td colspan=2 class=mut><code>{_install_cmd(p)}</code></td></tr>"
        for p in not_installed
    )

    pin_banner = ""
    if _PIN_GATE and not can_edit:
        pin_banner = """<div style="background:rgba(245,158,11,.08);border-bottom:1px solid rgba(245,158,11,.2);padding:8px 32px;display:flex;align-items:center;gap:10px;font-size:12px;color:#f59e0b">
  <span>Settings are read-only. Paste your AlgoVoi licence key to unlock editing.</span>
  <input type=text id=pin-input placeholder="Paste licence key" autocomplete=off spellcheck=false style="padding:5px 10px;background:#0a0e17;border:1px solid rgba(245,158,11,.4);border-radius:6px;color:#f1f5f9;font-size:12px;width:320px;outline:none">
  <button id=pin-unlock style="padding:5px 14px;background:rgba(245,158,11,.15);border:1px solid rgba(245,158,11,.3);border-radius:6px;color:#f59e0b;font-size:12px;cursor:pointer">Unlock</button>
  <span id=pin-msg style="color:#ef4444;font-size:11px"></span>
</div>"""

    store_path = _esc(_store._path)
    return f"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>AlgoVoi Keystone Control</title><meta name="csrf-token" content="{_esc(csrf_token)}"><style nonce="{nonce}">{_CSS}</style></head><body>
<div class=topbar>
  <span class=tb-brand>AlgoVoi <span class=tb-dim>Keystone Control</span></span>
  <span class="tb-pill open">Apache-2.0</span>
  <span class=tb-spacer></span>
  <span class=tb-count>{len(steps)} of {len(all_pkgs)} steps installed</span>
  <button id=signout class=tb-link>Sign out</button>
</div>
{pin_banner}
<div class=wrap>
<div class=sub>Settings tune the verdict, never the hash. All settings visible — nothing hidden.</div>
<div class=grid>
  <div class=stat><div class=n>{len(steps)}</div><div class=l>Installed steps</div></div>
  <div class=stat><div class=n>{custom_n}</div><div class=l>Custom settings</div></div>
  <div class=stat><div class=n>{missing_n}</div><div class=l>Not installed</div></div>
</div>
<div class=card><h2>Installed keystone steps</h2>
<table><tr><th>#</th><th>step</th><th>ref</th><th>posture</th><th>version</th><th>settings</th><th></th></tr>
{rows or "<tr><td colspan=7 class=mut>No algovoi keystone packages detected — pip install algovoi-spend-guardrail to get started.</td></tr>"}
</table></div>
{"<div class=card><h2>Available (not installed)</h2><table><tr><th>#</th><th>step</th><th>ref</th><th>posture</th><th>status</th><th colspan=2>install</th></tr>" + missing_rows + "</table></div>" if not_installed else ""}
<div id=editor class=card style="display:none">
  <h2 id=etitle>Edit settings</h2>
  <div style="display:flex;gap:8px;margin-bottom:8px;flex-wrap:wrap">
    <button class=secondary data-tab=app id=tab-app>App settings</button>
    <button class=ghost data-tab=ks id=tab-ks>Keystone substrate</button>
  </div>
  <div id=pane-app>
    <div style="color:var(--mut);font-size:11px;margin-bottom:6px">Application-level gate configuration. Saved and applied at runtime.</div>
    <textarea id=esettings spellcheck=false></textarea>
  </div>
  <div id=pane-ks style="display:none">
    <div style="color:var(--mut);font-size:11px;margin-bottom:6px">Substrate-layer keystone variables — canon version, hash algorithm, required fields, chain bindings. Edit with care: changing these affects ref computation.</div>
    <textarea id=eksettings spellcheck=false style="border-color:rgba(59,130,246,.35)"></textarea>
  </div>
  <div class=row>
    <button class=primary data-act=save>Save</button>
    <button class=ghost data-act=close-editor>Close</button>
    <span id=emsg class=msg></span>
  </div>
</div>
<div class=foot>Settings stored in <code class=mono>{store_path}</code> · <a href="/v1/steps" style="color:var(--mut)">JSON API</a> · <a href="https://docs.algovoi.co.uk/keystone" style="color:var(--mut)">Docs</a></div>
</div>
<script nonce="{nonce}">
async function verifyPin(){{
  const pin=document.getElementById('pin-input').value;
  const fd=new FormData();fd.append('pin',pin);
  const r=await fetch('/pin',{{method:'POST',body:fd}});
  if(r.ok||r.redirected){{location.reload();}}
  else{{document.getElementById('pin-msg').textContent='Invalid pin';}}
}}
let cur=null,curTab='app';
const CSRF=document.querySelector('meta[name="csrf-token"]').content||"";
function setMsg(t){{document.getElementById('emsg').textContent=t;}}
function showTab(t){{
  curTab=t;
  document.getElementById('pane-app').style.display=t==='app'?'block':'none';
  document.getElementById('pane-ks').style.display=t==='ks'?'block':'none';
  document.getElementById('tab-app').className=t==='app'?'secondary':'ghost';
  document.getElementById('tab-ks').className=t==='ks'?'secondary':'ghost';
}}
async function edit(step){{
  cur=step;
  const r=await fetch('/v1/steps/'+encodeURIComponent(step)+'/settings');
  const j=await r.json();
  const s=j.settings;
  const ks=s.__keystone||{{}};
  const app=Object.fromEntries(Object.entries(s).filter(([k])=>k!=='__keystone'));
  document.getElementById('etitle').textContent='Edit · '+step;
  document.getElementById('esettings').value=JSON.stringify(app,null,2);
  document.getElementById('eksettings').value=JSON.stringify(ks,null,2);
  document.getElementById('editor').style.display='block';
  setMsg(j.is_default?'showing defaults':'showing custom settings');
  showTab('app');
  window.scrollTo(0,document.body.scrollHeight);
}}
async function doSave(){{
  let app,ks;
  try{{app=JSON.parse(document.getElementById('esettings').value)}}catch(e){{return setMsg('invalid JSON in app settings');}}
  try{{ks=JSON.parse(document.getElementById('eksettings').value)}}catch(e){{return setMsg('invalid JSON in keystone settings');}}
  const merged=Object.keys(ks).length?{{...app,__keystone:ks}}:app;
  const r=await fetch('/v1/steps/'+encodeURIComponent(cur)+'/settings',{{method:'PUT',headers:{{'content-type':'application/json','x-algv-csrf':CSRF}},body:JSON.stringify(merged)}});
  if(r.ok){{setMsg('saved');location.reload();}}else{{setMsg('error '+r.status);}}
}}
async function reset(step){{
  if(!confirm('Reset '+step+' to defaults?'))return;
  await fetch('/v1/steps/'+encodeURIComponent(step)+'/settings',{{method:'DELETE',headers:{{'x-algv-csrf':CSRF}}}});
  location.reload();
}}
async function doLogout(){{
  const r=await fetch('/logout',{{method:'POST',headers:{{'x-algv-csrf':CSRF}}}});
  if(r.ok||r.redirected){{location.reload();}}
}}
document.addEventListener('click',function(e){{
  const b=e.target.closest('[data-act],[data-tab],#pin-unlock,#signout');
  if(!b)return;
  if(b.id==='pin-unlock'){{verifyPin();return;}}
  if(b.id==='signout'){{doLogout();return;}}
  if(b.dataset.tab){{showTab(b.dataset.tab);return;}}
  const a=b.dataset.act;
  if(a==='save')doSave();
  else if(a==='close-editor')document.getElementById('editor').style.display='none';
  else if(a==='edit')edit(b.dataset.step);
  else if(a==='reset')reset(b.dataset.step);
}});
</script></body></html>"""
