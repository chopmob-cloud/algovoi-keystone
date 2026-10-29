"""
Runtime licence verification for algovoi-keystone-control.

Verification is fully OFFLINE: the installer's licence key (a Falcon-1024-signed envelope
issued by AlgoVoi) is checked against the bundled issuer public key — signature + type +
package match + expiry. No network call, no phone-home. Depends only on ``pqcrypto`` + ``rfc8785``.

Provide the key via the browser UI when prompted by the pin gate.
"""
from __future__ import annotations

import base64
import json
import os
import re
from datetime import datetime, timezone

try:
    from algovoi_substrate.canonicalize import canonicalize_bytes as _jcs_bytes
    _HAS_JCS = True
except Exception:
    _HAS_JCS = False

try:
    from pqcrypto.sign.falcon_1024 import verify as _falcon_verify
    _HAS_FALCON = True
except Exception:
    _HAS_FALCON = False

# AlgoVoi licence-fulfilment issuer Falcon-1024 PUBLIC key (kid ce299eca183dc4e3).
_ISSUER_PUBKEY_B64 = "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"
_PUBLIC_KEY_BYTES = 1793

PACKAGE_NAME = "algovoi-keystone-control"
_VALID_TIERS = {"v0", "commercial"}


class LicenseError(RuntimeError):
    pass


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * ((-len(s)) % 4))


def _is_expired(iso: str | None) -> bool:
    if not iso:
        return True
    try:
        exp = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except Exception:
        return True
    return datetime.now(timezone.utc) >= exp


def verify_license_offline(license_key: str) -> tuple[bool, str]:
    """Return ``(ok, reason)``. Checks Falcon-1024 sig + package match + expiry."""
    if not _HAS_FALCON:
        return False, "pqcrypto unavailable — rebuild venv with Python 3.11"
    if not _HAS_JCS:
        return False, "algovoi-substrate unavailable"
    try:
        pub = base64.b64decode(_ISSUER_PUBKEY_B64)
        env = json.loads(_b64u_decode(license_key))
        payload = env["payload"]
        sig = _b64u_decode(env["sig"])
    except Exception:
        return False, "malformed licence key"
    if not isinstance(payload, dict) or payload.get("type") != "oem_license":
        return False, "not an oem_license"
    if len(pub) != _PUBLIC_KEY_BYTES:
        return False, "bad issuer key"
    try:
        ok = bool(_falcon_verify(pub, _jcs_bytes(payload), sig))
    except Exception:
        ok = False
    if not ok:
        return False, "signature verification failed"
    if payload.get("package") != PACKAGE_NAME:
        return False, f"licence is for {payload.get('package')!r}, not {PACKAGE_NAME!r}"
    tier = payload.get("tier", "commercial")
    if tier not in _VALID_TIERS:
        return False, f"tier {tier!r} not accepted by this package"
    if _is_expired(payload.get("expires_at")):
        return False, "licence has expired"
    return True, "active"
