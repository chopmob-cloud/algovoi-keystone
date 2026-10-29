"""File-backed settings store — one JSON file, keyed by step name.

Persistence hardening:
* every file boundary is utf-8 (Windows locale codepage can otherwise corrupt
  hand-edited settings and 500 every panel render);
* corrupt / unreadable / wrong-schema persistence degrades to an empty store
  instead of raising;
* writes are atomic (mkstemp + os.replace), no predictable *.tmp name, no
  leftover temp files on failure;
* the file and its directory are restricted to the owning account. On POSIX that
  is mode 0o600 / 0o700. On Windows POSIX modes are a silent no-op, so the ACL is
  restricted explicitly instead — and if that cannot be done the store says so
  once rather than claiming protection it does not have.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from typing import Any

_MAX_FILE_BYTES = 8 * 1024 * 1024  # guard against runaway persistence

_WARNED: set[str] = set()


def _restrict(path: str, mode: int) -> None:
    """Restrict a path to the owning account; never raise on a best-effort basis.

    POSIX: chmod(mode). Windows: POSIX modes do not apply, so inheritance is
    removed and only the current user is granted access. If neither can be
    applied, warn once with the path so the operator can secure it.
    """
    if os.name != "nt":
        try:
            os.chmod(path, mode)
        except OSError:
            _warn_once(path, "could not set POSIX mode")
        return

    user = os.environ.get("USERNAME") or os.environ.get("USER")
    if not user:
        _warn_once(path, "USERNAME unset")
        return
    try:
        if os.path.isdir(path):
            args = ["icacls", path, "/inheritance:r", "/grant:r", f"{user}:(OI)(CI)F"]
        else:
            args = ["icacls", path, "/inheritance:r", "/grant:r", f"{user}:F"]
        r = subprocess.run(args, capture_output=True, timeout=15,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if r.returncode != 0:
            _warn_once(path, "icacls failed")
    except Exception:
        _warn_once(path, "icacls unavailable")


def _warn_once(path: str, reason: str) -> None:
    key = f"{reason}:{path}"
    if key in _WARNED:
        return
    _WARNED.add(key)
    print(f"  WARNING: could not restrict permissions on {path} ({reason}); "
          f"the settings store may be readable by other local accounts",
          file=sys.stderr, flush=True)


def _dir_of(path: str) -> str:
    return os.path.dirname(os.path.abspath(path))


def _load_json(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, UnicodeDecodeError, OSError,
            RecursionError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return data


def _save_json(path: str, data: dict) -> None:
    directory = _dir_of(path)
    created = not os.path.isdir(directory)
    if created:
        os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=os.path.basename(path) + ".", suffix=".tmp",
                               dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        _restrict(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    if created:
        _restrict(directory, 0o700)


class SettingsStore:
    def __init__(self, path: str | None = None):
        self._path = path or os.path.join(
            os.environ.get("ALGV_DATA_DIR", "."), "keystone_settings.json"
        )

    def _load(self) -> dict:
        return _load_json(self._path)

    def _save(self, data: dict) -> None:
        _save_json(self._path, data)

    def get(self, step: str, default: dict) -> dict:
        return self._load().get(step, default)

    def put(self, step: str, settings: dict) -> None:
        data = self._load()
        data[step] = settings
        self._save(data)

    def all(self) -> dict:
        return self._load()

    def reset(self, step: str, default: dict) -> None:
        data = self._load()
        data.pop(step, None)
        self._save(data)
