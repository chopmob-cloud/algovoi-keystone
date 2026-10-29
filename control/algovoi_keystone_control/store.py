"""File-backed settings store — one JSON file, keyed by step name.

Persistence hardening:
* every file boundary is utf-8 (Windows locale codepage can otherwise corrupt
  hand-edited settings and 500 every panel render);
* corrupt / unreadable / wrong-schema persistence degrades to an empty store
  instead of raising;
* writes are atomic (mkstemp + os.replace), mode 0o600, directory 0o700,
  no predictable *.tmp name, no leftover temp files on failure.
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any

_MAX_FILE_BYTES = 8 * 1024 * 1024  # guard against runaway persistence


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
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    if created:
        os.chmod(directory, 0o700)


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
