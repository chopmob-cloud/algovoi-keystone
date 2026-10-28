#!/usr/bin/env python3
"""AlgoVoi delegation-ref v0 adoption check — run before issuing a free v0 licence key.

Usage:
  python scripts/check_v0_adoption.py /path/to/submitted/project
  python scripts/check_v0_adoption.py --lockfile /path/to/requirements.txt [--notice /path/to/NOTICE]

Four required checks must all pass before issuing a key (the same gate as
algovoi-retention-chain / algovoi-policy-binding, with this package's anchors):

  1. DEPENDENCY DECLARATION  -- algovoi-delegation-ref appears in a lockfile or manifest.
  2. VECTOR HASH ANCHOR      -- at least one canonical delegation_ref hex from
                                 conformance/delegation_ref_v1/vectors.json appears in the
                                 project (hard evidence they ran our conformance suite
                                 against our exact vectors, not a reimplementation).
  3. NOTICE ATTRIBUTION      -- a NOTICE file exists and mentions both "AlgoVoi" and
                                 "algovoi-delegation-ref".
  4. VERSION PIN             -- pinned to a specific version (==0.1.0 or a wheel --hash),
                                 not a bare range.

Exit codes: 0 ISSUE_V0_KEY | 1 HOLD | 2 REJECT. Internal use only; not shipped in the wheel.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

# Canonical anchors from conformance/delegation_ref_v1/vectors.json: the root and
# chain delegation_refs plus the three tamper recomputations (scope / expiry / delegate).
_CANONICAL_ANCHORS: list[str] = [
    "4e59d4d1fcee3e2fa6a9be3cfa905b4bc09e5746a40c1dab96c277c4e10d3276",  # root
    "91329d2887d8eb879cef066c36418245266116b52758c386246fdb927d34494a",  # chain link
    "e30dbd4782298eb77c9be989538a5c6b6c2aed7e83a7506ca60d4597bf6200a2",  # scope-widen tamper
    "b4b5dfc3b387f791865a35ff61c3ade0b304eb72800f2cc80f64a3495b25a54a",  # expiry-extend tamper
    "be6fd71169cea6df9a93e2e9f8d80274f9df58e7bdee4f0ca8990394c079c35c",  # delegate-swap tamper
]

_PACKAGE_PATTERNS: list[re.Pattern] = [
    re.compile(r"algovoi[-_]delegation[-_]ref", re.IGNORECASE),
    re.compile(r"algovoi/delegation-ref", re.IGNORECASE),
    re.compile(r"@algovoi/delegation-ref", re.IGNORECASE),
    re.compile(r"AlgoVoi\.DelegationRef", re.IGNORECASE),
    re.compile(r"io\.algovoi[:/]delegation.ref", re.IGNORECASE),
]

_LOCKFILE_NAMES: set[str] = {
    "requirements.txt", "requirements-lock.txt", "constraints.txt",
    "pyproject.toml", "setup.cfg", "setup.py", "poetry.lock", "Pipfile", "Pipfile.lock",
    "go.mod", "go.sum", "Cargo.toml", "Cargo.lock",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "Gemfile", "Gemfile.lock", "pom.xml", "build.gradle", "build.gradle.kts",
    "packages.lock.json", "*.csproj",
}
_NOTICE_NAMES: set[str] = {"NOTICE", "NOTICE.txt", "NOTICE.md", "NOTICE.rst"}
_SKIP_DIRS: set[str] = {".git", ".hg", "node_modules", "__pycache__", ".tox", ".venv",
                        "venv", "env", "dist", "build", "target", ".gradle"}
_TEXT_EXTENSIONS: set[str] = {".py", ".ts", ".js", ".go", ".rs", ".rb", ".cs", ".java",
                              ".kt", ".toml", ".json", ".yaml", ".yml", ".txt", ".md",
                              ".lock", ".sum", ".cfg", ".ini", ".env"}

_PIN_RE = re.compile(r"algovoi[-_]delegation[-_]ref\s*(==|~=|@)", re.IGNORECASE)
_HASH_RE = re.compile(r"algovoi[-_]delegation[-_]ref[^\n]*--hash", re.IGNORECASE)


def _text_files(root: Path) -> list[Path]:
    result: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fname in filenames:
            p = Path(dirpath) / fname
            if p.suffix.lower() in _TEXT_EXTENSIONS or p.name in _LOCKFILE_NAMES | _NOTICE_NAMES:
                result.append(p)
    return result


def _read_safe(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return ""


def _is_lockfile(p: Path) -> bool:
    return p.name in _LOCKFILE_NAMES or p.suffix == ".csproj"


def check_dependency(files: list[Path]) -> tuple[str, str]:
    hits: list[str] = []
    for lf in [f for f in files if _is_lockfile(f)]:
        content = _read_safe(lf)
        if any(pat.search(content) for pat in _PACKAGE_PATTERNS):
            hits.append(lf.name)
    if hits:
        return "PASS", f"algovoi-delegation-ref found in: {', '.join(sorted(set(hits)))}"
    return "FAIL", "algovoi-delegation-ref not found in any lockfile or manifest."


def check_vector_anchor(files: list[Path]) -> tuple[str, str]:
    found: list[str] = []
    for f in files:
        content = _read_safe(f)
        for anchor in _CANONICAL_ANCHORS:
            if anchor in content:
                found.append(f"{anchor[:12]}… in {f.name}")
                break
    if found:
        return "PASS", f"{len(found)} canonical hash(es) found — {', '.join(found[:4])}"
    return "FAIL", ("No canonical delegation_ref vector hashes found. Run the conformance "
                    "suite against the canonical vectors and embed at least one hash.")


def check_notice(root: Path | None, explicit_notice: Path | None) -> tuple[str, str]:
    candidates: list[Path] = []
    if explicit_notice:
        candidates.append(explicit_notice)
    if root:
        for name in _NOTICE_NAMES:
            if (root / name).exists():
                candidates.append(root / name)
        for child in root.iterdir():
            if child.is_dir() and child.name not in _SKIP_DIRS:
                for name in _NOTICE_NAMES:
                    if (child / name).exists():
                        candidates.append(child / name)
    for notice in candidates:
        content = _read_safe(notice)
        has_algovoi = bool(re.search(r"algovoi", content, re.IGNORECASE))
        has_pkg = bool(re.search(r"algovoi.delegation.ref", content, re.IGNORECASE))
        if has_algovoi and has_pkg:
            return "PASS", f"NOTICE attribution confirmed in {notice.name}"
        if has_algovoi:
            return "FAIL", f"{notice.name} mentions AlgoVoi but not algovoi-delegation-ref."
    if candidates:
        return "FAIL", f"NOTICE file {candidates[0].name} does not mention AlgoVoi."
    return "FAIL", "No NOTICE file found (Apache-2.0 requires preserving it)."


def check_version_pin(files: list[Path]) -> tuple[str, str]:
    for f in [f for f in files if _is_lockfile(f)]:
        content = _read_safe(f)
        if _HASH_RE.search(content):
            return "PASS", "wheel hash pin found (strongest)"
        if _PIN_RE.search(content):
            return "PASS", "version pin found (==0.1.0 or similar)"
    return "FAIL", "No specific version pin found. Pin to algovoi-delegation-ref==0.1.0."


_ICONS = {"PASS": "[PASS]", "FAIL": "[FAIL]", "WARN": "[WARN]"}


def run_checks(root: Path | None, explicit_lockfile: Path | None,
               explicit_notice: Path | None) -> int:
    print("\nAlgoVoi delegation-ref v0 Adoption Check\n" + "=" * 50)
    if root:
        print(f"Project: {root}")
    all_files: list[Path] = _text_files(root) if root else []
    if explicit_lockfile and explicit_lockfile.exists():
        all_files.append(explicit_lockfile)

    results = {
        "dependency": check_dependency(all_files),
        "vector_anchor": check_vector_anchor(all_files),
        "notice": check_notice(root, explicit_notice),
        "version_pin": check_version_pin(all_files),
    }
    labels = {"dependency": "Dependency declaration", "vector_anchor": "Vector hash anchor    ",
              "notice": "NOTICE attribution    ", "version_pin": "Version pin           "}
    for key, label in labels.items():
        status, detail = results[key]
        print(f"  {_ICONS[status]} {label} — {detail}")

    failures = [k for k in results if results[k][0] == "FAIL"]
    print()
    if failures:
        print(f"RESULT: REJECT  ({len(failures)} required check(s) failed: {', '.join(failures)})")
        return 2
    print("RESULT: ISSUE_V0_KEY  (all checks passed)")
    print("  Sign a v0 licence key for 'algovoi-mandate-auditor' (tier: v0) and deliver via chopmob@gmail.com.")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Check whether a project qualifies for a free AlgoVoi delegation-ref v0 key.")
    parser.add_argument("project_dir", nargs="?", type=Path)
    parser.add_argument("--lockfile", "-l", type=Path)
    parser.add_argument("--notice", "-n", type=Path)
    args = parser.parse_args()
    if not args.project_dir and not args.lockfile:
        parser.print_help()
        sys.exit(3)
    root = args.project_dir.resolve() if args.project_dir else None
    if root and not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        sys.exit(3)
    sys.exit(run_checks(root, args.lockfile, args.notice))


if __name__ == "__main__":
    main()
