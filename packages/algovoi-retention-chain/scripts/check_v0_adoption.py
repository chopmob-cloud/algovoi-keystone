#!/usr/bin/env python3
"""AlgoVoi v0 adoption check — run before issuing a free v0 licence key.

Usage:
  python scripts/check_v0_adoption.py /path/to/submitted/project
  python scripts/check_v0_adoption.py --lockfile /path/to/requirements.txt [--notice /path/to/NOTICE]

Three required checks must all pass before issuing a key:

  1. DEPENDENCY DECLARATION  -- algovoi-retention-chain appears in a lockfile or
                                 manifest (any supported language).
  2. VECTOR HASH ANCHOR      -- at least one of the 6 canonical chain_ref / receipt_hash
                                 hex strings from retention-chain-v1.json appears in the
                                 project.  This is the hard evidence they ran our conformance
                                 suite against our exact vectors, not a reimplementation.
  3. NOTICE ATTRIBUTION      -- a NOTICE (or NOTICE.txt / NOTICE.md) file exists and
                                 mentions both "AlgoVoi" and "algovoi-retention-chain".

  4. VERSION PIN             -- the package is pinned to a specific version (e.g. ==0.1.0
                                 or a wheel hash), not just an open range (>=0.1.0).
                                 A bare range does not qualify — the pin proves structural
                                 commitment to a specific, immutable import.

Exit codes:
  0  ISSUE_V0_KEY  -- all required checks passed
  1  HOLD          -- required checks passed but advisory warnings present (review manually)
  2  REJECT        -- one or more required checks failed

Internal use only.  Not shipped in the wheel.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Canonical vector anchors from chopmob-cloud/algovoi-jcs-conformance-vectors.
# Any of these 64-hex strings appearing in the project proves the adopter
# ran conformance against the canonical vectors.
# Source: retention_chain_v0 (3 vectors) + retention_chain_v1 (14 vectors), both
# cross-validated 8-impl 2026-06-16/17.
# ---------------------------------------------------------------------------
_CANONICAL_ANCHORS: list[str] = [
    # retention_chain_v0 — chain_ref hashes (seq 0, 1, 2; issuer_id=algovoi:test)
    "f15a1dcd03cc039204dff24619ff4815ad041ad8796b94f59d52252043d0d08f",
    "7114dc39543710bf26d0a5825acddd915ffd51fb5b14503024f70fda403053d9",
    "d3bddca79477e6003cb6ef199897bffed185f5d785b4e7333f9b0585b2b81144",
    # retention_chain_v0 — receipt_hash values (sha256("receipt_N"))
    "24c3e22bc6ece631e4524e3beeb904553fbb1cd6fd124e1cb3c68a9a277ba23a",
    "55d4a60cbf6928423fd1cd0e06f7cccd98011e9064240a3fd24f7c6bbae8266a",
    "08a132f9262230f24640a591c60a08e756d313dbf15ff578b4c10fdd30120a4a",
    # retention_chain_v1 Part A — chain_ref hashes (seq 0–5; issuer_id=algovoi:compliance)
    "60081d57e585e6a7ee0b79e1204aae2be3739a539c6524074003408b3de1951e",
    "d23aeb006c5f3db9dd96315916410393904f56c4c871593065eb73b783fff35f",
    "43f888f00ea70e38fb8e38c205219b3fff51a90c62197d890b9f270f0f81fe42",
    "deeb8fb8d1e59de0493c26c461bf015d1461320cb54d172d36a4a0384147ae5b",
    "6c76bc81c6ed4101ab15d7c2ac1c0cac255cd774665c8807586e8407b832dad5",
    "e91e6f680c8c92ca2b751d8d0dcb801f4eadcfd5e590e100f4591ea3031d0d57",
    # retention_chain_v1 Part B — issuer isolation chain_refs
    "52ef8da2c45178c5f2aef027d6c1e838d1f044dabb41596a639624cea5b57f83",
    "ced0cd4cc8d9446b17fca7ff57ed9508a9d5b50fce45a93d4a7e83779012810e",
    "683eb369f960cdea868414ebf8fb4d692af09afa9e5b94c91dc093448117a042",
    "7aa77a429f476fee8d09e6e2044b7f4c40277cbc250d9676110fb6fb68441b90",
    # retention_chain_v1 Part C — seq-gap adversarial pair chain_refs
    "9c589d9657146e062d4a91cf3a4bf92c98cbb6fcde0d509a84e020675ad8c7ea",
    "2277ec545e5540a60b54c706b533c8962df61fb9a9c92de417d3808bd7be3cef",
]

# Package names across ecosystems.
_PACKAGE_PATTERNS: list[re.Pattern] = [
    re.compile(r"algovoi[-_]retention[-_]chain", re.IGNORECASE),  # Python / Rust
    re.compile(r"algovoi/retention-chain", re.IGNORECASE),         # Go
    re.compile(r"@algovoi/retention-chain", re.IGNORECASE),        # Node
    re.compile(r"AlgoVoi\.RetentionChain", re.IGNORECASE),         # C# / NuGet
    re.compile(r"io\.algovoi[:/]retention.chain", re.IGNORECASE),  # Maven / Gradle
]

# Lockfile / manifest names to scan for dependency declarations.
_LOCKFILE_NAMES: set[str] = {
    "requirements.txt", "requirements-lock.txt", "constraints.txt",
    "pyproject.toml", "setup.cfg", "setup.py",
    "poetry.lock", "Pipfile", "Pipfile.lock",
    "go.mod", "go.sum",
    "Cargo.toml", "Cargo.lock",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "Gemfile", "Gemfile.lock",
    "pom.xml", "build.gradle", "build.gradle.kts",
    "packages.lock.json", "*.csproj",
}

# NOTICE file candidates.
_NOTICE_NAMES: set[str] = {"NOTICE", "NOTICE.txt", "NOTICE.md", "NOTICE.rst"}

# Directories to skip when walking a project tree.
_SKIP_DIRS: set[str] = {
    ".git", ".hg", "node_modules", "__pycache__", ".tox", ".venv",
    "venv", "env", "dist", "build", "target", ".gradle",
}

# File extensions to scan for vector anchors (text-ish only).
_TEXT_EXTENSIONS: set[str] = {
    ".py", ".ts", ".js", ".go", ".rs", ".rb", ".cs", ".java", ".kt",
    ".toml", ".json", ".yaml", ".yml", ".txt", ".md", ".lock", ".sum",
    ".cfg", ".ini", ".env",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _text_files(root: Path) -> list[Path]:
    """Walk root, yield text-ish files (skip VCS / build dirs)."""
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
    if p.name in _LOCKFILE_NAMES:
        return True
    if p.suffix == ".csproj":
        return True
    return False


# ---------------------------------------------------------------------------
# Check 1: dependency declaration
# ---------------------------------------------------------------------------

def check_dependency(files: list[Path]) -> tuple[str, str]:
    """Return (status, detail). status in {PASS, FAIL}."""
    lockfiles = [f for f in files if _is_lockfile(f)]
    hits: list[str] = []
    for lf in lockfiles:
        content = _read_safe(lf)
        for pat in _PACKAGE_PATTERNS:
            if pat.search(content):
                hits.append(str(lf.name))
                break
    if hits:
        unique = sorted(set(hits))
        return "PASS", f"algovoi-retention-chain found in: {', '.join(unique)}"
    return "FAIL", (
        "algovoi-retention-chain not found in any lockfile or manifest. "
        "Expected in: requirements.txt / pyproject.toml / go.mod / Cargo.toml / package.json / etc."
    )


# ---------------------------------------------------------------------------
# Check 2: vector hash anchor
# ---------------------------------------------------------------------------

def check_vector_anchor(files: list[Path]) -> tuple[str, str]:
    """Return (status, detail). status in {PASS, FAIL}."""
    found: list[tuple[str, str, int]] = []  # (hash_prefix, filename, lineno)
    for f in files:
        content = _read_safe(f)
        for anchor in _CANONICAL_ANCHORS:
            if anchor in content:
                # Find which line
                for i, line in enumerate(content.splitlines(), 1):
                    if anchor in line:
                        found.append((anchor[:12] + "…", f.name, i))
                        break
    if found:
        detail_lines = [f"{h} in {fn}:{ln}" for h, fn, ln in found[:4]]
        extra = f" (+{len(found)-4} more)" if len(found) > 4 else ""
        return "PASS", f"{len(found)} canonical hash(es) found — {', '.join(detail_lines)}{extra}"
    return "FAIL", (
        "No canonical retention-chain-v1.json hashes found. "
        "The adopter must run the conformance suite against the canonical vectors and "
        "commit the results (or embed at least one hash) to demonstrate actual usage."
    )


# ---------------------------------------------------------------------------
# Check 3: NOTICE attribution
# ---------------------------------------------------------------------------

def check_notice(root: Path | None, explicit_notice: Path | None) -> tuple[str, str]:
    """Return (status, detail). status in {PASS, FAIL}."""
    candidates: list[Path] = []
    if explicit_notice:
        candidates.append(explicit_notice)
    if root:
        for name in _NOTICE_NAMES:
            p = root / name
            if p.exists():
                candidates.append(p)
        # Also look one level deep.
        for child in root.iterdir():
            if child.is_dir() and child.name not in _SKIP_DIRS:
                for name in _NOTICE_NAMES:
                    p = child / name
                    if p.exists():
                        candidates.append(p)

    for notice in candidates:
        content = _read_safe(notice)
        has_algovoi = bool(re.search(r"algovoi", content, re.IGNORECASE))
        has_pkg = bool(re.search(r"algovoi.retention.chain", content, re.IGNORECASE))
        if has_algovoi and has_pkg:
            return "PASS", f"NOTICE attribution confirmed in {notice.name}"
        if has_algovoi:
            return "FAIL", (
                f"{notice.name} mentions AlgoVoi but not algovoi-retention-chain. "
                "Full Apache-2.0 attribution requires the package name."
            )

    if candidates:
        return "FAIL", (
            f"NOTICE file found ({candidates[0].name}) but does not mention AlgoVoi. "
            "Apache-2.0 requires preserving the NOTICE file from the upstream package."
        )
    return "FAIL", (
        "No NOTICE file found. Apache-2.0 requires a NOTICE file attributing AlgoVoi "
        "and algovoi-retention-chain when distributing a work built on this package."
    )


# ---------------------------------------------------------------------------
# Check 4: version pin (REQUIRED)
# ---------------------------------------------------------------------------

_PIN_RE = re.compile(
    r"algovoi[-_]retention[-_]chain\s*(==|~=|@)",  # exact pin, compatible release, or direct ref
    re.IGNORECASE,
)
_HASH_RE = re.compile(
    r"algovoi[-_]retention[-_]chain[^\n]*--hash",   # pip hash pin
    re.IGNORECASE,
)

def check_version_pin(files: list[Path]) -> tuple[str, str]:
    """Return (status, detail). status in {PASS, FAIL}.

    A specific version pin (==0.1.0) or wheel --hash is required.
    A bare range (>=0.1.0) does not qualify — pinning proves the adopter
    has committed to a specific, immutable import rather than a moving target.
    """
    for f in [f for f in files if _is_lockfile(f)]:
        content = _read_safe(f)
        if _HASH_RE.search(content):
            return "PASS", "wheel hash pin found (strongest)"
        if _PIN_RE.search(content):
            return "PASS", "version pin found (==0.1.0 or similar)"
    return "FAIL", (
        "No specific version pin found. Pin to algovoi-retention-chain==0.1.0 "
        "(or a wheel --hash) in your lockfile. A bare range (>=0.1.0) does not qualify — "
        "the pin proves structural commitment to a specific, immutable import."
    )


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

_ICONS = {"PASS": "[PASS]", "FAIL": "[FAIL]", "WARN": "[WARN]"}


def run_checks(
    root: Path | None,
    explicit_lockfile: Path | None,
    explicit_notice: Path | None,
) -> int:
    """Run all checks and print a report. Return exit code."""
    print()
    print("AlgoVoi v0 Adoption Check")
    print("=" * 50)
    if root:
        print(f"Project: {root}")
    if explicit_lockfile:
        print(f"Lockfile: {explicit_lockfile}")
    if explicit_notice:
        print(f"Notice:  {explicit_notice}")
    print()

    # Collect files.
    all_files: list[Path] = []
    if root:
        all_files = _text_files(root)
    if explicit_lockfile and explicit_lockfile.exists():
        all_files.append(explicit_lockfile)

    results: dict[str, tuple[str, str]] = {}

    results["dependency"] = check_dependency(all_files)
    results["vector_anchor"] = check_vector_anchor(all_files)
    results["notice"] = check_notice(root, explicit_notice)
    results["version_pin"] = check_version_pin(all_files)

    labels = {
        "dependency":    "Dependency declaration",
        "vector_anchor": "Vector hash anchor    ",
        "notice":        "NOTICE attribution    ",
        "version_pin":   "Version pin           ",
    }

    required = {"dependency", "vector_anchor", "notice", "version_pin"}

    for key, label in labels.items():
        status, detail = results[key]
        print(f"  {_ICONS[status]} {label} — {detail}")

    required_failures = [k for k in required if results[k][0] == "FAIL"]
    advisory_warnings = [k for k in results if k not in required and results[k][0] == "WARN"]

    print()
    if required_failures:
        print(f"RESULT: REJECT")
        print(f"  {len(required_failures)} required check(s) failed: {', '.join(required_failures)}")
        print()
        print("  Do NOT issue a v0 key until all required checks pass.")
        print("  Ask the applicant to remedy the failing checks and resubmit.")
        return 2
    elif advisory_warnings:
        print("RESULT: HOLD — review manually before issuing")
        print(f"  All required checks passed; {len(advisory_warnings)} advisory warning(s).")
        print()
        print("  Decide whether the advisory warning(s) are acceptable,")
        print("  then issue or decline at your discretion.")
        print("  To issue: sign a v0 licence key for algovoi-mandate-auditor and email to the applicant.")
        return 1
    else:
        print("RESULT: ISSUE_V0_KEY")
        print("  All checks passed.")
        print()
        print("  Sign a v0 licence key for 'algovoi-mandate-auditor' (tier: v0)")
        print("  and deliver it to the applicant via chopmob@gmail.com.")
        return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check whether a project qualifies for a free AlgoVoi v0 licence key.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "project_dir",
        nargs="?",
        type=Path,
        help="Root of the submitted project to scan.",
    )
    parser.add_argument(
        "--lockfile", "-l",
        type=Path,
        help="Path to a single lockfile (use instead of or alongside project_dir).",
    )
    parser.add_argument(
        "--notice", "-n",
        type=Path,
        help="Path to the NOTICE file (if not at the project root).",
    )
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
