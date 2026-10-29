"""The single source of truth for "which directories in this repo are projects".

Both ``conftest.py`` (so pytest can never import a stale wheel) and CI use this
module, so the import order the tests run under and the order CI asserts cannot
drift apart.

    python tools/source_roots.py            # print them, os.pathsep-joined
    python tools/source_roots.py --verify   # pin them, then prove every package
                                            # resolves inside this tree
"""
from __future__ import annotations

import argparse
import importlib
import os
import pathlib
import sys

SKIP = {"build", "dist", "node_modules", "__pycache__", ".git", ".venv", "venv", ".tox"}
MARKER = "pyproject.toml"


def project_roots(root):
    """Every project dir: a ``pyproject.toml`` with an importable package beside it."""
    root = pathlib.Path(root).resolve()
    roots = []
    for pp in sorted(root.glob("**/" + MARKER)):
        d = pp.parent
        if any(part in SKIP for part in d.relative_to(root).parts):
            continue
        # a project dir holds the importable package(s) beside its pyproject
        if any((child / "__init__.py").exists() for child in d.iterdir() if child.is_dir()):
            roots.append(d)
    return roots


def pin(root, path=None):
    """Put every project dir at the front of ``sys.path``.

    Inserted in reverse so the first-listed project ends up first on the path.
    """
    path = sys.path if path is None else path
    roots = project_roots(root)
    for d in reversed(roots):
        s = str(d)
        if s in path:
            path.remove(s)
        path.insert(0, s)
    return roots


def verify(root):
    """Import every package in the tree and prove none came from site-packages.

    This is the guard against the failure that made a green suite meaningless:
    266 passing tests for a repository that was never executed.
    """
    root = pathlib.Path(root).resolve()
    roots = pin(root)
    checked, bad = 0, []
    for d in roots:
        for pkg in sorted(p for p in d.iterdir() if p.is_dir() and (p / "__init__.py").exists()):
            if not pkg.name.isidentifier():
                bad.append(f"{pkg.name}: not a valid package name")
                continue
            try:
                mod = importlib.import_module(pkg.name)
            except Exception as exc:  # noqa: BLE001 - report, do not mask
                bad.append(f"{pkg.name}: import failed: {exc!r}")
                continue
            checked += 1
            src = pathlib.Path(getattr(mod, "__file__", "") or "").resolve()
            if root not in src.parents:
                bad.append(f"{pkg.name}: imported from outside the tree: {src}")
    if bad:
        print(f"FAIL: {len(bad)} package(s) not served by the tree under test", file=sys.stderr)
        for line in bad:
            print("  " + line, file=sys.stderr)
        return 1
    print(f"OK: {checked} packages imported from the tree under test ({len(roots)} source roots)")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=pathlib.Path(__file__).resolve().parent.parent,
                    help="repository root (default: the parent of tools/)")
    ap.add_argument("--verify", action="store_true",
                    help="import every package and assert it resolves inside --root")
    args = ap.parse_args(argv)

    root = pathlib.Path(args.root).resolve()
    if args.verify:
        return verify(root)
    roots = project_roots(root)
    print(f"[source_roots] {len(roots)} project dirs under {root}", file=sys.stderr)
    print(os.pathsep.join(str(d) for d in roots))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
