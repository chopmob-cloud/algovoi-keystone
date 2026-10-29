"""Standardise the estate on version 0.4.0 with consistent metadata.

- sets [project].version = 0.4.0 in every package
- sets the matching __version__ literal in the package's real module (build/ excluded)
- raises first-party dependency floors from >=0.1.0 to >=0.4.0
- unifies rfc8785 floors to >=0.1.4 (matches the substrate's own requirement)
Every edited file is re-parsed; a file that fails to parse is restored from its original bytes.
"""
from __future__ import annotations
import pathlib, re, sys, tomllib

TARGET = "0.4.0"
PATTERNS = ["packages/*/pyproject.toml", "plugins/*/python/pyproject.toml",
            "adapters/*/python/pyproject.toml"]
FIRST_PARTY = ("algovoi-execution-ref", "algovoi-keystone-agent",
               "algovoi-keystone-connect", "algovoi-keystone-runtime")

root = pathlib.Path(".").resolve()
apply = "--apply" in sys.argv
changes: list[str] = []
problems: list[str] = []


def set_version(text: str) -> tuple[str, bool]:
    new, n = re.subn(r'(?m)^version\s*=\s*"[^"]+"', f'version = "{TARGET}"', text, count=1)
    return new, n > 0 and new != text


def bump_deps(text: str) -> tuple[str, list[str]]:
    notes = []
    for pkg in FIRST_PARTY:
        pat = re.compile(rf'"{re.escape(pkg)}>=0\.1\.0"')
        if pat.search(text):
            text = pat.sub(f'"{pkg}>={TARGET}"', text)
            notes.append(f"{pkg} >=0.1.0 -> >={TARGET}")
    if '"rfc8785>=0.1.2"' in text:
        text = text.replace('"rfc8785>=0.1.2"', '"rfc8785>=0.1.4"')
        notes.append("rfc8785 >=0.1.2 -> >=0.1.4")
    return text, notes


def module_inits(pkg_root: pathlib.Path) -> list[pathlib.Path]:
    out = []
    for d in pkg_root.iterdir():
        if not d.is_dir() or d.name in ("build", "dist", "node_modules", "__pycache__"):
            continue
        init = d / "__init__.py"
        if init.exists() and d.name.startswith("algovoi"):
            out.append(init)
    return out


for pattern in PATTERNS:
    for pp in sorted(root.glob(pattern)):
        pkg_root = pp.parent
        raw = pp.read_bytes()
        text = raw.decode("utf-8")
        try:
            before = tomllib.loads(text)
        except Exception as e:
            problems.append(f"{pp}: pre-parse {e}")
            continue

        new_text, ver_changed = set_version(text)
        new_text, dep_notes = bump_deps(new_text)
        if new_text != text:
            try:
                tomllib.loads(new_text)
            except Exception as e:
                pp.write_bytes(raw)
                problems.append(f"{pp}: post-parse {e} — ROLLED BACK")
                continue
            if apply:
                pp.write_text(new_text, encoding="utf-8", newline="\n")
            changes.append(f"{pp.relative_to(root)}: version {before['project']['version']} -> {TARGET}"
                           + (f"; {', '.join(dep_notes)}" if dep_notes else ""))

        for init in module_inits(pkg_root):
            itext = init.read_text(encoding="utf-8")
            new_i = re.sub(r'(?m)^__version__\s*=\s*"[^"]+"', f'__version__ = "{TARGET}"', itext)
            if new_i != itext:
                if apply:
                    init.write_text(new_i, encoding="utf-8", newline="\n")
                old = re.search(r'^__version__\s*=\s*"([^"]+)"', itext, re.M)
                changes.append(f"{init.relative_to(root)}: __version__ {old.group(1)} -> {TARGET}")

print(f"changes: {len(changes)}  problems: {len(problems)}")
for c in changes:
    print("  +", c)
for p in problems:
    print("  !", p)
sys.exit(1 if problems else 0)
