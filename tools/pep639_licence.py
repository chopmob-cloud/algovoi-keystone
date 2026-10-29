"""Standardise every package on PEP 639 licence metadata.

Replaces the legacy `license = { text = "Apache-2.0" }` table with the SPDX
expression form `license = "Apache-2.0"`, adds `license-files`, and removes the
`License :: OSI Approved :: Apache Software License` classifier, which setuptools
now rejects alongside an expression.

Every edit is re-parsed; a file that fails to parse is restored from original bytes.
"""
from __future__ import annotations
import pathlib, re, sys, tomllib

PATTERNS = ["packages/*/pyproject.toml", "plugins/*/python/pyproject.toml",
            "adapters/*/python/pyproject.toml",
            "control/pyproject.toml"]
LICENCE_CLASSIFIER = "License :: OSI Approved :: Apache Software License"

root = pathlib.Path(".").resolve()
apply = "--apply" in sys.argv
changes, problems = [], []

for pattern in PATTERNS:
    for pp in sorted(root.glob(pattern)):
        raw = pp.read_bytes()
        text = raw.decode("utf-8")
        try:
            doc = tomllib.loads(text)
        except Exception as e:
            problems.append(f"{pp}: pre-parse {e}")
            continue
        proj = doc.get("project", {})
        orig = text
        notes = []

        # 1. legacy table -> SPDX expression
        lic = proj.get("license")
        if isinstance(lic, dict) and (lic.get("text") or "").strip() == "Apache-2.0":
            text = re.sub(r'(?m)^license\s*=\s*\{\s*text\s*=\s*"Apache-2\.0"\s*\}\s*$',
                          'license = "Apache-2.0"', text, count=1)
            notes.append("license table -> SPDX expression")
        elif isinstance(lic, dict) and lic.get("file"):
            text = re.sub(r'(?m)^license\s*=\s*\{\s*file\s*=\s*"[^"]+"\s*\}\s*$',
                          'license = "Apache-2.0"', text, count=1)
            notes.append("license file ref -> SPDX expression")

        # 2. license-files alongside the expression
        if "license-files" not in proj:
            m = re.search(r'(?m)^(license\s*=\s*"Apache-2\.0"\s*)$', text)
            if m:
                text = text[:m.end()] + '\nlicense-files = ["LICENSE", "NOTICE"]' + text[m.end():]
                notes.append("added license-files")

        # 3. drop the now-invalid licence classifier
        if LICENCE_CLASSIFIER in text:
            text = re.sub(r'(?m)^\s*"' + re.escape(LICENCE_CLASSIFIER) + r'",?\s*\n', '', text)
            notes.append("removed licence classifier")

        if text != orig:
            try:
                after = tomllib.loads(text)
            except Exception as e:
                pp.write_bytes(raw)
                problems.append(f"{pp}: post-parse {e} — ROLLED BACK")
                continue
            if after.get("project", {}).get("license") != "Apache-2.0":
                pp.write_bytes(raw)
                problems.append(f"{pp}: licence not an expression after edit — ROLLED BACK")
                continue
            if apply:
                pp.write_text(text, encoding="utf-8", newline="\n")
            changes.append(f"{pp.relative_to(root)}: {'; '.join(notes)}")

print(f"changes: {len(changes)}  problems: {len(problems)}")
for c in changes:
    print("  +", c)
for p in problems:
    print("  !", p)
sys.exit(1 if problems else 0)
