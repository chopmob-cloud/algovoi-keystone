"""Force Homepage to the canonical AlgoVoi site across every package, preserving other URLs."""
from __future__ import annotations
import pathlib, re, sys, tomllib

HOME = "https://www.algovoi.co.uk"
PATTERNS = ["packages/*/pyproject.toml", "plugins/*/python/pyproject.toml",
            "adapters/*/python/pyproject.toml"]
apply = "--apply" in sys.argv
root = pathlib.Path(".").resolve()
changed, problems = [], []

for pattern in PATTERNS:
    for pp in sorted(root.glob(pattern)):
        raw = pp.read_bytes()
        text = raw.decode("utf-8")
        try:
            doc = tomllib.loads(text)
        except Exception as e:
            problems.append(f"{pp}: pre-parse {e}")
            continue
        urls = doc.get("project", {}).get("urls") or {}
        if not urls:
            continue
        home_keys = [k for k in urls if k.lower() in ("homepage", "home", "website")]
        if home_keys and str(urls[home_keys[0]]).rstrip("/") == HOME:
            continue
        key = home_keys[0] if home_keys else "Homepage"
        if home_keys:
            text2 = re.sub(rf'(?m)^({re.escape(key)}\s*=\s*)"[^"]*"', rf'\1"{HOME}"', text, count=1)
        else:
            m = re.search(r"^\[project\.urls\]\s*$", text, re.M)
            text2 = text[:m.end()] + f'\n{key} = "{HOME}"' + text[m.end():]
        if text2 == text:
            problems.append(f"{pp}: no change applied")
            continue
        try:
            after = tomllib.loads(text2)
        except Exception as e:
            pp.write_bytes(raw)
            problems.append(f"{pp}: post-parse {e} — ROLLED BACK")
            continue
        got = (after["project"]["urls"] or {}).get(key)
        if got != HOME:
            pp.write_bytes(raw)
            problems.append(f"{pp}: Homepage not canonical after edit — ROLLED BACK")
            continue
        if apply:
            pp.write_text(text2, encoding="utf-8", newline="\n")
        changed.append(f"{pp.relative_to(root)}: {key} -> {HOME}")

print(f"changed: {len(changed)}  problems: {len(problems)}")
for c in changed:
    print("  +", c)
for p in problems:
    print("  !", p)
sys.exit(1 if problems else 0)
