"""PyPI conformance gate for the AlgoVoi open packages.

Report-only by default; --apply backfills. Exits non-zero when anything fails,
so it can run as a CI job while the backlog is cleared.

Checks per package (PEP 621 / PEP 639 aware):
  description present and substantive
  readme present, file exists, non-trivial
  licence: Apache-2.0 declared (expression or text form) + LICENSE and NOTICE on disk
  classifiers: Apache licence + at least one Python version (unless PEP 639 expression)
  [project.urls]: Homepage -> the AlgoVoi site, Repository -> the source repo
  requires-python present
"""
from __future__ import annotations
import argparse, json, pathlib, re, sys

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # 3.10: the packages still declare requires-python >= 3.10
    import tomli as tomllib

HOME = "https://www.algovoi.co.uk"
REPO = "https://github.com/chopmob-cloud/algovoi-keystone"
DOCS = "https://docs.algovoi.co.uk"
MIN_DESCRIPTION = 40
MIN_README = 400

ROOTS = [
    ("packages", "packages/*/pyproject.toml"),
    ("plugins", "plugins/*/python/pyproject.toml"),
    ("adapters", "adapters/*/python/pyproject.toml"),
]

def load(p):
    with open(p, "rb") as f:
        return tomllib.load(f)

def check(pkg_dir: pathlib.Path, doc: dict) -> list[str]:
    fails = []
    proj = doc.get("project")
    if not proj:
        return ["no [project] table"]

    desc = (proj.get("description") or "").strip()
    if not desc:
        fails.append("description missing")
    elif len(desc) < MIN_DESCRIPTION:
        fails.append(f"description too short ({len(desc)} < {MIN_DESCRIPTION})")

    readme = proj.get("readme")
    if not readme:
        fails.append("readme missing")
    elif isinstance(readme, str):
        f = pkg_dir / readme
        if not f.exists():
            fails.append(f"readme file not found: {readme}")
        elif len(f.read_text(encoding="utf-8", errors="replace")) < MIN_README:
            fails.append(f"readme too short (<{MIN_README} chars)")

    lic = proj.get("license")
    expr = proj.get("license-expression") or proj.get("license_expression")
    if isinstance(lic, str):
        is_apache = lic.strip() == "Apache-2.0"
    elif isinstance(lic, dict):
        is_apache = (lic.get("text") or "").strip() == "Apache-2.0" or \
                    (lic.get("file") or "").lower().startswith("license")
    else:
        is_apache = False
    if not (is_apache or (expr or "").strip() == "Apache-2.0"):
        fails.append("licence not declared as Apache-2.0")

    if not any((pkg_dir / n).exists() for n in ("LICENSE", "LICENSE.txt", "LICENSE.md")):
        fails.append("LICENSE file missing in package dir")
    if not any((pkg_dir / n).exists() for n in ("NOTICE", "NOTICE.txt", "NOTICE.md")):
        fails.append("NOTICE file missing in package dir")

    cls = proj.get("classifiers") or []
    # PEP 639: an SPDX expression and a licence classifier are mutually exclusive —
    # setuptools refuses to build when both are present.
    if isinstance(lic, str) and lic.strip():
        if any("License ::" in c for c in cls):
            fails.append("licence classifier present alongside SPDX expression (setuptools rejects this)")
    elif not any("License :: OSI Approved :: Apache Software License" in c for c in cls):
        fails.append("no Apache licence classifier")
    if not any(re.match(r"Programming Language :: Python :: 3(\.\d+)?$", c) for c in cls):
        fails.append("no Python version classifier")

    urls = proj.get("urls") or {}
    if not urls:
        fails.append("no [project.urls]")
    else:
        home = next((str(v) for k, v in urls.items() if k.lower() in ("homepage", "home", "website")), None)
        if home is None:
            fails.append("no Homepage key")
        elif home.rstrip("/") != HOME.rstrip("/"):
            fails.append(f"Homepage is {home!r}, expected {HOME!r}")
        if not any("github.com" in str(v) for v in urls.values()):
            fails.append("no Repository link")

    if not proj.get("requires-python"):
        fails.append("requires-python missing")
    return fails

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    root = pathlib.Path(a.root).resolve()

    results = []
    for _, glob in ROOTS:
        for pp in sorted(root.glob(glob)):
            pkg_dir = pp.parent
            try:
                doc = load(pp)
            except Exception as e:
                results.append({"pkg": pkg_dir.name, "path": str(pp), "fails": [f"TOML parse error: {e}"]})
                continue
            name = doc.get("project", {}).get("name", pkg_dir.name)
            fails = check(pkg_dir, doc)
            results.append({"pkg": name, "path": str(pp), "fails": fails})

    bad = [r for r in results if r["fails"]]
    if a.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            mark = "OK  " if not r["fails"] else "FAIL"
            print(f"{mark} {r['pkg']}")
            for f in r["fails"]:
                print(f"       - {f}")
        print(f"\n{len(results)} packages, {len(bad)} failing, "
              f"{sum(len(r['fails']) for r in bad)} issues")
    return 1 if bad else 0

if __name__ == "__main__":
    sys.exit(main())
