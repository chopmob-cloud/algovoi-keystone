"""Pin every import to the source tree under test.

A suite that silently imported an older installed copy from site-packages reported
266 passing tests for a repository it never executed. Before collecting anything,
put each project directory in this repo at the front of ``sys.path`` so a stale
wheel can never shadow the code being tested.
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent
_SKIP = {"build", "dist", "node_modules", "__pycache__", ".git"}

_roots = []
for pp in sorted(ROOT.glob("**/pyproject.toml")):
    d = pp.parent
    if any(part in _SKIP for part in d.relative_to(ROOT).parts):
        continue
    # a project dir holds the importable package(s) beside its pyproject
    if any((child / "__init__.py").exists() for child in d.iterdir() if child.is_dir()):
        _roots.append(d)

for d in reversed(_roots):  # keep the first-listed project first on sys.path
    s = str(d)
    if s in sys.path:
        sys.path.remove(s)
    sys.path.insert(0, s)

if _roots:
    print(f"[conftest] pinned {len(_roots)} source roots ahead of site-packages")
