"""Pin every import to the source tree under test.

A suite that silently imported an older installed copy from site-packages reported
266 passing tests for a repository it never executed. Before collecting anything,
put each project directory in this repo at the front of ``sys.path`` so a stale
wheel can never shadow the code being tested.

The pinning itself lives in ``tools/source_roots.py`` so CI can assert against
exactly the same list pytest runs under (``python tools/source_roots.py --verify``).
"""
import importlib.util
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent

_spec = importlib.util.spec_from_file_location(
    "_keystone_source_roots", ROOT / "tools" / "source_roots.py"
)
_source_roots = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_source_roots)

_roots = _source_roots.pin(ROOT)

if _roots:
    print(f"[conftest] pinned {len(_roots)} source roots ahead of site-packages")
