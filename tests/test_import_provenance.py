"""Every importable project in this repo must resolve to the tree under test.

A green suite once reported 266 passing tests for a repository it never executed:
pytest imported an older installed copy from site-packages. ``conftest.py`` pins the
source roots; this test asserts the pin actually took effect, so the false-green
failure mode cannot return silently.
"""
import importlib
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]


def _module_dirs():
    """Each project directory that holds an importable package beside its pyproject."""
    out = []
    for pp in sorted(REPO.glob("**/pyproject.toml")):
        d = pp.parent
        if any(part in {"build", "dist", "node_modules", "__pycache__", ".git"}
               for part in d.relative_to(REPO).parts):
            continue
        for child in d.iterdir():
            if child.is_dir() and (child / "__init__.py").exists() and child.name.startswith("algovoi"):
                out.append((child.name, d))
    return out


def test_source_roots_are_pinned_ahead_of_site_packages():
    pinned = [p for p in sys.path if str(REPO) in p]
    assert pinned, "conftest.py did not pin any source roots"
    # nothing imported from the repo may be shadowed by an installed copy
    site = [p for p in sys.path if "site-packages" in p]
    if site:
        first_site = min(sys.path.index(p) for p in site)
        assert sys.path.index(pinned[0]) < first_site, (
            "a site-packages entry precedes the source roots; a stale wheel can shadow the tree"
        )


def test_every_project_module_resolves_inside_the_repo():
    modules = _module_dirs()
    assert len(modules) >= 28, f"expected the whole estate, found {len(modules)}"
    wrong = []
    for name, _ in modules:
        try:
            mod = importlib.import_module(name)
        except Exception as exc:  # import errors are a different test's problem
            wrong.append((name, f"import failed: {type(exc).__name__}: {exc}"))
            continue
        path = getattr(mod, "__file__", "") or ""
        resolved = pathlib.Path(path).resolve()
        if REPO.resolve() not in resolved.parents:
            wrong.append((name, path))
    assert not wrong, f"modules resolved outside the repo: {wrong}"
