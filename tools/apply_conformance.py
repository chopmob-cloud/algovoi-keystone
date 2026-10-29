"""Backfill PyPI metadata gaps detected by conformance.py.

Text-preserving and idempotent: adds [project.urls] (Homepage/Repository/Documentation),
missing classifiers and requires-python. Every edit is re-parsed with tomllib; a file that
no longer parses, or that gains a duplicate key, is restored from its original bytes.
"""
from __future__ import annotations
import json, pathlib, re, sys, tomllib

HOME = "https://www.algovoi.co.uk"
REPO = "https://github.com/chopmob-cloud/algovoi-keystone"
DOCS = "https://docs.algovoi.co.uk"
PY_CLASSIFIERS = [
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: 3.13",
]
LICENCE_CLASSIFIER = "License :: OSI Approved :: Apache Software License"
ROOTS = ["packages/*/pyproject.toml", "plugins/*/python/pyproject.toml", "adapters/*/python/pyproject.toml",
            "control/pyproject.toml"]


def project_section_span(text: str) -> tuple[int, int]:
    """Return (start, end) line indices of the [project] table body."""
    lines = text.splitlines(keepends=True)
    start = None
    for i, l in enumerate(lines):
        if re.match(r"^\[project\]\s*$", l.strip() or ""):
            start = i
            continue
        if start is not None and i > start and re.match(r"^\[[^\]]+\]\s*$", l.strip() or ""):
            return start, i
    if start is None:
        return -1, -1
    return start, len(lines)


def ensure_line_in_project(lines: list[str], span: tuple[int, int], key: str, value: str) -> bool:
    start, end = span
    body = "".join(lines[start:end])
    if re.search(rf"^{re.escape(key)}\s*=", body, re.M):
        return False
    ins = f'{key} = {value}\n'
    lines.insert(end, ins)
    return True


def add_classifiers(lines: list[str], span: tuple[int, int], wanted: list[str]) -> bool:
    start, end = span
    body = "".join(lines[start:end])
    m = re.search(r"^classifiers\s*=\s*\[(.*?)\]", body, re.S | re.M)
    if m:
        existing = re.findall(r'"([^"]+)"', m.group(1))
        missing = [c for c in wanted if c not in existing]
        if not missing:
            return False
        abs_start = start + body[: m.start()].count("\n")
        abs_end = start + body[: m.end()].count("\n")
        block = "".join(lines[abs_start:abs_end + 1])
        new_block = block.rstrip()
        assert new_block.endswith("]")
        inner = new_block[:-1].rstrip().rstrip(",").rstrip()
        add = "".join(f',\n    "{c}"' for c in missing)
        lines[abs_start:abs_end + 1] = [inner + add + ",\n]\n"]
        return True
    # no classifiers key: insert one before the section ends
    block = "classifiers = [\n" + "".join(f'    "{c}",\n' for c in wanted) + "]\n"
    lines.insert(end, block)
    return True


def add_urls(text: str) -> tuple[str, bool]:
    if re.search(r"^\[project\.urls\]", text, re.M):
        lines = text.splitlines(keepends=True)
        i = next(i for i, l in enumerate(lines) if re.match(r"^\[project\.urls\]\s*$", l.strip()))
        # find end of this table
        end = len(lines)
        for j in range(i + 1, len(lines)):
            if re.match(r"^\[[^\]]+\]\s*$", lines[j].strip() or ""):
                end = j
                break
        block = "".join(lines[i:end])
        add = ""
        if not re.search(r"^Homepage\s*=", block, re.M):
            add += f'Homepage = "{HOME}"\n'
        if not re.search(r"^Repository\s*=", block, re.M):
            add += f'Repository = "{REPO}"\n'
        if not re.search(r"^Documentation\s*=", block, re.M):
            add += f'Documentation = "{DOCS}"\n'
        if not add:
            return text, False
        lines.insert(i + 1, add)
        return "".join(lines), True
    return text.rstrip("\n") + (
        f'\n\n[project.urls]\nHomepage = "{HOME}"\nRepository = "{REPO}"\n'
        f'Documentation = "{DOCS}"\n'
    ), True


def main() -> int:
    apply = "--apply" in sys.argv
    root = pathlib.Path(".").resolve()
    changed, failed = [], []

    for pattern in ROOTS:
        for pp in sorted(root.glob(pattern)):
            original = pp.read_bytes()
            text = original.decode("utf-8")
            try:
                before = tomllib.loads(text)
            except Exception as e:
                failed.append((str(pp), f"pre-parse failed: {e}"))
                continue

            proj = before.get("project", {})
            lines = text.splitlines(keepends=True)
            span = project_section_span(text)
            touched = False

            if "--apply" in sys.argv and span[0] >= 0:
                if not proj.get("requires-python"):
                    touched |= ensure_line_in_project(lines, span, "requires-python", '">=3.10"')
                text2 = "".join(lines)
                span = project_section_span(text2)
                wanted = [LICENCE_CLASSIFIER] + PY_CLASSIFIERS
                if add_classifiers(lines, span, wanted):
                    touched = True
                text2 = "".join(lines)
                text2, urls_changed = add_urls(text2)
                touched |= urls_changed
                lines = text2.splitlines(keepends=True)

            new_text = "".join(lines) if touched else text

            if touched:
                try:
                    after = tomllib.loads(new_text)
                except Exception as e:
                    pp.write_bytes(original)
                    failed.append((str(pp), f"post-parse failed, ROLLED BACK: {e}"))
                    continue
                # duplicate-key / loss guard: project keys must not shrink
                if set(before.get("project", {})) - set(after.get("project", {})):
                    pp.write_bytes(original)
                    failed.append((str(pp), "keys lost, ROLLED BACK"))
                    continue
                pp.write_text(new_text, encoding="utf-8", newline="\n")
                changed.append(str(pp.relative_to(root)))

    print(f"changed: {len(changed)}  failed: {len(failed)}")
    for c in changed:
        print("  +", c)
    for p, why in failed:
        print("  !", p, why)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
