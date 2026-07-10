"""keystone -- the Keystone SDK command line.

One entry point over the bolt-on toolchain:

    keystone new <name> --kind connector|behaviour|stage   scaffold a publishable bolt-on
    keystone test [path]                                    run the bolt-on's test battery
    keystone validate <records.json>                        verify emitted refs offline
    keystone doctor                                         check the environment
    keystone info                                           show installed pieces + the primitive
    keystone journal <db> [--show]                          verify (and list) a runtime journal
    keystone publish [path]                                 build the dist and check it (mirror-first)

Everything reduces to one primitive:
    keystone_ref(payload) == "sha256:" + SHA-256(RFC 8785 JCS(payload))
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata as _im
import json
import os
import re
import subprocess
import sys
import urllib.request

MIRROR = "https://pip.algovoi.co.uk/simple/"
_FAMILY = [
    "algovoi-keystone", "algovoi-keystone-connect", "algovoi-keystone-agent",
    "algovoi-keystone-validate", "algovoi-execution-ref", "rfc8785",
]


def _ok(msg): print("  [ok]   " + msg)
def _bad(msg): print("  [FAIL] " + msg)
def _warn(msg): print("  [warn] " + msg)


def _keystone_ref(payload):
    import rfc8785
    return "sha256:" + hashlib.sha256(rfc8785.dumps(payload)).hexdigest()


def _version(dist):
    try:
        return _im.version(dist)
    except _im.PackageNotFoundError:
        return None


# --------------------------------------------------------------------------- #
# info / doctor
# --------------------------------------------------------------------------- #

def cmd_info(_args):
    print("Keystone SDK -- installed pieces:")
    for dist in _FAMILY:
        v = _version(dist)
        print("  %-26s %s" % (dist, v or "(not installed)"))
    print("\nOne primitive:")
    print('  keystone_ref(payload) == "sha256:" + SHA-256(RFC 8785 JCS(payload))')
    print("  docs: https://docs.algovoi.co.uk/keystone")
    return 0


def cmd_doctor(_args):
    print("keystone doctor")
    fails = 0

    try:
        import rfc8785  # noqa: F401
        _ok("rfc8785 (RFC 8785 JCS) importable")
    except Exception as exc:
        _bad("rfc8785 not importable: %r" % exc); fails += 1

    try:
        a = _keystone_ref({"b": 1, "a": 2})
        b = _keystone_ref({"a": 2, "b": 1})
        if a == b and a.startswith("sha256:") and len(a) == 71:
            _ok("keystone_ref canonical + deterministic (key order independent)")
        else:
            _bad("keystone_ref not canonical: %s vs %s" % (a, b)); fails += 1
    except Exception as exc:
        _bad("keystone_ref failed: %r" % exc); fails += 1

    for mod, dist in [("algovoi_keystone_connect", "algovoi-keystone-connect"),
                      ("algovoi_keystone_agent", "algovoi-keystone-agent")]:
        try:
            __import__(mod)
            _ok("%s importable (%s)" % (dist, _version(dist) or "?"))
        except Exception as exc:
            _bad("%s not importable: %r" % (dist, exc)); fails += 1

    try:
        req = urllib.request.Request(MIRROR, headers={"User-Agent": "keystone-cli"})
        with urllib.request.urlopen(req, timeout=6) as r:
            reachable = r.status == 200
        _ok("AlgoVoi index reachable (%s)" % MIRROR) if reachable else _warn("index HTTP %s" % r.status)
    except Exception as exc:
        _warn("AlgoVoi index not reachable (offline is fine): %r" % exc)

    print("\n=> %s" % ("PASS" if not fails else "FAIL (%d)" % fails))
    return 1 if fails else 0


# --------------------------------------------------------------------------- #
# validate -- verify emitted refs offline
# --------------------------------------------------------------------------- #

def _verify_record(rec):
    """(ok, ref_field, note). Handles execution_ref records and any
    content-addressed (keystone_ref) record such as a behaviour_ref."""
    if isinstance(rec, dict) and "execution_ref" in rec and all(
            k in rec for k in ("decision_ref", "action_type", "scope", "outcome", "executed_at_ms")):
        try:
            from algovoi_execution_ref import execution_ref
            want = execution_ref(rec["decision_ref"], rec["action_type"],
                                 rec["scope"], rec["outcome"], rec["executed_at_ms"])
            return (want == rec["execution_ref"], "execution_ref", "execution record")
        except Exception as exc:
            return (False, "execution_ref", "cannot recompute: %r" % exc)
    if isinstance(rec, dict):
        candidates = [k for k in rec if isinstance(rec.get(k), str)
                      and rec[k].startswith("sha256:") and (k.endswith("_ref") or k == "ref")]
        for key in candidates:
            body = {k: v for k, v in rec.items() if k != key}
            try:
                if _keystone_ref(body) == rec[key]:
                    return (True, key, "content-addressed")
            except Exception:
                pass
    return (False, "?", "no self-ref recomputes")


def cmd_validate(args):
    try:
        data = json.load(open(args.file, encoding="utf-8"))
    except Exception as exc:
        _bad("cannot read %s: %r" % (args.file, exc)); return 2
    records = data if isinstance(data, list) else [data]
    print("keystone validate %s -- %d record(s)" % (args.file, len(records)))
    fails = 0
    for i, rec in enumerate(records):
        ok, field, note = _verify_record(rec)
        (_ok if ok else _bad)("record %d [%s] %s" % (i, field, note))
        fails += 0 if ok else 1
    print("\n=> %s" % ("PASS" if not fails else "FAIL (%d/%d)" % (fails, len(records))))
    return 1 if fails else 0


# --------------------------------------------------------------------------- #
# new -- scaffold a publishable bolt-on
# --------------------------------------------------------------------------- #

def _slug(name):
    s = re.sub(r"[^a-z0-9]+", "_", name.strip().lower()).strip("_")
    if not s:
        raise SystemExit("keystone new: name must contain a letter or digit")
    return s


def _files_for(kind, name):
    slug = _slug(name)
    mod = "keystone_" + slug
    dist = "keystone-" + slug.replace("_", "-")
    common_pyproject = f"""[build-system]
requires = ["setuptools>=70", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "{dist}"
version = "0.1.0"
description = "A Keystone bolt-on ({kind}) built with algovoi-keystone-connect"
readme = "README.md"
license = {{ text = "Apache-2.0" }}
requires-python = ">=3.10"
dependencies = ["algovoi-keystone-connect>=0.1.0", "algovoi-keystone-agent>=0.1.0"]

[tool.setuptools.packages.find]
where = ["."]
include = ["{mod}*"]
"""
    notice = f"{dist}\nCopyright 2026\n\nBuilt on the AlgoVoi Keystone substrate: RFC 8785 (JCS) + SHA-256.\n"
    readme = f"# {dist}\n\nA Keystone bolt-on ({kind}). Test it with `keystone test`, publish it per\nhttps://docs.algovoi.co.uk/publishing-bolt-ons\n"

    if kind == "connector":
        init = f'''"""A Keystone {slug} connector: bind each write on a data plane to its decision_ref."""
from algovoi_keystone_connect import connector

# Map each write method to (action, scope_fn(call)). scope_fn reads call.kwargs /
# call.args for per-call values and call.client for fixed context.
keystone_{slug} = connector("{slug}", writes={{
    "write":  ("write",  lambda call: str(call.kwargs.get("key", ""))),
    "delete": ("delete", lambda call: str(call.kwargs.get("key", ""))),
}})
'''
        test = f'''from algovoi_keystone_connect import check_connector
from {mod} import keystone_{slug}


class Fake:
    def __init__(self): self.calls = []
    def write(self, **kw):  self.calls.append(("write", kw));  return {{}}
    def delete(self, **kw): self.calls.append(("delete", kw)); return {{}}


def test_connector_conforms():
    report = check_connector(keystone_{slug}, Fake(), [
        ("write",  {{"key": "k1"}}),
        ("delete", {{"key": "k1"}}),
    ])
    assert report.ok, report
'''
    elif kind == "behaviour":
        init = f'''"""A Keystone {slug} behaviour: govern a stage of the chain."""
from algovoi_keystone_agent import behaviour, rule, trigger

# Edit the trigger (when it wakes) and the rule (ALLOW / FLAG / BLOCK).
{slug} = behaviour(
    "{slug}",
    on=trigger(stage="execution", where=lambda ev: ev.get("method") is not None),
    rule=rule("{slug}_rule", lambda ev: "ALLOW"),
)
'''
        test = f'''from algovoi_keystone_agent import check_behaviour, synth_event
from {mod} import {slug}


def test_behaviour_conforms():
    report = check_behaviour({slug}, [synth_event("execution", method="write")])
    assert report.ok, report
'''
    elif kind == "stage":
        init = f'''"""A Keystone {slug} stage: a content-addressed ref-builder over its payload."""
from algovoi_keystone_connect import keystone_ref


def {slug}_ref(payload):
    # Bind to the upstream stage via a *_ref field inside `payload`.
    return keystone_ref(payload)
'''
        test = f'''from algovoi_keystone_connect import check_ref_builder, synth_ref
from {mod} import {slug}_ref


def test_stage_conforms():
    report = check_ref_builder(
        {slug}_ref,
        {{"prev_ref": synth_ref("prev"), "field": "value"}},
        prev_field="prev_ref",
    )
    assert report.ok, report
'''
    else:
        raise SystemExit("keystone new: --kind must be connector, behaviour, or stage")

    root = os.path.join(name, "python")
    return {
        os.path.join(root, mod, "__init__.py"): init,
        os.path.join(root, "tests", f"test_{mod}.py"): test,
        os.path.join(root, "pyproject.toml"): common_pyproject,
        os.path.join(root, "NOTICE"): notice,
        os.path.join(root, "README.md"): readme,
    }


def cmd_new(args):
    if os.path.exists(args.name):
        _bad("%s already exists" % args.name); return 2
    files = _files_for(args.kind, args.name)
    for path, content in files.items():
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
    print("scaffolded %s bolt-on %r:" % (args.kind, args.name))
    for path in sorted(files):
        print("  " + path)
    print("\nnext:")
    print("  cd %s/python && keystone test" % args.name)
    print("  keystone publish        # build + check, then publish per the docs")
    return 0


# --------------------------------------------------------------------------- #
# journal -- verify / list a runtime journal
# --------------------------------------------------------------------------- #

def cmd_journal(args):
    try:
        from algovoi_keystone_runtime import Journal
    except Exception as exc:
        _bad("algovoi-keystone-runtime not installed: %r" % exc); return 2
    j = Journal(args.db)
    try:
        print("keystone journal %s -- %d entries" % (args.db, j.count()))
        if args.show:
            for rec in j.records():
                ref = rec.get("execution_ref") or rec.get("behaviour_ref") or rec.get("stage_ref") or "?"
                tag = rec.get("stage") or ("execution" if "execution_ref" in rec else "?")
                note = rec.get("verdict", "")
                print("  %-12s %s  %s" % (tag, ref[:24] + "...", note))
        report = j.verify()
        print(report)
        return 0 if report.ok else 1
    finally:
        j.close()


# --------------------------------------------------------------------------- #
# test / publish
# --------------------------------------------------------------------------- #

def cmd_test(args):
    path = args.path or "."
    print("keystone test %s (pytest)" % path)
    return subprocess.call([sys.executable, "-m", "pytest", "-q", path])


def cmd_publish(args):
    path = args.path or "."
    print("keystone publish %s -- build + check (does not push)" % path)
    rc = subprocess.call([sys.executable, "-m", "build", path])
    if rc != 0:
        _bad("build failed"); return rc
    dist = os.path.join(path, "dist")
    rc = subprocess.call([sys.executable, "-m", "twine", "check", os.path.join(dist, "*")])
    print("\nMirror-first cadence:")
    print("  1. publish the wheel to the AlgoVoi index first (validated, panel-installable)")
    print("  2. promote to PyPI once it is verified in place")
    print("  docs: https://docs.algovoi.co.uk/publishing-bolt-ons")
    return rc


# --------------------------------------------------------------------------- #

def build_parser():
    p = argparse.ArgumentParser(prog="keystone", description="The Keystone SDK command line.")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("info", help="show installed pieces + the primitive").set_defaults(fn=cmd_info)
    sub.add_parser("doctor", help="check the environment").set_defaults(fn=cmd_doctor)

    n = sub.add_parser("new", help="scaffold a publishable bolt-on")
    n.add_argument("name")
    n.add_argument("--kind", choices=["connector", "behaviour", "stage"], default="connector")
    n.set_defaults(fn=cmd_new)

    t = sub.add_parser("test", help="run the bolt-on's tests")
    t.add_argument("path", nargs="?")
    t.set_defaults(fn=cmd_test)

    v = sub.add_parser("validate", help="verify emitted refs offline")
    v.add_argument("file")
    v.set_defaults(fn=cmd_validate)

    jn = sub.add_parser("journal", help="verify (and list) a runtime journal")
    jn.add_argument("db")
    jn.add_argument("--show", action="store_true", help="list the entries")
    jn.set_defaults(fn=cmd_journal)

    pub = sub.add_parser("publish", help="build + check a bolt-on (mirror-first)")
    pub.add_argument("path", nargs="?")
    pub.set_defaults(fn=cmd_publish)

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not getattr(args, "fn", None):
        build_parser().print_help()
        return 0
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
