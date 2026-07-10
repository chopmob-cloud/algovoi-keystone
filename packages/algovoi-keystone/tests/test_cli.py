"""End-to-end tests for the algovoi-keystone umbrella + `keystone` CLI."""
import json
import os
import subprocess
import sys

import pytest

from algovoi_keystone import (  # umbrella import surface
    Engine, behaviour, behaviours, connector, keystone_ref, rule, trigger,
)
from algovoi_keystone.cli import cmd_new, main


def test_umbrella_reexports_work():
    # one import gives connectors + behaviours + the primitive
    ks3 = connector("s3", writes={"put_object": ("put", lambda c: c.kwargs["Bucket"])})
    eng = Engine([behaviours.cap_charges(500)], decision_ref=keystone_ref({"g": 1}), clock_ms=lambda: 1)
    fired = eng.dispatch({"stage": "spend_decision", "amount": 900, "action_type": "charge"})
    assert fired and fired[0]["verdict"] == "BLOCK"
    assert callable(ks3) and callable(rule) and callable(trigger) and callable(behaviour)


def test_info_and_doctor(capsys):
    assert main(["info"]) == 0
    out = capsys.readouterr().out
    assert "algovoi-keystone-connect" in out and "keystone_ref(payload)" in out
    # doctor: connect + agent + rfc8785 all importable in this env
    assert main(["doctor"]) == 0
    assert "PASS" in capsys.readouterr().out


@pytest.mark.parametrize("kind", ["connector", "behaviour", "stage"])
def test_scaffold_then_test_is_green(tmp_path, kind, monkeypatch):
    monkeypatch.chdir(tmp_path)
    name = "acme-" + kind
    rc = cmd_new(type("A", (), {"name": name, "kind": kind})())
    assert rc == 0
    pkgdir = tmp_path / name / "python"
    assert (pkgdir / "pyproject.toml").exists()
    assert (pkgdir / f"keystone_acme_{kind}" / "__init__.py").exists()
    # the scaffolded bolt-on must pass its own wired-in conformance test
    env = dict(os.environ)
    env["PYTHONPATH"] = str(pkgdir) + os.pathsep + env.get("PYTHONPATH", "")
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", str(pkgdir / "tests")],
                       capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stdout + r.stderr


def test_validate_behaviour_and_execution_records(tmp_path):
    # a behaviour_ref record
    eng = Engine([behaviours.cap_charges(500)], decision_ref=keystone_ref({"g": 1}), clock_ms=lambda: 1)
    brec = eng.dispatch({"stage": "spend_decision", "amount": 900, "action_type": "charge"})[0]
    # an execution_ref record from a real connector
    ks3 = connector("s3", writes={"put_object": ("put", lambda c: c.kwargs["Bucket"] + "/" + c.kwargs["Key"])})

    class Fake:
        def put_object(self, **kw): return {}
    client = ks3(Fake(), decision_ref=keystone_ref({"g": 1}))
    client.put_object(Bucket="b", Key="k")
    erec = client.executions[-1] if hasattr(client, "executions") else None

    records = [brec] + ([erec] if erec else [])
    f = tmp_path / "records.json"
    f.write_text(json.dumps(records))
    assert main(["validate", str(f)]) == 0


def test_runtime_reexport_and_journal_command(tmp_path, capsys):
    from algovoi_keystone import Journal, Runtime, keystone_ref
    db = str(tmp_path / "j.db")
    rt = Runtime(Journal(db, clock_ms=lambda: 1), decision_ref=keystone_ref({"g": 1}),
                 clock_ms=lambda: 2)
    rt.record_stage("passport", {"agent": "a7"})
    rt.journal.close()
    assert main(["journal", db, "--show"]) == 0
    out = capsys.readouterr().out
    assert "1 entries" in out and "passport" in out and "PASS" in out


def test_validate_catches_tamper(tmp_path):
    eng = Engine([behaviours.cap_charges(500)], decision_ref=keystone_ref({"g": 1}), clock_ms=lambda: 1)
    rec = dict(eng.dispatch({"stage": "spend_decision", "amount": 900, "action_type": "charge"})[0])
    rec["verdict"] = "ALLOW"  # tamper: was BLOCK, ref no longer recomputes
    f = tmp_path / "bad.json"
    f.write_text(json.dumps(rec))
    assert main(["validate", str(f)]) == 1  # non-zero exit on failure
