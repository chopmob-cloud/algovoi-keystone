"""`keystone verify` -- exit codes, pinning, and the two verdict lines.

0 = the chain composes (and every pin matches); 1 = a well-formed chain that does
not verify (a real negative); 2 = a problem with the input or the invocation.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from algovoi_keystone.cli import main

VECTORS = Path(__file__).parent / "vectors"


def run(capsys, *argv):
    rc = main(list(argv))
    out = capsys.readouterr().out
    return rc, out


def test_valid_chain_exits_zero(capsys):
    rc, out = run(capsys, "verify", str(VECTORS / "keystone-golden.json"))
    assert rc == 0
    assert "KEYSTONE VALID:" in out
    assert "no issuer contact" in out


def test_recurr_chain_verifies_and_reports_the_cap(capsys):
    rc, out = run(capsys, "verify", str(VECTORS / "recurr-golden.json"))
    assert rc == 0
    assert "recurring-cap hold" in out
    assert "capped: standing_authority" not in out  # the cap is the aggregating final link
    assert "capped:" in out


def test_broken_assertion_exits_one(capsys):
    rc, out = run(capsys, "verify", str(VECTORS / "recurr-broken-overcap.json"))
    assert rc == 1
    assert "KEYSTONE BROKEN: recurring_cap failed" in out
    assert "does not prove what it claims" in out


def test_broken_link_exits_one(capsys):
    rc, out = run(capsys, "verify", str(VECTORS / "broken-execution.json"))
    assert rc == 1
    assert "KEYSTONE BROKEN at" in out


def test_missing_file_exits_two(capsys):
    rc, out = run(capsys, "verify", str(VECTORS / "nope.json"))
    assert rc == 2


def test_malformed_json_exits_two(capsys, tmp_path):
    bad = tmp_path / "chain.json"
    bad.write_text("{not json", encoding="utf-8")
    rc, _ = run(capsys, "verify", str(bad))
    assert rc == 2


def test_manifest_without_chain_array_exits_two(capsys):
    rc, _ = run(capsys, "verify", str(VECTORS / "alias-escape.json"))
    assert rc == 2


def test_pin_matches_exit_zero(capsys):
    chain = json.loads((VECTORS / "recurr-golden.json").read_text(encoding="utf-8"))
    ref = _ref_of(chain, "standing_authority")
    rc, out = run(capsys, "verify", str(VECTORS / "recurr-golden.json"),
                  "--expect", f"standing_authority={ref}")
    assert rc == 0
    assert "ref-pinned hold" in out


def test_pin_mismatch_exits_one(capsys):
    rc, out = run(capsys, "verify", str(VECTORS / "recurr-golden.json"),
                  "--expect", "standing_authority=sha256:" + "0" * 64)
    assert rc == 1
    assert "KEYSTONE BROKEN: ref_pinned failed" in out


def test_malformed_pin_exits_two(capsys):
    rc, out = run(capsys, "verify", str(VECTORS / "recurr-golden.json"),
                  "--expect", "standing_authority=not-a-ref")
    assert rc == 2


def test_pin_without_equals_exits_two(capsys):
    rc, _ = run(capsys, "verify", str(VECTORS / "recurr-golden.json"), "--expect", "standing_authority")
    assert rc == 2


def _ref_of(chain, name):
    from algovoi_keystone.verify import verify_chain
    return next(l.computed for l in verify_chain(chain).links if l.name == name)
