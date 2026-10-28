"""Tests for the algovoi-execution-ref standalone app.

Pins to the published corpus values (keystone_v1 / execution_ref_v1 /
spend_decision_v1). These hold identically on substrate v0 and v1 because the
app uses only JCS canonicalisation.
"""
from __future__ import annotations

import json
import subprocess
import sys

import pytest

import algovoi_substrate as _sub
from algovoi_execution_ref import (
    execution_ref, decision_ref, trust_query_ref,
    bind_keystone, verify_record, ExecutionRefError, __version__,
)

PASSPORT = "sha256:b3594e33998af01bd1ad208172c5c1ac586daa8c75781379f034d97e50b1a9be"
MANDATE = "sha256:a4f8cb5ee09b29478ac1cc2f468d66e16d3d25f7a229a31d22ad521e11d04d35"
POLICY = "sha256:aaee2091799f376ee8cac802ea4920feaa4eca52950488a3e047ff82e6959a21"
DECISION_ALLOW = "sha256:2a444c629892f44fde1bd004aba9be01dd6cc7fe251eecdd545b82dca9f0bf97"
EXECUTION = "sha256:f6e2bfc15b085ed51c4c972de81d1c6b00f4e55b272e2aa12e56bb7c521fc65a"
TRUST_KEYSTONE = "sha256:18fb601a08c71eb6bed11e1c117f33bdc0ada6d635ea9bb9cca15e8410ce7ebd"

KW = dict(passport_ref=PASSPORT, mandate_ref=MANDATE, policy_bound_ref=POLICY,
          verdict="ALLOW", action_type="payment", scope="bilateral",
          outcome="COMMITTED", executed_at_ms=1716460800000, trust_outcome="TRUSTED")


def test_version():
    assert __version__ == "0.1.0"


def test_runs_on_any_substrate_version():
    # informational: the app must work on whatever substrate is installed
    assert _sub.__version__  # present


def test_decision_ref_matches_corpus():
    assert decision_ref(PASSPORT, MANDATE, POLICY, "ALLOW") == DECISION_ALLOW


def test_execution_ref_matches_corpus():
    assert execution_ref(DECISION_ALLOW, "payment", "bilateral", "COMMITTED", 1716460800000) == EXECUTION


def test_trust_query_ref_matches_corpus():
    assert trust_query_ref([PASSPORT, MANDATE, POLICY, DECISION_ALLOW, EXECUTION], "TRUSTED") == TRUST_KEYSTONE


def test_bind_keystone_matches_corpus():
    r = bind_keystone(**KW)
    assert r["decision_ref"] == DECISION_ALLOW
    assert r["execution_ref"] == EXECUTION
    assert r["trust_query_ref"] == TRUST_KEYSTONE
    assert r["chain"] == [PASSPORT, MANDATE, POLICY, DECISION_ALLOW, EXECUTION]


def test_record_self_verifies():
    assert verify_record(bind_keystone(**KW)) is True


def test_tamper_detected():
    r = bind_keystone(**KW)
    r["execution_ref"] = "sha256:" + "f" * 64
    assert verify_record(r) is False


def test_decision_binding_load_bearing():
    allow = bind_keystone(**KW)
    deny = bind_keystone(**{**KW, "verdict": "DENY"})
    assert deny["execution_ref"] != allow["execution_ref"]
    assert deny["trust_query_ref"] != allow["trust_query_ref"]


def test_rejects_rfc3339_timestamp():
    with pytest.raises(ExecutionRefError):
        execution_ref(DECISION_ALLOW, "payment", "bilateral", "COMMITTED", "2026-05-23T00:00:00.000Z")


def test_rejects_bad_inputs():
    with pytest.raises(ExecutionRefError):
        bind_keystone(**{**KW, "passport_ref": "nope"})
    with pytest.raises(ExecutionRefError):
        bind_keystone(**{**KW, "outcome": "DONE"})


def test_cli_roundtrip():
    b = subprocess.run([sys.executable, "-m", "algovoi_execution_ref"],
                       input=json.dumps(KW), capture_output=True, text=True)
    assert b.returncode == 0, b.stderr
    assert json.loads(b.stdout)["trust_query_ref"] == TRUST_KEYSTONE
    v = subprocess.run([sys.executable, "-m", "algovoi_execution_ref", "--verify"],
                       input=b.stdout, capture_output=True, text=True)
    assert v.returncode == 0 and "VERIFIED" in v.stdout
