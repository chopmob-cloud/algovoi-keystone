"""Replacement parity: execution_ref does everything action_ref does, as the
natural keystone replacement, and the lifecycle/binding roles more cleanly.

Each test maps a documented action_ref capability (from the action_ref_namespace_v0,
action_ref_transactional_v0, action_ref_exactly_once_v1, and settlement_action_binding_v1
corpus sets) to its execution_ref equivalent and proves it. Runs on substrate v0 and v1.
"""
from __future__ import annotations

import pytest

from algovoi_execution_ref import (
    execution_ref, decision_ref, execution_binding, bind_keystone,
    ExecutionRefError, EXECUTION_OUTCOMES,
)

DEC = "sha256:2a444c629892f44fde1bd004aba9be01dd6cc7fe251eecdd545b82dca9f0bf97"   # ALLOW
DEC2 = "sha256:792a5b43e9df0fc460d6bf99d6357afafbdcf910ef1e81a340e3581bc27109cf"  # DENY
REF_A = "sha256:" + "a" * 64
REF_B = "sha256:" + "b" * 64
REF_C = "sha256:" + "c" * 64


def E(**kw):
    base = dict(decision_ref=DEC, action_type="payment", scope="bilateral",
                outcome="COMMITTED", executed_at_ms=1716460800000)
    base.update(kw)
    return execution_ref(**base)


# --- action_ref capability 1: content-addressed identity + deterministic correlation ---
def test_deterministic_content_address():
    # action_ref: same logical action -> same handle. execution_ref: same here.
    assert E() == E()


def test_two_parties_correlate_same_execution():
    # two independent emitters describing the same execution derive the same ref
    party_a = execution_ref(DEC, "payment", "bilateral", "COMMITTED", 1716460800000)
    party_b = execution_ref(DEC, "payment", "bilateral", "COMMITTED", 1716460800000)
    assert party_a == party_b


# --- capability 2: every field byte-load-bearing (namespace / scope discipline) ---
@pytest.mark.parametrize("field,alt", [
    ("decision_ref", DEC2),
    ("action_type", "refund"),
    ("scope", "unilateral"),
    ("outcome", "REVERSED"),
    ("executed_at_ms", 1716460800001),
])
def test_every_field_is_load_bearing(field, alt):
    assert E() != E(**{field: alt})


# --- capability 3: integer-ms discipline (Substrate Rule) ---
def test_integer_ms_discipline():
    with pytest.raises(ExecutionRefError):
        E(executed_at_ms="2026-05-23T00:00:00.000Z")   # RFC 3339 string rejected
    with pytest.raises(ExecutionRefError):
        E(executed_at_ms=1716460800000.5)               # float rejected
    with pytest.raises(ExecutionRefError):
        E(executed_at_ms=-1)                             # negative rejected
    assert E(executed_at_ms=0)                           # epoch zero valid


# --- capability 4: transactional lifecycle (PENDING/COMMITTED/REVERSED -> outcome enum) ---
def test_lifecycle_states_distinct():
    refs = {oc: E(outcome=oc) for oc in EXECUTION_OUTCOMES}
    # each lifecycle state yields a distinct execution_ref; none collide
    assert len(set(refs.values())) == len(EXECUTION_OUTCOMES)


# --- capability 5: exactly-once / SKIP-on-retry idempotency ---
def test_exactly_once_idempotent_commit():
    # the committed execution is idempotent: re-deriving it gives the same ref
    first = E(outcome="COMMITTED")
    again = E(outcome="COMMITTED")
    assert first == again


def test_skip_on_retry_is_distinguishable():
    # a suppressed duplicate (SKIPPED) is a distinct, recordable outcome, not a silent dup
    committed = E(outcome="COMMITTED")
    skipped = E(outcome="SKIPPED")
    assert committed != skipped


# --- capability 6: replay-binding (an execution cannot be re-attributed) ---
def test_replay_binding_via_decision():
    # the same action replayed under a different authorizing decision is a different ref
    assert E(decision_ref=DEC) != E(decision_ref=DEC2)


# --- capability 7: settlement binding (action_ref + transition_hash -> binding_ref) ---
def test_settlement_binding_over_execution_ref():
    e = E(outcome="COMMITTED")
    b1 = execution_binding(e, REF_B, REF_C)
    assert b1.startswith("sha256:") and len(b1) == len("sha256:") + 64
    # settlement-binding: changing settlement_ref changes the binding
    assert execution_binding(e, REF_A, REF_C) != b1
    # action-binding: changing the execution changes the binding
    assert execution_binding(E(outcome="REVERSED"), REF_B, REF_C) != b1
    # chain-binding: changing retention_chain_ref changes the binding
    assert execution_binding(e, REF_B, REF_A) != b1


def test_settlement_binding_subsumes_transition_hash():
    # execution_ref already encodes the committed outcome, so the binding needs
    # one decision-bound reference where action_ref needed action_ref + transition_hash
    committed = execution_binding(E(outcome="COMMITTED"), REF_B, REF_C)
    reversed_ = execution_binding(E(outcome="REVERSED"), REF_B, REF_C)
    assert committed != reversed_   # the lifecycle state is still load-bearing in the binding


# --- capability 8: anchors the keystone record (receipts / audit) ---
def test_execution_ref_anchors_keystone():
    rec = bind_keystone(
        passport_ref=REF_A, mandate_ref=REF_B, policy_bound_ref=REF_C,
        verdict="ALLOW", action_type="payment", scope="bilateral",
        outcome="COMMITTED", executed_at_ms=1716460800000, trust_outcome="TRUSTED",
    )
    # the execution_ref is the load-bearing anchor inside the record + the chain
    assert rec["execution_ref"] in rec["chain"]
    assert rec["execution_ref"] == execution_ref(rec["decision_ref"], "payment", "bilateral", "COMMITTED", 1716460800000)
