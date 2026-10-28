"""Security tests for the AlgoVoi OTel gen_ai adapter.

The adapter carried no tests. These establish the contract an adapter can
silently break: a ref that verifies must be recomputable by a third party from
the carried preimage alone, and every malformed or tampered span must be
refused rather than trusted.
"""
import pytest

from algovoi_otel_genai import (
    execution_ref,
    to_gen_ai_attributes,
    verify_gen_ai_execution_ref,
)

PREIMAGE = dict(
    decision_ref="d1",
    action_type="transfer",
    scope="acct-1",
    outcome="ALLOW",
    executed_at_ms=1_700_000_000_000,
)


@pytest.fixture()
def attrs():
    return to_gen_ai_attributes(**PREIMAGE)


# ---------------------------------------------------------------- positive

def test_genuine_span_verifies(attrs):
    assert verify_gen_ai_execution_ref(attrs) is True


def test_ref_is_recomputable_from_preimage(attrs):
    """A third party with only the carried fields must reach the same ref."""
    recomputed = execution_ref(
        attrs["algovoi.keystone.decision_ref"],
        attrs["algovoi.keystone.action_type"],
        attrs["algovoi.keystone.scope"],
        attrs["algovoi.keystone.outcome"],
        int(attrs["algovoi.keystone.executed_at_ms"]),
    )
    assert recomputed == attrs["algovoi.keystone.execution_ref"]


def test_ref_is_deterministic():
    a = to_gen_ai_attributes(**PREIMAGE)
    b = to_gen_ai_attributes(**PREIMAGE)
    assert a["algovoi.keystone.execution_ref"] == b["algovoi.keystone.execution_ref"]


def test_ref_is_prefixed(attrs):
    assert attrs["algovoi.keystone.execution_ref"].startswith("sha256:")


# ---------------------------------------------------------------- tampering

@pytest.mark.parametrize("field,value", [
    ("algovoi.keystone.decision_ref", "d2"),
    ("algovoi.keystone.action_type", "refund"),
    ("algovoi.keystone.scope", "acct-2"),
    ("algovoi.keystone.outcome", "DENY"),
    ("algovoi.keystone.executed_at_ms", 1_700_000_000_001),
])
def test_tampered_field_is_refused(attrs, field, value):
    bad = dict(attrs)
    bad[field] = value
    assert verify_gen_ai_execution_ref(bad) is False


def test_tampered_ref_is_refused(attrs):
    bad = dict(attrs)
    bad["algovoi.keystone.execution_ref"] = "sha256:" + "0" * 64
    assert verify_gen_ai_execution_ref(bad) is False


def test_null_ref_is_refused(attrs):
    bad = dict(attrs)
    bad["algovoi.keystone.execution_ref"] = None
    assert verify_gen_ai_execution_ref(bad) is False


def test_ref_swapped_between_spans_is_refused(attrs):
    """Copying a valid ref from another span must not authenticate this one."""
    other = to_gen_ai_attributes(**{**PREIMAGE, "decision_ref": "d-other"})
    forged = dict(attrs)
    forged["algovoi.keystone.execution_ref"] = other["algovoi.keystone.execution_ref"]
    assert verify_gen_ai_execution_ref(forged) is False


# ---------------------------------------------------------------- abuse

@pytest.mark.parametrize("payload", [
    {},
    None,
    [],
    {"algovoi.keystone.execution_ref": "sha256:" + "0" * 64},
])
def test_malformed_input_fails_closed(payload):
    assert verify_gen_ai_execution_ref(payload) is False


def test_missing_single_field_fails_closed(attrs):
    """Every field in the ref preimage is required; optional metadata is not."""
    preimage = [
        "algovoi.keystone.decision_ref",
        "algovoi.keystone.action_type",
        "algovoi.keystone.scope",
        "algovoi.keystone.outcome",
        "algovoi.keystone.executed_at_ms",
    ]
    for key in preimage:
        assert key in attrs, "adapter did not emit %s" % key
        partial = {k: v for k, v in attrs.items() if k != key}
        assert verify_gen_ai_execution_ref(partial) is False, key


def test_optional_metadata_is_not_part_of_the_preimage(attrs):
    """Decorative attributes may be dropped without breaking verification."""
    optional = [k for k in attrs if k.startswith("gen_ai.")]
    assert optional, "expected decorative gen_ai.* attributes"
    for key in optional:
        partial = {k: v for k, v in attrs.items() if k != key}
        assert verify_gen_ai_execution_ref(partial) is True, key


def test_non_integer_timestamp_fails_closed(attrs):
    bad = dict(attrs)
    bad["algovoi.keystone.executed_at_ms"] = "not-a-number"
    assert verify_gen_ai_execution_ref(bad) is False


def test_boolean_outcome_is_not_coerced(attrs):
    """A truthy non-string outcome must not sneak through as a valid preimage."""
    bad = dict(attrs)
    bad["algovoi.keystone.outcome"] = True
    assert verify_gen_ai_execution_ref(bad) is False
