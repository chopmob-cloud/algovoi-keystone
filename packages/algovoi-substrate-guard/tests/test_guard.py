"""Tests for algovoi-substrate-guard: control accepts; each bound rejects (exceeded by one) with its
named code; profile_ref is key-order invariant and pinnable."""
from __future__ import annotations

import hashlib

import pytest
import rfc8785

from algovoi_substrate_guard import DEFAULT_PROFILE, GuardError, Profile, guard, profile_ref


def _reject_code(value, profile=DEFAULT_PROFILE) -> str:
    with pytest.raises(GuardError) as ei:
        guard(value, profile)
    return ei.value.code


# ---- control -----------------------------------------------------------------------------------

def test_control_value_accepted():
    value = {"type": "spend_decision", "amount": 1000000, "items": ["a", "b", "c"], "nested": {"k": 1}}
    assert guard(value) is True


def test_boundary_values_at_the_limit_accepted():
    p = Profile(max_object_keys=4, max_array_length=4, max_string_length=4, max_total_nodes=64, max_bytes=65536)
    assert guard({"a": "wxyz", "b": [1, 2, 3, 4], "c": 1, "d": 2}, p) is True  # exactly at limits


# ---- one isolated rejection per bound (exceed exactly one limit by one) -------------------------

def test_over_string():
    p = Profile(max_string_length=8)
    assert _reject_code("x" * 9, p) == "REJECT_OVER_STRING"


def test_over_string_on_object_key():
    p = Profile(max_string_length=4)
    assert _reject_code({"toolongkey": 1}, p) == "REJECT_OVER_STRING"


def test_too_many_keys():
    p = Profile(max_object_keys=4, max_total_nodes=10_000)
    assert _reject_code({str(i): 1 for i in range(5)}, p) == "REJECT_TOO_MANY_KEYS"


def test_over_array():
    p = Profile(max_array_length=4, max_total_nodes=10_000)
    assert _reject_code([1, 2, 3, 4, 5], p) == "REJECT_OVER_ARRAY"


def test_over_depth():
    p = Profile(max_depth=3, max_total_nodes=10_000)
    # depth 4: {a:{a:{a:{a:1}}}} -> root(1) a(2) a(3) a(4)
    assert _reject_code({"a": {"a": {"a": {"a": 1}}}}, p) == "REJECT_OVER_DEPTH"


def test_over_nodes():
    p = Profile(max_total_nodes=5, max_array_length=10_000)
    assert _reject_code([1, 2, 3, 4, 5], p) == "REJECT_OVER_NODES"  # root + 5 items = 6 > 5


def test_unsafe_number_int():
    assert _reject_code(2 ** 53, DEFAULT_PROFILE) == "REJECT_UNSAFE_NUMBER"
    assert _reject_code(-(2 ** 53), DEFAULT_PROFILE) == "REJECT_UNSAFE_NUMBER"


def test_unsafe_number_non_finite_float():
    assert _reject_code(float("inf")) == "REJECT_UNSAFE_NUMBER"
    assert _reject_code(float("nan")) == "REJECT_UNSAFE_NUMBER"


def test_over_size():
    # passes every structural bound but the canonical form exceeds max_bytes
    p = Profile(max_bytes=200, max_array_length=10_000, max_string_length=10_000, max_total_nodes=10_000)
    assert _reject_code(["x" * 50] * 10, p) == "REJECT_OVER_SIZE"


def test_safe_number_at_boundary_accepted():
    assert guard(2 ** 53 - 1) is True
    assert guard(-(2 ** 53 - 1)) is True


# ---- profile_ref -------------------------------------------------------------------------------

def test_profile_ref_is_content_address():
    # rfc8785 is the independent oracle: the package uses algovoi_substrate; this confirms they agree.
    assert profile_ref() == "sha256:" + hashlib.sha256(rfc8785.dumps(DEFAULT_PROFILE.snapshot())).hexdigest()
    assert profile_ref().startswith("sha256:")


def test_profile_ref_key_order_invariant():
    # JCS sorts keys, so a different field order in the snapshot yields the same ref.
    snap = DEFAULT_PROFILE.snapshot()
    reordered = {k: snap[k] for k in reversed(list(snap))}
    assert ("sha256:" + hashlib.sha256(rfc8785.dumps(reordered)).hexdigest()) == profile_ref()


def test_different_bounds_address_differently():
    assert profile_ref(Profile(max_bytes=999)) != profile_ref()


def test_named_profile_is_part_of_the_address():
    assert profile_ref(Profile(name="custom-v1")) != profile_ref()


def test_default_profile_ref_matches_published_vector():
    # the canonical anchor published in conformance/substrate_guard_v1/vectors.json
    assert profile_ref() == "sha256:a4791b13c67a16109b85ef67fc65700ea902b6ad40dad44d8556632c3d5524a6"
