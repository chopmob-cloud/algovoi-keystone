"""Chain verification: every committed vector, the six assertion kinds, and ref pinning.

The vectors in ``tests/vectors`` are the fixture set this estate publishes as its
conformance examples. Expectations here are the declared behaviour of each
fixture, not a recording of whatever the code happens to do:

* the five assertion kinds shared with the published
  ``algovoi-keystone-compose`` 0.3.1 wheels (scope_subset, field_equals,
  time_within, not_revoked, journey) produce the same verdict here as on those
  compiled wheels, byte for byte;
* ``recurring_cap`` is the kind 0.3.1 does not know, which is the whole reason
  this module exists — 0.3.1 raises ``unknown assertion kind 'recurring_cap'``
  on every recurr vector below.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from algovoi_keystone.verify import KeystoneError, scope_contains, verify_chain

VECTORS = Path(__file__).parent / "vectors"

# Chains that must compose (and, for the aggregating ones, cap the chain).
GOLDEN = [
    "keystone-golden",
    "delegation-golden",
    "journey-golden",
    "revocation-golden",
    "recurr-golden",
    "recurr-float-amount",
]

# Chains that recompose but must fail a named assertion.
ASSERTION_FAILURES = {
    "delegation-broken-scope": "scope_subset",
    "delegation-broken-delegate": "field_equals",
    "delegation-broken-expired": "time_within",
    "journey-broken": "journey",
    "revocation-broken-after": "not_revoked",
    "revocation-multihop": "not_revoked",
    "recurr-broken-widened": "recurring_cap",
    "recurr-broken-fractional": "recurring_cap",
    "recurr-broken-expired": "recurring_cap",
    "recurr-broken-overcap": "recurring_cap",
    "recurr-broken-naive-expiry": "recurring_cap",
    "recurr-broken-negative": "recurring_cap",
    "recurr-broken-revoked": "not_revoked",
}

# One fixture fails at a link, not at an assertion.
LINK_FAILURES = ["broken-execution"]


def load(name):
    return json.loads((VECTORS / f"{name}.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", GOLDEN)
def test_golden_chains_compose_and_cap(name):
    r = verify_chain(load(name))
    assert r.ok, [a for a in r.assertions if not a.ok]
    assert r.capped
    assert r.cap == r.links[-1].name


@pytest.mark.parametrize("name,kind", sorted(ASSERTION_FAILURES.items()))
def test_broken_vectors_fail_the_right_assertion(name, kind):
    r = verify_chain(load(name))
    assert not r.ok
    failing = r.failed_assertion
    assert failing is not None, f"{name} passed every assertion"
    assert failing.kind == kind
    assert failing.detail


@pytest.mark.parametrize("name", LINK_FAILURES)
def test_link_mismatch_fails_before_assertions(name):
    r = verify_chain(load(name))
    assert not r.ok
    broken = r.first_broken
    assert broken is not None
    assert broken.detail


def test_zero_padded_expiry_is_rejected_by_naive_awareness():
    """A naive ISO-8601 expiry must fail closed: Python and JS would disagree on the instant."""
    r = verify_chain(load("recurr-broken-naive-expiry"))
    assert not r.ok
    assert "timezone-aware" in r.failed_assertion.detail


def test_integer_valued_float_matches_the_node_twin():
    """JCS collapses 500.0 to 500, so an integer-valued float is the SAME signed object."""
    assert verify_chain(load("recurr-float-amount")).ok


def test_unsafe_integer_fails_closed():
    """2**53+1 cannot round-trip through a JS double: both impls must refuse, never verify."""
    try:
        r = verify_chain(load("recurr-broken-unsafe-int"))
    except Exception as exc:  # noqa: BLE001 - an out-of-domain int must fail closed
        assert "IntegerDomain" in type(exc).__name__
    else:
        assert not r.ok
        assert r.failed_assertion.kind == "recurring_cap"


def test_manifest_without_a_chain_array_is_malformed():
    """alias-escape.json is a grammar manifest, not a chain: refuse it as malformed."""
    with pytest.raises(KeystoneError, match="non-empty 'chain' array"):
        verify_chain(load("alias-escape"))


def test_duplicate_link_names_are_refused():
    chain = load("keystone-golden")
    chain = {"chain": [dict(chain["chain"][0]), dict(chain["chain"][0])]}
    with pytest.raises(KeystoneError, match="duplicate link name"):
        verify_chain(chain)


# --- the @name grammar (alias_escape_v1) ------------------------------------

def test_alias_grammar_refs_and_escape():
    manifest = load("alias-escape")
    for case in manifest["cases"]:
        expect = case["expect"]
        if "error_contains" in expect:
            with pytest.raises(KeystoneError, match=expect["error_contains"]):
                verify_chain({"chain": case["chain"]})
            continue
        r = verify_chain({"chain": case["chain"]})
        assert {l.name: l.computed for l in r.links} == expect["refs"], case["name"]
        if "binds" in expect:
            assert {l.name: l.binds for l in r.links} == expect["binds"], case["name"]


def test_escaped_literal_differs_from_resolved_alias():
    """'@@name' must be the literal '@name'; if the two refs coincide the escape is inert."""
    manifest = load("alias-escape")
    by_name = {c["name"]: c for c in manifest["cases"]}
    escaped = by_name["escaped-literal-collides-with-link-name"]["expect"]["refs"]["post"]
    resolved = by_name["alias-resolves-and-binds"]["expect"]["refs"]["post"]
    assert escaped != resolved


# --- pinning a reference you independently trust ----------------------------

def test_pin_matching_authority_verifies():
    chain = load("recurr-golden")
    pinned = verify_chain(chain, expect={"standing_authority": "sha256:" + "0" * 64})
    assert not pinned.ok
    assert pinned.failed_assertion.kind == "ref_pinned"
    good = verify_chain(chain, expect={"standing_authority": _ref_of(chain, "standing_authority")})
    assert good.ok
    assert [a.kind for a in good.assertions] == ["ref_pinned", "recurring_cap"]


def _ref_of(chain, name):
    return next(l.computed for l in verify_chain(chain).links if l.name == name)


def test_pin_rejects_a_widened_authority():
    """The hole pinning closes: a wider cap in an otherwise valid chain still recomposes."""
    chain = load("recurr-golden")
    signed = _ref_of(chain, "standing_authority")

    widened = json.loads(json.dumps(chain))
    for link in widened["chain"]:
        if link["name"] == "standing_authority":
            link["preimage"]["cap_amount_minor"] = 999_000_000
    widened.pop("ref", None)

    assert verify_chain(widened).ok  # consistency alone proves nothing about intent
    pinned = verify_chain(widened, expect={"standing_authority": signed})
    assert not pinned.ok
    assert pinned.failed_assertion.kind == "ref_pinned"


def test_pin_for_absent_link_fails():
    r = verify_chain(load("keystone-golden"), expect={"not_a_link": "sha256:" + "1" * 64})
    assert not r.ok
    assert "not in the chain" in r.failed_assertion.detail


@pytest.mark.parametrize("bad", ["", "sha256:", "sha256:xyz", "0" * 64, "SHA256:" + "a" * 64])
def test_malformed_pin_is_refused(bad):
    with pytest.raises(KeystoneError, match="sha256"):
        verify_chain(load("keystone-golden"), expect={"passport": bad})


# --- canonicalisation source ----------------------------------------------

def test_rfc8785_only_path_matches_the_crosschecked_path():
    """Verification must not require AlgoVoi software: rfc8785 alone gives the same refs."""
    import algovoi_keystone.verify as v

    before = [l.computed for l in verify_chain(load("keystone-golden")).links]
    saved = v._substrate
    v._substrate = None
    try:
        after = [l.computed for l in verify_chain(load("keystone-golden")).links]
    finally:
        v._substrate = saved
    assert before == after


def test_scope_contains_is_fail_closed_on_widening():
    assert scope_contains({"max_amount": 10}, {"max_amount": 10})[0]
    assert not scope_contains({"max_amount": 10}, {"max_amount": 11})[0]
    assert not scope_contains({"max_amount": 10}, {})[0]
    assert scope_contains({"resource": "a/b"}, {"resource": "a/b/c"})[0]
    assert not scope_contains({"resource": "a/b"}, {"resource": "a"})[0]
    assert not scope_contains({"capabilities": ["read"]}, {"capabilities": ["read", "write"]})[0]
