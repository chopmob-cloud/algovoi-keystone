"""Verify that an AlgoVoi keystone chain composes end to end.

A keystone chain is an ordered list of content-addressed links. Each link's
reference is `"sha256:" + SHA-256(RFC 8785 JCS(preimage))`. Composition is
structural: a downstream preimage refers to an upstream link by `@name`, so the
downstream reference cannot be computed without the exact upstream reference.
Tamper any link and that link, and every link that binds it, diverge.

This is the part a plain receipt checker cannot do: it does not just recompute
individual digests, it proves the whole chain binds into one recomputable
sequence and that one verdict covers it in order.

Six assertion kinds are checked: ``scope_subset``, ``field_equals``,
``time_within``, ``not_revoked``, ``journey`` and ``recurring_cap`` (a recurring
standing authority composed by ``algovoi-recurr``: the per-cycle cap, the
period cap, the policy bound and the authority window).

Offline. No issuer contact. Canonicalisation is RFC 8785 JCS + SHA-256. The
canonical bytes come from the independent ``rfc8785`` library, so verification
needs no AlgoVoi software in the trust base; when ``algovoi-substrate`` (L1) is
installed as well, its canonicaliser is cross-checked byte-for-byte against
``rfc8785`` and a divergence fails closed rather than silently choosing one.

Apache-2.0. (c) AlgoVoi. NOTICE attribution required for redistribution.
"""
from __future__ import annotations

import datetime
import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Mapping

import rfc8785

# The L1 substrate is optional: a verifier that only needs an independent JCS
# implementation must not force AlgoVoi code into someone else's trust base.
# When it IS present it is the substrate under test and rfc8785 is the witness;
# the two must agree byte-for-byte or the chain is refused.
try:  # pragma: no cover - exercised both ways in the test suite
    import algovoi_substrate as _substrate
except Exception:  # noqa: BLE001 - absent, or present but broken: fall back to rfc8785
    _substrate = None

SUBSTRATE_CROSSCHECKED = _substrate is not None

_REF_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class KeystoneError(ValueError):
    """Raised when a chain is structurally invalid (not when a link simply mismatches)."""


def _canonicalize(obj: Any) -> bytes:
    """RFC 8785 JCS bytes for `obj`, from rfc8785, cross-checked against the substrate.

    rfc8785 is the independent witness and always available; algovoi-substrate,
    when installed, is the substrate under test. Two implementations, one
    required agreement — a divergence is a hard error, never a silent choice.
    """
    primary = rfc8785.dumps(obj)
    if _substrate is not None:
        other = _substrate.canonicalize_bytes(obj)
        if not isinstance(other, (bytes, bytearray)):
            other = other.encode("utf-8")
        if bytes(other) != primary:
            raise KeystoneError(
                "canonicalisation divergence: algovoi-substrate and rfc8785 disagree"
            )
    return primary


def _ref(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonicalize(obj)).hexdigest()


def _resolve(value: Any, refs: dict[str, str], link_name: str) -> Any:
    """Replace every '@name' marker with the already-computed reference of link `name`.

    A leading '@@' is an escape: '@@name' is the literal string '@name' and never
    resolves. Domain data that legitimately begins with '@' (handles, some DIDs)
    is written escaped, so it can never be mistaken for a composition marker.
    """
    if isinstance(value, str) and value.startswith("@"):
        if value.startswith("@@"):
            return value[1:]
        target = value[1:]
        if target not in refs:
            raise KeystoneError(
                f"link '{link_name}' references @{target}, which is not an earlier link"
            )
        return refs[target]
    if isinstance(value, list):
        return [_resolve(v, refs, link_name) for v in value]
    if isinstance(value, dict):
        return {k: _resolve(v, refs, link_name) for k, v in value.items()}
    return value


@dataclass
class LinkResult:
    name: str
    computed: str
    expected: str | None
    ok: bool
    binds: list[str]               # names of upstream links this preimage referenced
    detail: str = ""


# --- scope model (v1): prove no permission was widened across a boundary ---
# A scope is a dict with optional dimensions; an absent dimension on the outer
# scope means it does not constrain that dimension. fail-closed where the outer
# constrains a dimension the inner does not demonstrate it stays within.

def scope_contains(outer: Any, inner: Any) -> tuple[bool, str]:
    """True iff `inner` is wholly within `outer` (the inner widened nothing)."""
    if not isinstance(outer, dict) or not isinstance(inner, dict):
        return (outer == inner, "" if outer == inner else "non-dict scopes differ")
    # resource: hierarchical path, inner must be outer or a sub-path (segment-wise)
    if "resource" in outer:
        o = [s for s in str(outer["resource"]).strip("/").split("/") if s != ""]
        i = [s for s in str(inner.get("resource", "")).strip("/").split("/") if s != ""]
        if i[: len(o)] != o:
            return (False, f"resource {inner.get('resource')!r} not within {outer['resource']!r}")
    # numeric bound: inner <= outer
    if "max_amount" in outer:
        iv = inner.get("max_amount")
        if iv is None or iv > outer["max_amount"]:
            return (False, f"max_amount {iv} exceeds {outer['max_amount']}")
    # set dimensions: inner subset of outer
    for dim in ("capabilities", "jurisdictions"):
        if dim in outer:
            if not set(inner.get(dim, [])) <= set(outer[dim]):
                return (False, f"{dim} {inner.get(dim)} not a subset of {outer[dim]}")
    return (True, "")


@dataclass
class AssertionResult:
    kind: str
    ok: bool
    detail: str = ""


@dataclass
class ChainResult:
    links: list[LinkResult] = field(default_factory=list)
    assertions: list[AssertionResult] = field(default_factory=list)
    cap: str | None = None             # the name of the final link if it aggregates the chain
    cap_covers: list[str] = field(default_factory=list)  # the ordered refs the cap binds
    capped: bool = False

    @property
    def ok(self) -> bool:
        return (bool(self.links) and all(l.ok for l in self.links)
                and all(a.ok for a in self.assertions))

    @property
    def first_broken(self) -> LinkResult | None:
        return next((l for l in self.links if not l.ok), None)

    @property
    def failed_assertion(self) -> AssertionResult | None:
        return next((a for a in self.assertions if not a.ok), None)


def _binds(value: Any, acc: list[str]) -> None:
    if isinstance(value, str) and value.startswith("@"):
        if not value.startswith("@@"):
            acc.append(value[1:])
    elif isinstance(value, list):
        for v in value:
            _binds(v, acc)
    elif isinstance(value, dict):
        for v in value.values():
            _binds(v, acc)


def _get(path: str, preimages: dict[str, Any]) -> Any:
    """Resolve 'linkname.field' to that link's preimage field (KeystoneError if absent)."""
    if "." not in path:
        raise KeystoneError(f"assertion path '{path}' must be 'link.field'")
    link, _, fld = path.partition(".")
    if link not in preimages:
        raise KeystoneError(f"assertion references link '{link}', which is not in the chain")
    # An absent field is an error, never None. Returning None silently made an assertion
    # between two missing fields compare None == None and PASS, so a typo or a renamed
    # field turned a load-bearing assertion vacuous while the chain still reported ok.
    if fld not in preimages[link]:
        raise KeystoneError(f"assertion path '{path}' names no field on link '{link}'")
    return preimages[link][fld]


# Largest integer that round-trips through a JS double (Number.MAX_SAFE_INTEGER).
# Above this, JS rounds (9007199254740993 -> ...992) while Python keeps the exact int,
# so the two verifiers would disagree on the same chain. Amounts (minor units) and ms
# timestamps are orders of magnitude below this, so bounding to the I-JSON safe range is
# harmless for real inputs and makes both impls reject an unsafe integer identically.
_MAX_SAFE_INT = 2 ** 53 - 1


def _pos_intish(v: Any) -> bool:
    """True iff v is a positive, integer-VALUED JSON number within the JS-safe range (bool excluded).

    JCS canonicalization collapses an integer-valued float (500.0) to its integer
    form (500), so the two share one reference and are the SAME signed object. Node's
    JSON.parse has no int/float distinction, so `Number.isInteger(500.0)` is true and
    Node accepts it. Python's json keeps 500.0 as a float, so a naive isinstance(v, int)
    check REJECTS what Node accepts -- a verifier divergence on an identical chain, which
    breaks the offline-parity guarantee. Accept integer-valued numbers here (matching
    Node), while still rejecting a genuine fractional amount (500.5), bool, <= 0, and any
    integer above the JS-safe range (where Python-vs-Node would diverge again).
    """
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return 0 < v <= _MAX_SAFE_INT
    if isinstance(v, float):
        return v.is_integer() and 0 < v <= _MAX_SAFE_INT
    return False


def _assert(a: dict, preimages: dict[str, Any]) -> AssertionResult:
    kind = a.get("kind")
    if kind == "scope_subset":
        inner, outer = a["inner"], a["outer"]
        for nm in (inner, outer):
            if nm not in preimages:
                raise KeystoneError(f"scope_subset references link '{nm}', not in the chain")
        ok, why = scope_contains(preimages[outer].get("scope"), preimages[inner].get("scope"))
        return AssertionResult("scope_subset", ok,
                               "" if ok else f"{inner}.scope widens {outer}.scope: {why}")
    if kind == "field_equals":
        av, bv = _get(a["a"], preimages), _get(a["b"], preimages)
        ok = av == bv
        return AssertionResult("field_equals", ok,
                               "" if ok else f"{a['a']} ({av!r}) != {a['b']} ({bv!r})")
    if kind == "time_within":
        win = a["window"]
        if win not in preimages:
            raise KeystoneError(f"time_within references window '{win}', not in the chain")
        t = _get(a["time"], preimages)
        nb, na = preimages[win].get("not_before_ms"), preimages[win].get("not_after_ms")
        ok = isinstance(t, int) and isinstance(nb, int) and isinstance(na, int) and nb <= t <= na
        return AssertionResult("time_within", ok,
                               "" if ok else f"{a['time']} ({t}) not within {win} [{nb}, {na}]")
    if kind == "not_revoked":
        # An action is valid only if it happened strictly before the authority it relies on was
        # revoked. The revocation link structurally binds the revoked authority via an @ref, and a
        # field_equals binds the revoker to the grantor; this is the temporal cascade: any action at
        # or after revoked_at_ms acted under revoked authority -> BROKEN (even multi-hop, since the
        # action's chain transitively binds the revoked authority).
        action, rev = a["action"], a["revocation"]
        for nm in (action, rev):
            if nm not in preimages:
                raise KeystoneError(f"not_revoked references link '{nm}', not in the chain")
        t = _get(a["time"], preimages)
        revoked_at = preimages[rev].get("revoked_at_ms")
        ok = isinstance(t, int) and isinstance(revoked_at, int) and t < revoked_at
        return AssertionResult("not_revoked", ok,
                               "" if ok else f"{action} acted at {t} >= {rev}.revoked_at_ms ({revoked_at}): authority revoked")
    if kind == "journey":
        # One ref for the whole multi-agent task: the journey link must bind every declared hop
        # (no hop omitted). Combined with the scope_subset, field_equals and not_revoked assertions,
        # a single journey_ref proves the entire A->B->C task end to end: identity + authority
        # continuity, scope never widened, nothing acted under a revoked grant.
        ref_name = a["ref"]
        hops = a.get("hops", [])
        if ref_name not in preimages:
            raise KeystoneError(f"journey references link '{ref_name}', not in the chain")
        covered: list[str] = []
        _binds(preimages[ref_name], covered)
        missing = [h for h in hops if h not in covered or h not in preimages]
        ok = bool(hops) and not missing
        return AssertionResult("journey", ok,
                               "" if ok else f"journey '{ref_name}' does not cover hops {missing}")
    if kind == "recurring_cap":
        # Recurr Tier-2 standing authority composed into the chain: prove each cycle's execution
        # stayed inside the ONE signed authority AND the authority stayed inside its policy. Reads
        # the recurr descriptor's own fields (per_cycle_amount_minor, cap_amount_minor, expires_at)
        # so the standing_authority link is the recurr descriptor verbatim (its authority_ref is the
        # keystone link ref, byte-for-byte). Checks, fail-closed, first failure wins:
        #   1. no widening:  per_cycle_amount_minor <= policy.max_amount
        #   2. per cycle:    each execution amount <= per_cycle_amount_minor
        #   3. in window:    each execution time <= authority.expires_at (ISO-8601)
        #   4. cap budget:   sum of the bound execution amounts <= cap_amount_minor
        auth, policy = a["authority"], a["policy"]
        execs = a.get("executions", [])
        amount_field = a.get("amount_field", "amount_minor")
        time_field = a.get("time_field", "executed_at_ms")
        for nm in (auth, policy, *execs):
            if nm not in preimages:
                raise KeystoneError(f"recurring_cap references link '{nm}', not in the chain")
        A, P = preimages[auth], preimages[policy]
        per_cycle, cap_amt, pmax = (A.get("per_cycle_amount_minor"),
                                    A.get("cap_amount_minor"), P.get("max_amount"))
        if not all(_pos_intish(v) for v in (per_cycle, cap_amt, pmax)):
            return AssertionResult("recurring_cap", False,
                                   "authority per_cycle/cap or policy max_amount must be a positive integer")
        per_cycle, cap_amt, pmax = int(per_cycle), int(cap_amt), int(pmax)
        try:
            _dt = datetime.datetime.fromisoformat(str(A.get("expires_at")).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return AssertionResult("recurring_cap", False,
                                   f"authority.expires_at not ISO-8601: {A.get('expires_at')!r}")
        # Must be timezone-aware, else Python (local tz) and JS (Date.parse) disagree on the instant
        # -- a naive expiry would make the window check diverge between implementations. Fail closed.
        if _dt.tzinfo is None:
            return AssertionResult("recurring_cap", False,
                                   "authority.expires_at must be timezone-aware ISO-8601 (got naive)")
        exp_ms = int(_dt.timestamp() * 1000)
        if per_cycle > pmax:
            return AssertionResult("recurring_cap", False,
                                   f"per_cycle_amount_minor {per_cycle} exceeds policy max_amount {pmax}")
        total = 0
        for e in execs:
            E = preimages[e]
            amt, t = E.get(amount_field), E.get(time_field)
            if not (_pos_intish(amt) and _pos_intish(t)):
                return AssertionResult("recurring_cap", False,
                                       f"{e}.{amount_field}/{time_field} must be positive integers")
            amt, t = int(amt), int(t)
            if amt > per_cycle:
                return AssertionResult("recurring_cap", False,
                                       f"{e}.{amount_field} {amt} exceeds per_cycle cap {per_cycle}")
            if t > exp_ms:
                return AssertionResult("recurring_cap", False,
                                       f"{e} executed at {t} after authority expiry {exp_ms}")
            total += amt
        if total > cap_amt:
            return AssertionResult("recurring_cap", False,
                                   f"cumulative {total} exceeds cap_amount_minor {cap_amt}")
        return AssertionResult("recurring_cap", True, "")
    raise KeystoneError(f"unknown assertion kind '{kind}'")


def _pin_results(refs: dict[str, str], expect: Mapping[str, str] | None) -> list[AssertionResult]:
    """Compare recomputed refs against the refs the caller independently trusts.

    A chain recomputes from its own bytes, so on its own it proves consistency.
    Pinning closes the remaining gap: without it, a wider cap (or an entirely
    different authority) in an otherwise well-formed chain still verifies,
    because nothing ties the links to the artefact the customer actually signed.
    Pin `standing_authority` to the recurr `authority_ref`, or any link to the
    ref you hold out of band.
    """
    if not expect:
        return []
    out: list[AssertionResult] = []
    for name, want in expect.items():
        if not isinstance(name, str) or not name:
            raise KeystoneError("expect keys must be non-empty link names")
        if not isinstance(want, str) or not _REF_RE.match(want):
            raise KeystoneError(
                f"expected ref for '{name}' must be 'sha256:' + 64 lowercase hex, got {want!r}"
            )
        if name not in refs:
            out.append(AssertionResult("ref_pinned", False,
                                       f"pinned link '{name}' is not in the chain"))
        elif refs[name] != want:
            out.append(AssertionResult("ref_pinned", False,
                                       f"{name} recomputed {refs[name]} != pinned {want}"))
        else:
            out.append(AssertionResult("ref_pinned", True, ""))
    return out


def verify_chain(chain: dict, *, expect: Mapping[str, str] | None = None) -> ChainResult:
    """Recompute every link in order, enforcing structural composition via @name refs.

    `chain` = {"chain": [ {"name": str, "preimage": obj, "ref"?: str}, ... ]}.
    `expect` optionally maps link name -> the reference you independently trust
    (e.g. the `authority_ref` a customer signed); every pinned link must be in
    the chain and must recompute to exactly that reference.

    Returns a ChainResult; `.ok` is True only if every link recomputes, (where an
    expected `ref` is supplied on the link) matches it, every assertion holds,
    and every pinned reference matches.
    """
    links = chain.get("chain")
    if not isinstance(links, list) or not links:
        raise KeystoneError("chain must contain a non-empty 'chain' array")

    refs: dict[str, str] = {}
    preimages: dict[str, Any] = {}
    result = ChainResult()
    for i, link in enumerate(links):
        if not isinstance(link, dict):
            raise KeystoneError(f"link at index {i} is not an object")
        name = link.get("name")
        if not name:
            raise KeystoneError(f"link at index {i} has no 'name'")
        if name in refs:
            raise KeystoneError(f"duplicate link name '{name}'")
        if "preimage" not in link:
            raise KeystoneError(f"link '{name}' has no 'preimage'")

        binds: list[str] = []
        _binds(link["preimage"], binds)
        resolved = _resolve(link["preimage"], refs, name)
        computed = _ref(resolved)
        expected = link.get("ref")
        ok = (expected is None) or (computed == expected)
        detail = "" if ok else f"recomputed {computed} != declared {expected}"
        refs[name] = computed
        preimages[name] = link["preimage"]
        result.links.append(LinkResult(name, computed, expected, ok, binds, detail))

    # pinned references first: a chain that is not the artefact you trust is broken
    # before any semantic claim about it is worth checking.
    result.assertions.extend(_pin_results(refs, expect))

    # semantic assertions: cross-party binding, scope-consistency, temporal validity
    for a in chain.get("assertions", []):
        result.assertions.append(_assert(a, preimages))

    # the final link is a "cap" if it aggregates two or more prior links into one verdict
    final = links[-1]
    final_binds: list[str] = []
    _binds(final.get("preimage", {}), final_binds)
    if len(final_binds) >= 2 and all(b in refs for b in final_binds):
        result.cap = final["name"]
        result.cap_covers = final_binds
        result.capped = result.links[-1].ok

    return result
