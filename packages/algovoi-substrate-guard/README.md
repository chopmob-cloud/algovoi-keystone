# algovoi-substrate-guard (lite)

Deterministic input-bounds / DoS hardening gate for the [AlgoVoi](https://docs.algovoi.co.uk) JCS
substrate. It runs **before** canonicalization and fails closed on well-formed but resource-hostile
payloads, with a named reject code. Apache-2.0.

The substrate already fails closed on **malformed** input. A payload can be perfectly valid JSON and
still be hostile by *resource*: megabytes of data, nested ten thousand deep, millions of keys, an 8 MB
string, numbers outside the safe-integer range. Those sail past "is it well-formed?" and into your
canonicalizer and hasher, which is exactly where a cheap denial-of-service lives. This guard is the front
door that stops them, so the expensive work never touches a hostile payload.

```bash
pip install algovoi-substrate-guard
```

```python
from algovoi_substrate_guard import guard, profile_ref, GuardError, Profile

# Accept or reject BEFORE canonicalization. Never truncates, never repairs.
try:
    guard(value)                 # uses the default profile guard-receipt-v1
    ref = ...                    # ...then action_ref(...) / decision_ref(...) / a receipt
except GuardError as e:
    print("rejected:", e.code)   # e.g. REJECT_OVER_DEPTH, REJECT_TOO_MANY_KEYS

# The limits in force are content-addressed, so a record can prove which bounds admitted it.
profile_ref()                    # "sha256:a4791b13...c3d5524a6"  (guard-receipt-v1)
profile_ref(Profile(max_depth=8, max_object_keys=16))   # your own pinnable profile
```

## What it adds

- **A pre-canonicalization gate.** Runs before JCS + SHA-256, so the expensive work never touches a hostile
  payload. Accept, or reject with a named code (`REJECT_OVER_DEPTH`, `REJECT_TOO_MANY_KEYS`, …). Never
  truncates or repairs: no silent mangling, no ambiguous half-processing.
- **Resource fail-closed, to match the malformed fail-closed.** Together the substrate fails closed on both
  axes: bad shape and bad size.
- **Pinnable, provable limits.** `profile_ref = "sha256:" + SHA-256(JCS(profile))`, the same discipline as
  `policy_binding`. An adopter pins `guard-receipt-v1` (or their own profile); a record can carry the
  `profile_ref` it was admitted under, so an auditor can prove which limits were enforced.
- **Cross-implementation by construction.** Every bound is a pure structural property of the parsed value
  (depth, count, length), so independent implementations enforce it identically: "N independent
  implementations reject the same hostile inputs with the same code."
- **Additive, zero blast radius.** Changes no hash, adds no crypto primitive. Composes in one line:
  `guard(value)` then your existing `action_ref(...)`. Everything built on the canonicalization substrate
  gets the protection for free, with no format change.

## Default profile `guard-receipt-v1`

| limit | default | reject code |
|---|---|---|
| `max_bytes` (UTF-8 of canonical form) | 65536 | `REJECT_OVER_SIZE` |
| `max_depth` (nesting, root = 1) | 32 | `REJECT_OVER_DEPTH` |
| `max_object_keys` (per object) | 256 | `REJECT_TOO_MANY_KEYS` |
| `max_array_length` | 1024 | `REJECT_OVER_ARRAY` |
| `max_string_length` (per string / key) | 8192 | `REJECT_OVER_STRING` |
| `max_total_nodes` | 4096 | `REJECT_OVER_NODES` |
| `number_safety` | on | `REJECT_UNSAFE_NUMBER` (outside JSON safe-int range / non-finite) |

`guard-receipt-v1` addresses to
`sha256:a4791b13c67a16109b85ef67fc65700ea902b6ad40dad44d8556632c3d5524a6`.

## Honest scope

A deterministic structural validator plus a content-addressed profile: **not** cryptography, and **not**
rate-limiting or replay windows (those stay in the runtime verifier layer, never claimed as a substrate
property). This is the open, lite tier of the AlgoVoi hardening layer.

## Conformance

`conformance/substrate_guard_v1/` carries the canonical vectors plus an independent verifier
(`verify.py`). The same vectors and a Node verifier ship in the `@algovoi/substrate-guard` package, so the
two implementations are checked to reject the same hostile inputs with the same code and compute the same
`profile_ref`. Vectors are also published in the
[AlgoVoi JCS conformance corpus](https://github.com/chopmob-cloud/algovoi-jcs-conformance-vectors).

```bash
pip install rfc8785 algovoi-substrate
python conformance/substrate_guard_v1/verify.py
```
