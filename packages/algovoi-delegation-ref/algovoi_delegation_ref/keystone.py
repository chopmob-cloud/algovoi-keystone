"""Keystone self-declaration for algovoi-delegation-ref. Pure metadata: declares this package as the
Keystone `delegation` step via the algovoi.keystone.steps entry point, so it is discoverable
and self-describing independent of the control-panel catalogue. Native step: `alias_of`
records that its ref IS the canonical `delegation_ref`.
"""
from __future__ import annotations


def keystone_step() -> dict:
    return {
        "package": "algovoi-delegation-ref",
        "step": "delegation",
        "ref": "delegation_ref",
        "alias_of": "delegation_ref",
        "order": 8,
        "posture": "Cross-party delegation: depth + scope narrowing",
        "default": {"__keystone": {"canon_version": "jcs-rfc8785-v1", "hash_algo": "sha256"}},
    }
