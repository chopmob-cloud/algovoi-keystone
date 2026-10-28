"""Keystone self-declaration for algovoi-composite-trust-query-lite. Pure metadata: declares this package as the
Keystone `trust_query` step via the algovoi.keystone.steps entry point, so it is discoverable
and self-describing independent of the control-panel catalogue. Native step: `alias_of`
records that its ref IS the canonical `trust_query_ref`.
"""
from __future__ import annotations


def keystone_step() -> dict:
    return {
        "package": "algovoi-composite-trust-query-lite",
        "step": "trust_query",
        "ref": "trust_query_ref",
        "alias_of": "trust_query_ref",
        "order": 7,
        "posture": "Composite trust query",
        "default": {"__keystone": {"canon_version": "jcs-rfc8785-v1", "hash_algo": "sha256"}},
    }
