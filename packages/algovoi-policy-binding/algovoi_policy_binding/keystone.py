"""Keystone self-declaration for algovoi-policy-binding. Pure metadata: declares this package as the
Keystone `policy_bound` step via the algovoi.keystone.steps entry point, so it is discoverable
and self-describing independent of the control-panel catalogue. Native step: `alias_of`
records that its ref IS the canonical `policy_bound_ref`.
"""
from __future__ import annotations


def keystone_step() -> dict:
    return {
        "package": "algovoi-policy-binding",
        "step": "policy_bound",
        "ref": "policy_bound_ref",
        "alias_of": "policy_bound_ref",
        "order": 3,
        "posture": "Policy snapshot seal",
        "default": {"__keystone": {"canon_version": "jcs-rfc8785-v1", "hash_algo": "sha256"}},
    }
