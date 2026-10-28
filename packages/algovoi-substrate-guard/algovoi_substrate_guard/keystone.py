"""Keystone self-declaration for algovoi-substrate-guard. Pure metadata: declares this package as the
Keystone `guard` step via the algovoi.keystone.steps entry point, so it is discoverable
and self-describing independent of the control-panel catalogue. Native step: `alias_of`
records that its ref IS the canonical `guard_ref`.
"""
from __future__ import annotations


def keystone_step() -> dict:
    return {
        "package": "algovoi-substrate-guard",
        "step": "guard",
        "ref": "guard_ref",
        "alias_of": "guard_ref",
        "order": 0,
        "posture": "Input bounds + DoS gate (pre-canon)",
        "default": {"__keystone": {"canon_version": "jcs-rfc8785-v1", "hash_algo": "sha256"}},
    }
