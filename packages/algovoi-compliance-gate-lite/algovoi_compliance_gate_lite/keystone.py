"""Keystone self-declaration for algovoi-compliance-gate-lite. Pure metadata: declares this package as the
Keystone `screen` step via the algovoi.keystone.steps entry point, so it is discoverable
and self-describing independent of the control-panel catalogue. Native step: `alias_of`
records that its ref IS the canonical `screen_ref`.
"""
from __future__ import annotations


def keystone_step() -> dict:
    return {
        "package": "algovoi-compliance-gate-lite",
        "step": "screen",
        "ref": "screen_ref",
        "alias_of": "screen_ref",
        "order": 4,
        "posture": "Compliance + sanctions screen",
        "default": {"__keystone": {"canon_version": "jcs-rfc8785-v1", "hash_algo": "sha256"}},
    }
