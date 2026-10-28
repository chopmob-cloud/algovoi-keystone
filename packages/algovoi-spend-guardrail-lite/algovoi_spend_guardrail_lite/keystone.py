"""Keystone self-declaration for algovoi-spend-guardrail-lite. Pure metadata: declares this package as the
Keystone `decision` step via the algovoi.keystone.steps entry point, so it is discoverable
and self-describing independent of the control-panel catalogue. Native step: `alias_of`
records that its ref IS the canonical `guardrail_ref`.
"""
from __future__ import annotations


def keystone_step() -> dict:
    return {
        "package": "algovoi-spend-guardrail-lite",
        "step": "decision",
        "ref": "guardrail_ref",
        "alias_of": "guardrail_ref",
        "order": 5,
        "posture": "Velocity + amount decision",
        "default": {"__keystone": {"canon_version": "jcs-rfc8785-v1", "hash_algo": "sha256"}},
    }
