"""Keystone self-declaration for algovoi-payment-mandate-lite. Pure metadata: declares this package as the
Keystone `mandate` step via the algovoi.keystone.steps entry point, so it is discoverable
and self-describing independent of the control-panel catalogue. Native step: `alias_of`
records that its ref IS the canonical `mandate_ref`.
"""
from __future__ import annotations


def keystone_step() -> dict:
    return {
        "package": "algovoi-payment-mandate-lite",
        "step": "mandate",
        "ref": "mandate_ref",
        "alias_of": "mandate_ref",
        "order": 2,
        "posture": "Scope + charge authorisation",
        "default": {"__keystone": {"canon_version": "jcs-rfc8785-v1", "hash_algo": "sha256"}},
    }
