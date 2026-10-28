"""Keystone self-declaration for algovoi-cancellation-receipt-lite. Pure metadata: declares this package as the
Keystone `cancellation` step via the algovoi.keystone.steps entry point, so it is discoverable
and self-describing independent of the control-panel catalogue. Native step: `alias_of`
records that its ref IS the canonical `cancellation_ref`.
"""
from __future__ import annotations


def keystone_step() -> dict:
    return {
        "package": "algovoi-cancellation-receipt-lite",
        "step": "cancellation",
        "ref": "cancellation_ref",
        "alias_of": "cancellation_ref",
        "order": 11,
        "posture": "Cancellation receipt (freeze-at-acceptance)",
        "default": {"__keystone": {"canon_version": "jcs-rfc8785-v1", "hash_algo": "sha256"}},
    }
