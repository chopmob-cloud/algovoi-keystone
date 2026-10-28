"""Keystone self-declaration for algovoi-refund-receipt-lite. Pure metadata: declares this package as the
Keystone `refund` step via the algovoi.keystone.steps entry point, so it is discoverable
and self-describing independent of the control-panel catalogue. Native step: `alias_of`
records that its ref IS the canonical `refund_ref`.
"""
from __future__ import annotations


def keystone_step() -> dict:
    return {
        "package": "algovoi-refund-receipt-lite",
        "step": "refund",
        "ref": "refund_ref",
        "alias_of": "refund_ref",
        "order": 12,
        "posture": "Refund receipt (bound to the original mandate)",
        "default": {"__keystone": {"canon_version": "jcs-rfc8785-v1", "hash_algo": "sha256"}},
    }
