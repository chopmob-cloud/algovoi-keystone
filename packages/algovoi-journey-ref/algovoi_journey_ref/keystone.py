"""Keystone self-declaration for algovoi-journey-ref. Pure metadata: declares this package as the
Keystone `journey` step via the algovoi.keystone.steps entry point, so it is discoverable
and self-describing independent of the control-panel catalogue.
"""
from __future__ import annotations


def keystone_step() -> dict:
    return {
        "package": "algovoi-journey-ref",
        "step": "journey",
        "ref": "journey_ref",
        "alias_of": "journey_ref",
        "order": 10,
        "posture": "Multi-hop integrity + outcome aggregation",
        "default": {"__keystone": {"canon_version": "jcs-rfc8785-v1", "hash_algo": "sha256"}},
    }
