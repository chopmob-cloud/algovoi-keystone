"""Keystone self-declaration for algovoi-execution-ref. Pure metadata: declares this package as the
Keystone `execution` step via the algovoi.keystone.steps entry point, so it is discoverable
and self-describing independent of the control-panel catalogue. Native step: `alias_of`
records that its ref IS the canonical `execution_ref`.
"""
from __future__ import annotations


def keystone_step() -> dict:
    return {
        "package": "algovoi-execution-ref",
        "step": "execution",
        "ref": "execution_ref",
        "alias_of": "execution_ref",
        "order": 6,
        "posture": "Execution evidence binding",
        "default": {"__keystone": {"canon_version": "jcs-rfc8785-v1", "hash_algo": "sha256"}},
    }
