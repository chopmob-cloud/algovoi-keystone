"""Keystone self-declaration for algovoi-revocation-ref. Pure metadata: declares this package as the
Keystone `revocation` step via the algovoi.keystone.steps entry point, so it is discoverable
and self-describing independent of the control-panel catalogue.
"""
from __future__ import annotations


def keystone_step() -> dict:
    return {
        "package": "algovoi-revocation-ref",
        "step": "revocation",
        "ref": "revocation_ref",
        "alias_of": "revocation_ref",
        "order": 9,
        "posture": "Revocation + not_revoked assertion",
        "default": {"__keystone": {"canon_version": "jcs-rfc8785-v1", "hash_algo": "sha256"}},
    }
