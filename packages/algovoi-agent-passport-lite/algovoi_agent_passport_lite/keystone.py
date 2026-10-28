"""Keystone self-declaration for algovoi-agent-passport-lite. Pure metadata: declares this package as the
Keystone `passport` step via the algovoi.keystone.steps entry point, so it is discoverable
and self-describing independent of the control-panel catalogue. Native step: `alias_of`
records that its ref IS the canonical `passport_ref`.
"""
from __future__ import annotations


def keystone_step() -> dict:
    return {
        "package": "algovoi-agent-passport-lite",
        "step": "passport",
        "ref": "passport_ref",
        "alias_of": "passport_ref",
        "order": 1,
        "posture": "Identity + assurance gate",
        "default": {"__keystone": {"canon_version": "jcs-rfc8785-v1", "hash_algo": "sha256"}},
    }
