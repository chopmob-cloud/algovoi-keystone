"""Keystone self-declaration for algovoi-retention-chain. Pure metadata: declares this
package as the Keystone `retention` step via the algovoi.keystone.steps entry point, so
it is discoverable and self-describing independent of the control-panel catalogue.
"""
from __future__ import annotations


def keystone_step() -> dict:
    return {
        "package": "algovoi-retention-chain",
        "step": "retention",
        "ref": "retention_chain_ref",
        "alias_of": "retention_chain_ref",
        "order": 13,
        "posture": "Tamper-evident retention chain (hash-linked receipts)",
        "default": {"__keystone": {"canon_version": "jcs-rfc8785-v1", "hash_algo": "sha256"}},
    }
