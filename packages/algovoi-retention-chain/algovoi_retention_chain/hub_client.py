"""Tiny client for the substrate-2 control plane hub. Standard library only, no
new dependencies, so the service stays self-contained.

  fetch_issuer_pks(hub_url)         -> {did: pk_b64}  live trust-pull from the CP
  self_register(hub_url, token, ...)                  register in a control plane
  register_into_ccc_from_env()                        register in a Compliance
                                                      Command Center (addon)

The retention-chain substrate is self-verifiable and does not require the issuer
trust set to function; it still self-registers so it appears in the control
plane posture alongside the other substrate-2 services.

The Compliance Command Center (CCC) live-service bridge speaks the same
POST /v1/services contract, so a CCC-targeting wrapper is a thin addon that lets
the service also appear in a Command Center's "Live service health" panel. It is
purely additive: the substrate-2 registration above is unchanged.
"""
from __future__ import annotations

import json
import os
import urllib.request


def fetch_issuer_pks(hub_url: str, *, timeout: float = 5.0) -> dict[str, str]:
    """GET ``<hub>/v1/issuer-pks`` and return the ``{did: pk_b64}`` trust map."""
    url = hub_url.rstrip("/") + "/v1/issuer-pks"
    with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 (internal hub URL)
        data = json.loads(resp.read().decode("utf-8"))
    return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}


def self_register(hub_url: str, token: str, *, name: str, type_: str, base_url: str,
                  health_path: str = "/health", timeout: float = 5.0) -> bool:
    """POST ``<hub>/v1/services`` to register this service with the control plane
    so it appears in the posture. Returns True on success, False otherwise."""
    body = json.dumps({
        "name": name, "type": type_, "base_url": base_url, "health_path": health_path,
    }).encode("utf-8")
    req = urllib.request.Request(
        hub_url.rstrip("/") + "/v1/services", data=body, method="POST",
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return 200 <= resp.status < 300
    except Exception:
        return False


def register_into_ccc_from_env(*, timeout: float = 5.0) -> bool:
    """Self-register with a Compliance Command Center live-service bridge when the
    CCC_HUB_* environment is set. Mirrors the CCC hub_client contract a product
    copies: POST ``<CCC_HUB_URL>/v1/services`` with a Bearer token and a body of
    {name, type, base_url, health_path}. Returns False when not configured.
    Best-effort and never raises, so an absent or unreachable Command Center can
    never stop the service from booting.

    Env:
      CCC_HUB_URL       Command Center base URL (e.g. http://command-center:8200)
      CCC_HUB_TOKEN     the Command Center service token
      CCC_HUB_NAME      service name in the panel (default "retention-chain")
      CCC_HUB_SELF_URL  how the Command Center reaches this service
    """
    hub = os.environ.get("CCC_HUB_URL", "").strip()
    tok = os.environ.get("CCC_HUB_TOKEN", "").strip()
    name = os.environ.get("CCC_HUB_NAME", "retention-chain").strip() or "retention-chain"
    self_url = os.environ.get("CCC_HUB_SELF_URL", "").strip()
    if not (hub and tok and self_url):
        return False
    return self_register(
        hub, tok, name=name, type_="retention-chain",
        base_url=self_url, health_path="/health", timeout=timeout,
    )
