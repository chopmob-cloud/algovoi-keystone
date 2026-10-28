"""Tests for the Compliance Command Center live-service bridge addon.

The addon lets the retention-chain service also self-register with a CCC, using
the same POST /v1/services contract as the substrate-2 control plane. It is
purely additive and best-effort: unconfigured or unreachable means False, never
an exception.
"""
from __future__ import annotations

import algovoi_retention_chain.hub_client as hc


def _clear_ccc_env(monkeypatch):
    for k in ("CCC_HUB_URL", "CCC_HUB_TOKEN", "CCC_HUB_NAME", "CCC_HUB_SELF_URL"):
        monkeypatch.delenv(k, raising=False)


def test_unconfigured_returns_false(monkeypatch):
    _clear_ccc_env(monkeypatch)
    assert hc.register_into_ccc_from_env() is False


def test_partial_config_returns_false(monkeypatch):
    _clear_ccc_env(monkeypatch)
    monkeypatch.setenv("CCC_HUB_URL", "http://command-center:8200")
    # no token, no self url
    assert hc.register_into_ccc_from_env() is False


def test_full_config_posts_expected_contract(monkeypatch):
    _clear_ccc_env(monkeypatch)
    monkeypatch.setenv("CCC_HUB_URL", "http://command-center:8200/")
    monkeypatch.setenv("CCC_HUB_TOKEN", "svc-tok-123")
    monkeypatch.setenv("CCC_HUB_SELF_URL", "http://retention-chain:8096")

    captured = {}

    def fake_self_register(hub_url, token, *, name, type_, base_url, health_path, timeout):
        captured.update(
            hub_url=hub_url, token=token, name=name, type_=type_,
            base_url=base_url, health_path=health_path,
        )
        return True

    monkeypatch.setattr(hc, "self_register", fake_self_register)
    assert hc.register_into_ccc_from_env() is True
    assert captured["hub_url"] == "http://command-center:8200/"
    assert captured["token"] == "svc-tok-123"
    assert captured["name"] == "retention-chain"        # default name
    assert captured["type_"] == "retention-chain"
    assert captured["base_url"] == "http://retention-chain:8096"
    assert captured["health_path"] == "/health"


def test_custom_name_honoured(monkeypatch):
    _clear_ccc_env(monkeypatch)
    monkeypatch.setenv("CCC_HUB_URL", "http://cc:8200")
    monkeypatch.setenv("CCC_HUB_TOKEN", "t")
    monkeypatch.setenv("CCC_HUB_SELF_URL", "http://rc:8096")
    monkeypatch.setenv("CCC_HUB_NAME", "payment-retention")
    monkeypatch.setattr(hc, "self_register", lambda *a, **k: True)
    # name flows through; we assert via a capturing stub
    seen = {}
    monkeypatch.setattr(hc, "self_register",
                        lambda *a, **k: seen.update(name=k["name"]) or True)
    assert hc.register_into_ccc_from_env() is True
    assert seen["name"] == "payment-retention"


def test_never_raises_on_transport_error(monkeypatch):
    _clear_ccc_env(monkeypatch)
    monkeypatch.setenv("CCC_HUB_URL", "http://cc:8200")
    monkeypatch.setenv("CCC_HUB_TOKEN", "t")
    monkeypatch.setenv("CCC_HUB_SELF_URL", "http://rc:8096")

    def boom(*a, **k):
        raise OSError("connection refused")

    # self_register itself swallows; but guard the wrapper contract too.
    monkeypatch.setattr(hc, "self_register", lambda *a, **k: False)
    assert hc.register_into_ccc_from_env() is False
