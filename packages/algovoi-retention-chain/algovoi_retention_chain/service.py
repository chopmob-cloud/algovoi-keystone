"""Retention Chain HTTP service.

Wraps the retention_chain_ref primitive as a stateless FastAPI service and bolts
into the substrate-2 control plane like the other bridged services.

Endpoints:
  POST /v1/chain-ref         — compute the retention_chain_ref for one record
  POST /v1/verify-link       — verify a single chain link
  POST /v1/verify-sequence   — verify a sequence of records forms an unbroken chain
  GET  /health               — liveness probe

Configuration (environment variables):
  RETENTION_CHAIN_BIND   — bind address (default 0.0.0.0:8096)
  S2_HUB_URL             — substrate-2 control plane URL (optional). If set, the
                           service self-registers so it appears in CP posture.
  S2_HUB_TOKEN           — admin token, required to self-register.
  S2_HUB_NAME            — service name in the posture (default "retention-chain")
  S2_HUB_SELF_URL        — how the CP reaches this service (default http://retention-chain:8096)

No secret is required; the service is out-of-box clean with zero configuration.

IETF anchor: draft-hopley-x402-retention-chain
"""
from __future__ import annotations

import logging
import os
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, Field

from algovoi_retention_chain import (
    __version__,
    retention_chain_ref,
    verify_chain_link,
    verify_chain_sequence,
)

logger = logging.getLogger(__name__)


# ── Hub bridging (optional) ───────────────────────────────────────────────────

def _bridge_into_control_plane() -> None:
    """Self-register with the substrate-2 control plane if S2_HUB_* is configured,
    and, as an addon, with a Compliance Command Center if CCC_HUB_* is configured.

    Retention is self-verifiable and does not consume the issuer trust set, so we
    only announce ourselves to each hub so the service shows in its posture. Both
    registrations are best-effort and independent: either, both, or neither.
    """
    hub = os.environ.get("S2_HUB_URL", "").strip()
    token = os.environ.get("S2_HUB_TOKEN", "").strip()
    if hub and token:
        from algovoi_retention_chain.hub_client import self_register
        ok = self_register(
            hub, token,
            name=os.environ.get("S2_HUB_NAME", "retention-chain"),
            type_="retention-chain",
            base_url=os.environ.get("S2_HUB_SELF_URL", "http://retention-chain:8096"),
        )
        logger.info("retention_chain.hub.self_register url=%s ok=%s", hub, ok)

    # Addon: also announce to a Compliance Command Center live-service bridge.
    ccc = os.environ.get("CCC_HUB_URL", "").strip()
    if ccc:
        from algovoi_retention_chain.hub_client import register_into_ccc_from_env
        ok = register_into_ccc_from_env()
        logger.info("retention_chain.ccc.self_register url=%s ok=%s", ccc, ok)


_bridge_into_control_plane()


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="AlgoVoi Retention Chain",
    description=(
        "Self-verifiable retention chain for payment receipts. Each receipt carries "
        "a retention_chain_ref = SHA-256(JCS({chain_seq, issuer_id, prev_receipt_hash, "
        "receipt_hash})); any party holding a contiguous or non-contiguous subset can "
        "verify chain integrity from local data alone. No AlgoVoi infrastructure, "
        "registry lookup, or network access is required. Satisfies MiCA Art. 68(9), "
        "DORA Art. 17, AMLR Art. 77. IETF: draft-hopley-x402-retention-chain"
    ),
    version=__version__,
    docs_url="/docs",
    redoc_url=None,
)


# ── Request / response models ─────────────────────────────────────────────────

class ChainRefRequest(BaseModel):
    chain_seq: int = Field(..., ge=0, description="Zero-indexed sequence position.")
    issuer_id: str = Field(..., min_length=1, description="Non-empty issuer identifier.")
    receipt_hash: str = Field(..., description='"sha256:<64-hex>" of the current receipt.')
    prev_receipt_hash: str = Field(
        "", description='"sha256:<64-hex>" of the previous receipt, or "" for genesis.'
    )


class ChainRefResponse(BaseModel):
    chain_ref: str


class VerifyLinkRequest(ChainRefRequest):
    chain_ref: str = Field(..., description='The claimed "sha256:<64-hex>" chain_ref to check.')


class Record(BaseModel):
    chain_seq: int = Field(..., ge=0)
    issuer_id: str = Field(..., min_length=1)
    receipt_hash: str
    prev_receipt_hash: str = ""
    chain_ref: str


class VerifySequenceRequest(BaseModel):
    records: list[Record] = Field(..., description="Records ordered by ascending chain_seq.")


class VerifyResponse(BaseModel):
    valid: bool
    failure_reason: str | None = None


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "service": "retention-chain", "version": __version__}


@app.post("/v1/chain-ref", response_model=ChainRefResponse)
async def chain_ref(body: ChainRefRequest) -> ChainRefResponse:
    """Compute the retention_chain_ref for a single record."""
    try:
        ref = retention_chain_ref(
            prev_receipt_hash=body.prev_receipt_hash,
            receipt_hash=body.receipt_hash,
            chain_seq=body.chain_seq,
            issuer_id=body.issuer_id,
        )
    except ValueError as exc:
        # Surface validation errors as a 400-style body without leaking internals.
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return ChainRefResponse(chain_ref=ref)


@app.post("/v1/verify-link", response_model=VerifyResponse)
async def verify_link(body: VerifyLinkRequest) -> VerifyResponse:
    """Verify a single chain link against its claimed chain_ref."""
    ok = verify_chain_link(
        chain_ref=body.chain_ref,
        prev_receipt_hash=body.prev_receipt_hash,
        receipt_hash=body.receipt_hash,
        chain_seq=body.chain_seq,
        issuer_id=body.issuer_id,
    )
    return VerifyResponse(valid=ok, failure_reason=None if ok else "chain_ref_mismatch")


@app.post("/v1/verify-sequence", response_model=VerifyResponse)
async def verify_sequence(body: VerifySequenceRequest) -> VerifyResponse:
    """Verify a sequence of records forms a valid unbroken chain."""
    records = [r.model_dump() for r in body.records]
    ok = verify_chain_sequence(records)
    return VerifyResponse(valid=ok, failure_reason=None if ok else "broken_or_invalid_chain")


def main() -> None:
    """Console entry point — serve the retention chain service."""
    import uvicorn
    bind = os.environ.get("RETENTION_CHAIN_BIND", "0.0.0.0:8096")
    host, _, port = bind.partition(":")
    uvicorn.run(app, host=host, port=int(port or "8096"))
