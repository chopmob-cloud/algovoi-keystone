# Changelog

All notable changes to `algovoi-retention-chain` are documented here.

## [0.4.4] - 2026-10-29

### Security

- **Chain linkage is now required (breaking for legacy chains).** The v1 preimage
  hashed `{chain_seq, issuer_id, prev_receipt_hash, receipt_hash}` and never the
  previous record's own `chain_ref`. Adjacency was checked against
  `prev_receipt_hash` — a *declared* value — so interior records could be rewritten,
  re-attributed and re-signed consistently while a pinned `expected_head` stayed
  byte-identical. Only the head record was genuinely pinned.
- New `retention_chain_ref_linked(..., prev_chain_ref=...)` adds `prev_chain_ref` to
  the preimage, so each link commits to its predecessor and pinning the head
  transitively commits to every earlier record. Rewriting any interior record now
  changes the head.
- `verify_chain_sequence()` verifies under the linked preimage by default and rejects
  v1 chains. Pass `allow_legacy_v1=True` to restore the old head-only assurance for
  existing data. `retention_chain_ref()` remains available for legacy refs.
- An interior slice is now rejected even with no pins: dropping the genesis breaks
  linkage itself, where v1 needed `require_genesis` to notice.

## [0.2.0] - 2026-06-17

### Added

- **RFC 9421 integration** (`pip install algovoi-retention-chain[rfc9421]`).

  New module `algovoi_retention_chain.rfc9421` with `verify_signed_chain_link`
  and `SignedChainLinkResult`. In one call, independently verifies:
  (1) the RFC 9421 HTTP Message Signature on the receipt-carrying request
  (via `algovoi-rfc9421-verifier>=0.3.0`, Ed25519 + RFC 9530 Content-Digest)
  and (2) the `retention_chain_ref` integrity for that chain link.
  Both checks are independent: `.signature_valid` and `.chain_ref_valid` are
  separate fields so callers can distinguish a bad HTTP signature from a
  tampered chain ref. `.valid` is True only when both pass.

- `[rfc9421]` optional extra pulling in `algovoi-rfc9421-verifier>=0.3.0`.
  The core package (`rfc8785` only) is unchanged.

- Conformance vector set `retention_chain_rfc9421_v1` (3 vectors: genesis + 2
  chain links, real Ed25519 RFC 9421 signatures over JCS-canonical bodies,
  fixed `created=1750000000`, byte-for-byte reproducible).
  File: `vectors/retention-chain-rfc9421-v1.json`.

- `tests/test_rfc9421.py` (8 tests: canonical vectors, tampered body, wrong
  chain ref, wrong public key, 3-receipt chain integration).

The core `retention_chain_ref` / `verify_chain_link` / `verify_chain_sequence`
API and all existing conformance vectors are unchanged.

## [0.1.0] - 2026-06-17

### Added
- `retention_chain_ref`, `verify_chain_link`, `verify_chain_sequence` primitives
  (JCS RFC 8785 + SHA-256 over the four-field preimage).
- Bridged HTTP service (`algovoi_retention_chain.service`): `/v1/chain-ref`,
  `/v1/verify-link`, `/v1/verify-sequence`, `/health`.
- Substrate-2 control-plane bridging via `S2_HUB_URL` + `S2_HUB_TOKEN`
  (self-registration; retention is self-verifiable, no trust set consumed).
- Dockerfile (port 8096), console command, and self-contained acceptance test.
- Normative spec: `draft-hopley-x402-retention-chain` on the IETF datatracker.
