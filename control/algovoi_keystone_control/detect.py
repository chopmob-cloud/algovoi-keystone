"""Auto-detect installed algovoi keystone packages and their configurable settings."""
import importlib.metadata as meta
import os
import re

# Untrusted vendor descriptors (``algovoi.keystone.steps`` entry-point bolt-ons) are
# validated here: only well-formed step/ref names, integral order and safe package
# names are accepted, and nothing may collide with the built-in catalogue.
_STEP_NAME_RE = re.compile(r"^[a-z0-9_]{2,40}$")
_PKG_NAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")
_MAX_VENDOR_STEPS = 256


def _catalogue() -> list:
    return [
        {
            "package": "algovoi-substrate-guard",
            "step": "guard",
            "order": 0,
            "ref": "guard_ref",
            "posture": "Input bounds + DoS gate (pre-canon)",
            "default": {
                "__keystone": {
                    "canon_version": "jcs-rfc8785-v1",
                    "hash_algo": "sha256",
                    "required_fields": ["input_bytes", "guard_result", "guarded_at_ms"],
                },
                "max_string_bytes": 2048,
                "max_depth": 8,
                "max_keys": 64,
                "rate_limit_per_sec": 100,
            },
        },
        {
            "package": "algovoi-agent-passport",
            "packages": ["algovoi-agent-passport", "algovoi-agent-passport-lite"],
            "step": "passport",
            "order": 1,
            "ref": "passport_ref",
            "posture": "Identity + assurance gate",
            "default": {
                "__keystone": {
                    "canon_version": "jcs-rfc8785-v1",
                    "hash_algo": "sha256",
                    "required_fields": ["agent_id", "assurance_level", "issued_at_ms", "scope"],
                    "assurance_levels": ["LOW", "MEDIUM", "HIGH", "VERIFIED"],
                    "did_methods": ["did:web", "did:key", "did:peer"],
                    "max_clock_skew_ms": 5000,
                },
                "require_did": True,
                "min_assurance": "MEDIUM",
                "max_age_ms": 86400000,
                "allow_anonymous": False,
            },
        },
        {
            "package": "algovoi-payment-mandate",
            "packages": ["algovoi-payment-mandate", "algovoi-payment-mandate-lite"],
            "step": "mandate",
            "order": 2,
            "ref": "mandate_ref",
            "posture": "Scope + charge authorisation",
            "default": {
                "__keystone": {
                    "canon_version": "jcs-rfc8785-v1",
                    "hash_algo": "sha256",
                    "required_fields": ["passport_ref", "payer_ref", "amount_minor", "currency", "scope", "issued_at_ms"],
                    "currency_codes": ["GBP", "USD", "EUR", "USDC", "ETH", "ALGO", "VOI"],
                    "scope_separator": ":",
                    "chain_requires": ["passport_ref"],
                },
                "require_scope_match": True,
                "max_amount_minor": 100000,
                "allow_open_scope": False,
            },
        },
        {
            "package": "algovoi-policy-binding",
            "step": "policy_bound",
            "order": 3,
            "ref": "policy_bound_ref",
            "posture": "Policy snapshot seal",
            "default": {
                "__keystone": {
                    "canon_version": "jcs-rfc8785-v1",
                    "hash_algo": "sha256",
                    "required_fields": ["mandate_ref", "policy_hash", "bound_at_ms"],
                    "chain_requires": ["mandate_ref"],
                },
                "require_active_policy": False,
                "allow_unsigned_policy": True,
            },
        },
        {
            "package": "algovoi-compliance-gate",
            "packages": ["algovoi-compliance-gate", "algovoi-compliance-gate-lite"],
            "step": "screen",
            "order": 4,
            "ref": "screen_ref",
            "posture": "Compliance + sanctions screen",
            "default": {
                "__keystone": {
                    "canon_version": "jcs-rfc8785-v1",
                    "hash_algo": "sha256",
                    "required_fields": ["mandate_ref", "payer_ref", "screen_result", "screened_at_ms"],
                    "screen_results": ["PASS", "REFER", "BLOCK"],
                    "chain_requires": ["mandate_ref"],
                },
                "check_sanctions": True,
                "check_pep": True,
                "check_denylist": True,
                "blocked_geos": [],
                "risk_threshold": 70,
                "travel_rule_threshold_minor": 100000,
            },
        },
        {
            "package": "algovoi-spend-guardrail",
            "packages": ["algovoi-spend-guardrail", "algovoi-spend-guardrail-lite"],
            "step": "decision",
            "order": 5,
            "ref": "guardrail_ref",
            "posture": "Velocity + amount decision",
            "default": {
                "__keystone": {
                    "canon_version": "jcs-rfc8785-v1",
                    "hash_algo": "sha256",
                    "required_fields": ["screen_ref", "agent_ref", "verdict", "decided_at_ms"],
                    "verdicts": ["ALLOW", "REFER", "DENY"],
                    "chain_requires": ["screen_ref"],
                },
                "velocity_window_ms": 3600000,
                "velocity_limit": 10,
                "amount_cap_minor": 500000,
                "risk_threshold": 70,
                "refer_threshold": 50,
            },
        },
        {
            "package": "algovoi-execution-ref",
            "step": "execution",
            "order": 6,
            "ref": "execution_ref",
            "posture": "Execution evidence binding",
            "default": {
                "__keystone": {
                    "canon_version": "jcs-rfc8785-v1",
                    "hash_algo": "sha256",
                    "required_fields": ["decision_ref", "action_type", "scope", "outcome", "executed_at_ms"],
                    "outcomes": ["COMMITTED", "SKIPPED", "FAILED", "REVERSED"],
                    "chain_requires": ["decision_ref"],
                },
                "require_decision_ref": True,
                "allowed_outcomes": ["COMMITTED", "SKIPPED", "FAILED", "REVERSED"],
            },
        },
        {
            "package": "algovoi-trust-query",
            "packages": ["algovoi-trust-query", "algovoi-composite-trust-query-lite"],
            "step": "trust_query",
            "order": 7,
            "ref": "trust_query_ref",
            "posture": "Composite trust query",
            "default": {
                "__keystone": {
                    "canon_version": "jcs-rfc8785-v1",
                    "hash_algo": "sha256",
                    "required_fields": ["refs", "query_result", "queried_at_ms"],
                    "chain_requires": ["execution_ref"],
                    "span": ["passport_ref", "mandate_ref", "screen_ref", "decision_ref", "execution_ref"],
                },
                "require_all_refs": True,
                "allow_partial": False,
            },
        },
        {
            "package": "algovoi-revocation-ref",
            "step": "revocation",
            "order": 9,
            "ref": "revocation_ref",
            "posture": "Revocation + not_revoked assertion",
            "default": {
                "__keystone": {
                    "canon_version": "jcs-rfc8785-v1",
                    "hash_algo": "sha256",
                    "required_fields": ["target_ref", "reason", "revoked_at_ms", "revoked_by"],
                    "revocation_reasons": ["COMPROMISE", "EXPIRED", "SUPERSEDED", "POLICY"],
                },
                "fail_on_missing": True,
                "require_reason": True,
                "allowed_reasons": ["COMPROMISE", "EXPIRED", "SUPERSEDED", "POLICY"],
            },
        },
        {
            "package": "algovoi-journey-ref",
            "step": "journey",
            "order": 10,
            "ref": "journey_ref",
            "posture": "Multi-hop integrity + outcome aggregation",
            "default": {
                "__keystone": {
                    "canon_version": "jcs-rfc8785-v1",
                    "hash_algo": "sha256",
                    "required_fields": ["hops", "journey_result", "started_at_ms", "completed_at_ms"],
                    "chain_requires": ["execution_ref"],
                },
                "require_no_omitted_hop": True,
                "require_scope_never_widened": True,
                "min_hops": 1,
            },
        },
        {
            "package": "algovoi-delegation-ref",
            "packages": ["algovoi-delegation-ref"],
            "step": "delegation",
            "order": 8,
            "ref": "delegation_ref",
            "posture": "Cross-party delegation: depth + scope narrowing",
            "default": {
                "__keystone": {
                    "canon_version": "jcs-rfc8785-v1",
                    "hash_algo": "sha256",
                    "required_fields": ["parent_ref", "delegate_scope", "depth", "delegated_at_ms"],
                    "chain_requires": ["mandate_ref"],
                },
                "max_depth": 3,
                "require_scope_narrowing": True,
            },
        },
        {
            "package": "algovoi-cancellation-receipt-lite",
            "packages": ["algovoi-cancellation-receipt-lite", "algovoi-cancellation-receipt"],
            "step": "cancellation",
            "order": 11,
            "ref": "cancellation_ref",
            "posture": "Cancellation receipt (freeze-at-acceptance)",
            "default": {
                "__keystone": {
                    "canon_version": "jcs-rfc8785-v1",
                    "hash_algo": "sha256",
                    "required_fields": ["mandate_ref", "reason", "cancelled_at_ms"],
                    "chain_requires": ["mandate_ref"],
                },
                "require_reason": True,
            },
        },
        {
            "package": "algovoi-refund-receipt-lite",
            "packages": ["algovoi-refund-receipt-lite", "algovoi-refund-receipt"],
            "step": "refund",
            "order": 12,
            "ref": "refund_ref",
            "posture": "Refund receipt (bound to the original mandate)",
            "default": {
                "__keystone": {
                    "canon_version": "jcs-rfc8785-v1",
                    "hash_algo": "sha256",
                    "required_fields": ["mandate_ref", "amount_minor", "reason", "refunded_at_ms"],
                    "chain_requires": ["mandate_ref"],
                },
                "require_reason": True,
            },
        },
        {
            "package": "algovoi-retention-chain",
            "packages": ["algovoi-retention-chain"],
            "step": "retention",
            "order": 13,
            "ref": "retention_chain_ref",
            "posture": "Tamper-evident retention chain (hash-linked receipts)",
            "default": {
                "__keystone": {
                    "canon_version": "jcs-rfc8785-v1",
                    "hash_algo": "sha256",
                    "required_fields": ["chain_seq", "prev_receipt_hash", "receipt_hash"],
                },
                "require_prev_link": True,
            },
        },
    ]


def _installed_packages() -> set:
    out = set()
    for d in meta.distributions():
        name = d.metadata.get("Name")
        if isinstance(name, str) and name:
            out.add(name.lower())
    return out


def _package_version(pkg: str) -> str:
    try:
        return meta.version(pkg)
    except Exception:
        return "unknown"


def _matched_package(entry, installed) -> str:
    # Return the installed package name that satisfies this catalogue entry, else "".
    # A step may be provided by its commercial parent OR an open/lite variant.
    for name in entry.get("packages", [entry["package"]]):
        if name.lower() in installed:
            return name
    return ""


def _clean_entry(entry):
    """Validate and normalise a vendor step descriptor; return None if unusable."""
    if not isinstance(entry, dict):
        return None
    step = entry.get("step")
    ref = entry.get("ref")
    if not isinstance(step, str) or not _STEP_NAME_RE.match(step):
        return None
    if not isinstance(ref, str) or not _STEP_NAME_RE.match(ref):
        return None
    try:
        order = int(entry.get("order", 99))
    except Exception:
        return None
    order = max(0, min(999, order))
    packages = entry.get("packages")
    if packages is None:
        packages = [entry.get("package", "")] if isinstance(entry.get("package"), str) else []
    if (not isinstance(packages, list)
            or not packages
            or not all(isinstance(x, str) and _PKG_NAME_RE.match(x) for x in packages)):
        return None
    posture = entry.get("posture", "Vendor bolt-on")
    if not isinstance(posture, str):
        posture = "Vendor bolt-on"
    default = entry.get("default", {})
    if not isinstance(default, dict):
        default = {}
    return {
        "step": step, "ref": ref, "order": order, "posture": posture,
        "package": packages[0], "packages": packages,
        "default": default, "_vendor": True,
    }


def _entry_point_steps() -> list:
    steps = []
    count = 0
    for ep in meta.entry_points(group="algovoi.keystone.steps"):
        if count >= _MAX_VENDOR_STEPS:
            break
        try:
            fn = ep.load()
            entry = _clean_entry(fn())
            if entry is None:
                continue
            count += 1
            steps.append(entry)
        except Exception:
            pass
    return steps


def detect():
    installed = _installed_packages()
    found = []
    seen_steps = set()
    seen_refs = set()
    for entry in _catalogue():
        match = _matched_package(entry, installed)
        if match:
            row = dict(entry)
            row["version"] = _package_version(match)
            row["provider"] = match
            seen_steps.add(row["step"])
            seen_refs.add(row["ref"])
            found.append(row)
    for entry in _entry_point_steps():
        if entry["step"] in seen_steps or entry["ref"] in seen_refs:
            continue  # a bolt-on may not shadow a catalogue step or ref
        seen_steps.add(entry["step"])
        seen_refs.add(entry["ref"])
        row = dict(entry)
        row["version"] = _package_version(entry.get("package", "")) or "0.1.0"
        found.append(row)
    found.sort(key=lambda r: r["order"])
    return found


def all_known():
    installed = _installed_packages()
    result = []
    for entry in _catalogue():
        match = _matched_package(entry, installed)
        row = dict(entry)
        row["installed"] = bool(match)
        row["version"] = _package_version(match) if match else None
        row["provider"] = match or None
        result.append(row)
    seen_steps = {r["step"] for r in result}
    seen_refs = {r["ref"] for r in result}
    for entry in _entry_point_steps():
        if entry["step"] in seen_steps or entry["ref"] in seen_refs:
            continue  # a bolt-on may not shadow a catalogue step or ref
        seen_steps.add(entry["step"])
        seen_refs.add(entry["ref"])
        row = dict(entry)
        row["installed"] = True
        row["version"] = _package_version(entry.get("package", "")) or "0.1.0"
        result.append(row)
    result.sort(key=lambda r: r["order"])
    return result


def _integration_catalogue() -> list:
    # Keystone INTEGRATIONS: purpose-built tools that consume / export / verify keystone
    # evidence. Not decision-flow steps (they emit no step ref) but keystone-compatible by design.
    return [
        {"package": "algovoi-keystone-vc", "name": "keystone-vc", "kind": "integration",
         "role": "exporter", "posture": "Export keystone decisions as W3C Verifiable Credentials"},
        {"package": "algovoi-keystone-mcp", "name": "keystone-mcp", "kind": "integration",
         "role": "interface", "posture": "Expose keystone evidence over MCP"},
        {"package": "algovoi-keystone-langchain", "name": "keystone-langchain", "kind": "integration",
         "role": "tracer", "posture": "Emit keystone refs into LangChain/LangSmith traces"},
        {"package": "algovoi-keystone-crewai", "name": "keystone-crewai", "kind": "integration",
         "role": "tracer", "posture": "Emit keystone refs into CrewAI traces"},
        {"package": "algovoi-keystone-autogen", "name": "keystone-autogen", "kind": "integration",
         "role": "tracer", "posture": "Emit keystone refs into AutoGen traces"},
        {"package": "algovoi-keystone-adk", "name": "keystone-adk", "kind": "integration",
         "role": "tracer", "posture": "Emit keystone refs into ADK traces"},
        {"package": "algovoi-cloudevents", "name": "cloudevents", "kind": "integration",
         "role": "exporter", "posture": "Wrap keystone refs as CloudEvents"},
        {"package": "algovoi-tap-verifier", "name": "tap-verifier", "kind": "integration",
         "role": "verifier", "posture": "Verify keystone TAP evidence offline"},
        {"package": "algovoi-webhook-verifier", "name": "webhook-verifier", "kind": "integration",
         "role": "verifier", "posture": "Verify keystone webhook signatures offline"},
        {"package": "algovoi-keystone-odbc", "name": "keystone-odbc", "kind": "integration",
         "role": "connector", "posture": "Bind ODBC / DB-API operations to keystone execution_ref"},
        {"package": "algovoi-keystone-sqlalchemy", "name": "keystone-sqlalchemy", "kind": "integration",
         "role": "connector", "posture": "Bind SQLAlchemy ORM operations to keystone execution_ref"},
        {"package": "algovoi-keystone-kafka", "name": "keystone-kafka", "kind": "integration",
         "role": "connector", "posture": "Bind Kafka message production to keystone execution_ref"},
        {"package": "algovoi-keystone-openlineage", "name": "keystone-openlineage", "kind": "integration",
         "role": "connector", "posture": "Bind OpenLineage runs to keystone execution_ref (run facet)"},
        {"package": "algovoi-keystone-asgi", "name": "keystone-asgi", "kind": "integration",
         "role": "connector", "posture": "Bind HTTP requests (ASGI / WSGI) to keystone execution_ref"},
        {"package": "algovoi-keystone-grpc", "name": "keystone-grpc", "kind": "integration",
         "role": "connector", "posture": "Bind gRPC unary calls to keystone execution_ref (server interceptor)"},
        {"package": "algovoi-keystone-s3", "name": "keystone-s3", "kind": "integration",
         "role": "connector", "posture": "Bind S3 object writes (put / delete) to keystone execution_ref"},
        {"package": "algovoi-keystone-redis", "name": "keystone-redis", "kind": "integration",
         "role": "connector", "posture": "Bind Redis write commands to keystone execution_ref"},
        {"package": "algovoi-keystone-mongo", "name": "keystone-mongo", "kind": "integration",
         "role": "connector", "posture": "Bind MongoDB writes to keystone execution_ref"},
        {"package": "algovoi-keystone-amqp", "name": "keystone-amqp", "kind": "integration",
         "role": "connector", "posture": "Bind AMQP / RabbitMQ publishes to keystone execution_ref"},
        {"package": "algovoi-keystone-elasticsearch", "name": "keystone-elasticsearch", "kind": "integration",
         "role": "connector", "posture": "Bind Elasticsearch writes to keystone execution_ref"},
        {"package": "algovoi-keystone-nats", "name": "keystone-nats", "kind": "integration",
         "role": "connector", "posture": "Bind NATS publishes to keystone execution_ref"},
        {"package": "algovoi-keystone-gcs", "name": "keystone-gcs", "kind": "integration",
         "role": "connector", "posture": "Bind Google Cloud Storage object writes to keystone execution_ref"},
        {"package": "algovoi-keystone-validate", "name": "keystone-validate", "kind": "integration",
         "role": "verifier", "posture": "Validate keystone execution evidence (recompute + tamper) + structured error logging"},
    ]


def integrations():
    """Installed keystone integrations (consumers / exporters / verifiers)."""
    installed = _installed_packages()
    out = []
    for entry in _integration_catalogue():
        match = _matched_package(entry, installed)
        if match:
            row = dict(entry)
            row["installed"] = True
            row["version"] = _package_version(match)
            row["provider"] = match
            out.append(row)
    return out


def all_integrations():
    """Every known keystone integration, installed or not, with its provider."""
    installed = _installed_packages()
    out = []
    for entry in _integration_catalogue():
        match = _matched_package(entry, installed)
        row = dict(entry)
        row["installed"] = bool(match)
        row["version"] = _package_version(match) if match else None
        row["provider"] = match or None
        out.append(row)
    return out
