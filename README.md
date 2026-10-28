# algovoi-keystone

The **Keystone** is the L2 bolt-on layer on top of the L1 [AlgoVoi
substrate](https://github.com/chopmob-cloud/algovoi-substrate) (RFC 8785 JCS canonicalisation +
SHA-256). Where L1 gives you one primitive, `ref = "sha256:" + SHA-256(RFC 8785 JCS(payload))`, L2
gives you the toolchain to build, govern, run and verify agent actions against it, with no AlgoVoi
software in your trust base.

This repository is the open (Apache-2.0) Keystone SDK. It holds the framework itself — four
pure-Python packages plus the `keystone` command line — and every stage of the chain as an
installable package. All 19 are pure Python: `py3-none-any` wheels and sdists, no compiled
extensions, no Cython.

## Packages

### Framework

| Package | What it is |
|---|---|
| [`algovoi-keystone-connect`](packages/algovoi-keystone-connect) | build a data-plane connector from a declarative spec, and test any bolt-on at any stage of the chain offline |
| [`algovoi-keystone-agent`](packages/algovoi-keystone-agent) | the agentic behaviour layer: rules, triggers and behaviours that gate any write before it commits, each firing a content-addressed `behaviour_ref` |
| [`algovoi-keystone-runtime`](packages/algovoi-keystone-runtime) | run a chain and keep the evidence in a queryable, tamper-evident journal that recomputes offline |
| [`algovoi-keystone`](packages/algovoi-keystone) | the umbrella: one install for the whole toolchain plus the `keystone` CLI |

### The chain

Fourteen stages, in execution order. Each package declares itself through an
`algovoi.keystone.steps` entry point, so the control panel and `keystone` discover it without a
hardcoded catalogue.

| # | Step | Package | Ref it emits | What it establishes |
|---|---|---|---|---|
| 0 | `guard` | [`algovoi-substrate-guard`](packages/algovoi-substrate-guard) | `guard_ref` | input bounds and DoS hardening, before anything is canonicalised |
| 1 | `passport` | [`algovoi-agent-passport-lite`](packages/algovoi-agent-passport-lite) | `passport_ref` | who is acting, and at what assurance level |
| 2 | `mandate` | [`algovoi-payment-mandate-lite`](packages/algovoi-payment-mandate-lite) | `mandate_ref` | what that agent has authority to spend or do |
| 3 | `policy_bound` | [`algovoi-policy-binding`](packages/algovoi-policy-binding) | `policy_bound_ref` | exactly which policy snapshot governs the decision |
| 4 | `screen` | [`algovoi-compliance-gate-lite`](packages/algovoi-compliance-gate-lite) | `screen_ref` | whether compliance and sanctions screening permits the counterparty |
| 5 | `decision` | [`algovoi-spend-guardrail-lite`](packages/algovoi-spend-guardrail-lite) | `guardrail_ref` | the pre-payment ALLOW / DENY verdict |
| 6 | `execution` | [`algovoi-execution-ref`](packages/algovoi-execution-ref) | `execution_ref` | what actually happened, bound to the decision that permitted it |
| 7 | `trust_query` | [`algovoi-composite-trust-query-lite`](packages/algovoi-composite-trust-query-lite) | `trust_query_ref` | a composite trust verdict a third party can recompute |
| 8 | `delegation` | [`algovoi-delegation-ref`](packages/algovoi-delegation-ref) | `delegation_ref` | authority passed on legitimately, with depth and scope narrowing |
| 9 | `revocation` | [`algovoi-revocation-ref`](packages/algovoi-revocation-ref) | `revocation_ref` | whether any of it has since been withdrawn |
| 10 | `journey` | [`algovoi-journey-ref`](packages/algovoi-journey-ref) | `journey_ref` | the outcome across a whole multi-agent journey |
| 11 | `cancellation` | [`algovoi-cancellation-receipt-lite`](packages/algovoi-cancellation-receipt-lite) | `cancellation_ref` | a cancellation receipt, frozen at acceptance |
| 12 | `refund` | [`algovoi-refund-receipt-lite`](packages/algovoi-refund-receipt-lite) | `refund_ref` | a refund receipt, tied back to the original mandate and execution |
| 13 | `retention` | [`algovoi-retention-chain`](packages/algovoi-retention-chain) | `retention_chain_ref` | a hash-linked retention chain over the receipts |

Stages 0–5 authorise, stage 6 is the commit, and 7–13 account for what happened. The lifecycle
stages (9–13) only fire when something actually occurs: a clean execution touches 0–7, 10 and 13.

Plus one package that is not a stage:

| Package | What it is |
|---|---|
| [`algovoi-recompute-drift`](packages/algovoi-recompute-drift) | offline drift detection — recompute a recorded `action_ref` and assert it still matches (`recompute_action_ref`, `drift_detected`, `assert_no_drift`) |

## One install, one command

```
pip install algovoi-keystone

keystone new redis-stream --kind connector   # scaffold a bolt-on, green out of the box
keystone test                                 # recompute, decision-bound, tamper-evident
keystone validate records.json                # verify any emitted ref offline
keystone journal run.db                        # verify a run's evidence journal
```

The chain packages install the same way. They are published to the AlgoVoi open package index,
which also serves `#sha256=` fragments so you can pin:

```
pip install --index-url https://pip.algovoi.co.uk/simple/ \
            algovoi-substrate-guard algovoi-agent-passport-lite algovoi-payment-mandate-lite \
            algovoi-policy-binding algovoi-compliance-gate-lite algovoi-spend-guardrail-lite \
            algovoi-execution-ref algovoi-composite-trust-query-lite algovoi-delegation-ref \
            algovoi-revocation-ref algovoi-journey-ref algovoi-cancellation-receipt-lite \
            algovoi-refund-receipt-lite algovoi-retention-chain
```

## One import surface

```python
from algovoi_keystone import connector, rule, trigger, behaviour, Engine, Runtime, Journal, keystone_ref, behaviours

keystone_s3 = connector("s3", writes={"put_object": ("put", lambda c: c.kwargs["Bucket"])})
rt = Runtime(Journal("keystone.db"), decision_ref=decision_ref)
s3 = rt.bind(keystone_s3(client, decision_ref=decision_ref), behaviours=[behaviours.deny_writes_to("s3", "delete")])
```

A behaviour only fires at the stage it declares. Pair `Engine.guard` with a stage-appropriate
behaviour — a spend cap triggers at the `decision` stage, not inside a write guard — and check
coverage with `check_guard_coverage` rather than assuming a bound behaviour is an active one.

## The one guarantee

Every reference this SDK emits, `execution_ref`, `behaviour_ref`, a stage ref, or the journal head,
recomputes from its own fields with a stock RFC 8785 implementation and standard SHA-256. There is
nothing to trust and nothing to run: any third party verifies the evidence offline.

Build it and prove it yourself:

```
git clone https://github.com/chopmob-cloud/algovoi-keystone && cd algovoi-keystone
pip install -e packages/algovoi-keystone-runtime -e packages/algovoi-keystone
pytest packages
```

Every stage is exercised end to end — including tamper-evidence negatives, where a modified field,
a broken journal chain and a truncated journal must all fail verification.

Documentation: https://docs.algovoi.co.uk/keystone-sdk

## Licence

Apache-2.0. See [LICENSE](LICENSE) and each package's `NOTICE`.
