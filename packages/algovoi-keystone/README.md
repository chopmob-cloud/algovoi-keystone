# algovoi-keystone

The Keystone SDK, in one install. `pip install algovoi-keystone` brings the whole bolt-on toolchain:
the connector builder ([keystone-connect](https://pypi.org/project/algovoi-keystone-connect/)), the
agentic behaviour layer ([keystone-agent](https://pypi.org/project/algovoi-keystone-agent/)) with its
ready-made behaviours, and the `keystone` command line. Everything still reduces to one primitive,
`ref = "sha256:" + SHA-256(RFC 8785 JCS(payload))`, with no AlgoVoi software in your trust base.
Apache-2.0.

## One import surface

```python
from algovoi_keystone import connector, rule, trigger, behaviour, Engine, keystone_ref, behaviours

keystone_s3 = connector("s3", writes={"put_object": ("put", lambda c: c.kwargs["Bucket"])})
engine = Engine([behaviours.cap_charges(500)], decision_ref=decision_ref)
```

## The `keystone` command line

```
keystone new <name> --kind connector|behaviour|stage   scaffold a publishable bolt-on
keystone test [path]                                    run the bolt-on's test battery
keystone validate <records.json>                        verify emitted refs offline
keystone verify <chain.json> [--expect NAME=REF]        prove a whole chain composes
keystone doctor                                         check the environment
keystone info                                           show installed pieces + the primitive
keystone publish [path]                                 build the dist and check it (mirror-first)
```

`keystone new` writes a complete package already wired to the conformance battery, so a bolt-on
goes from nothing to tested in one step:

```
keystone new redis-stream --kind connector
cd redis-stream/python && keystone test        # green: recompute, decision-bound, tamper-evident
```

`keystone validate` verifies any emitted record offline, whether it is an `execution_ref` from a
connector or a `behaviour_ref` from the agent layer: it recomputes the reference from the recorded
fields and reports any that do not match, so a third party checks your evidence with a stock RFC 8785
implementation and standard SHA-256.

## Chain verification

`keystone validate` checks records one at a time; `keystone verify` proves the composition — every
link recomputes in order, every `@name` reference resolves to an earlier link, and the assertions the
chain declares actually hold:

```
keystone verify chain.json
keystone verify chain.json --expect standing_authority=sha256:...   # pin a ref you trust
```

Six assertion kinds: `scope_subset`, `field_equals`, `time_within`, `not_revoked`, `journey`, and
`recurring_cap` (Recurr Tier-2 recurring standing authorities: per-cycle cap, period cap, policy
bound, authority window). Exit codes: `0` composes, `1` a well-formed chain that does not prove what
it claims, `2` bad input or invocation.

```python
from algovoi_keystone import verify_chain

result = verify_chain(chain)                                    # recompute + assertions
result = verify_chain(chain, expect={"standing_authority": ref})  # ... and pin what you trust
result.ok, result.failed_assertion, result.capped
```

Pinning matters because a recompute only proves internal consistency: a chain whose cap was widened
still recomputes. Pin the link to the reference you hold out of band (the recurr `authority_ref` the
customer signed, the passport ref you recorded) and a widened authority fails at `ref_pinned`.

Canonicalisation comes from the independent `rfc8785` library, so verification needs no AlgoVoi
software. When `algovoi-substrate` is installed as well, its canonicaliser is cross-checked
byte-for-byte against `rfc8785` and a divergence fails closed.

Install from the Keystone control panel (the integrity path, from the AlgoVoi index); new releases
land on the AlgoVoi index first, with PyPI mirrors following. Built on the AlgoVoi substrate
(RFC 8785 JCS + SHA-256).
