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

Install from the Keystone control panel (the integrity path, from the AlgoVoi index); new releases
land on the AlgoVoi index first, with PyPI mirrors following. Built on the AlgoVoi substrate
(RFC 8785 JCS + SHA-256).
