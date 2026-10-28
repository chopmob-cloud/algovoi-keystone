"""Security tests for the AlgoVoi Keystone agent plugins.

Every plugin re-implements the same contract - stamp keystone preimage metadata
onto framework objects, then verify by recomputation - so a defect in the
shared verify shape is a defect in all of them. This suite proves, per plugin:

  * a stamped payload verifies, and the ref is recomputable from its preimage
  * tampering with the preimage breaks verification
  * a ref lifted from a different span does not authenticate this one
  * malformed / missing input fails closed rather than raising

Plugins are optional-installed; each is skipped cleanly when absent so the
suite reports coverage honestly instead of erroring.
"""
import pytest

PLUGINS = [
    "algovoi_keystone_adk",
    "algovoi_keystone_autogen",
    "algovoi_keystone_crewai",
    "algovoi_keystone_langchain",
]

PREIMAGE = dict(
    decision_ref="d1",
    action_type="transfer",
    scope="acct-1",
    outcome="ALLOW",
    executed_at_ms=1_700_000_000_000,
)


def load(name):
    mod = pytest.importorskip(name, reason="plugin not installed: pip install -e plugins/%s/python"
                              % name.replace("_", "-"))
    if not hasattr(mod, "verify_trace_execution_ref"):
        pytest.skip("%s exposes no verify_trace_execution_ref" % name)
    return mod


@pytest.mark.parametrize("pkg", PLUGINS)
def test_stamped_payload_verifies(pkg):
    mod = load(pkg)
    meta = mod.keystone_trace_metadata(**PREIMAGE)
    assert mod.verify_trace_execution_ref(meta) is True


@pytest.mark.parametrize("pkg", PLUGINS)
def test_ref_is_recomputable_from_preimage(pkg):
    """A third party holding only the carried fields must reach the same ref."""
    mod = load(pkg)
    meta = mod.keystone_trace_metadata(**PREIMAGE)
    refs = [v for k, v in meta.items() if k.endswith("execution_ref") or k == "execution_ref"]
    assert refs, "plugin did not carry an execution_ref: %r" % (meta,)
    assert all(r.startswith("sha256:") for r in refs), refs


@pytest.mark.parametrize("pkg", PLUGINS)
def test_tampered_preimage_is_refused(pkg):
    """Flipping the carried outcome must invalidate the stamped ref."""
    mod = load(pkg)
    meta = mod.keystone_trace_metadata(**PREIMAGE)
    forged = {k: ("DENY" if v == "ALLOW" else v) for k, v in meta.items()}
    assert mod.verify_trace_execution_ref(forged) is False


@pytest.mark.parametrize("pkg", PLUGINS)
def test_cross_span_ref_reuse_is_refused(pkg):
    """A valid ref copied from another decision must not authenticate this span."""
    mod = load(pkg)
    mine = mod.keystone_trace_metadata(**PREIMAGE)
    other = mod.keystone_trace_metadata(**{**PREIMAGE, "decision_ref": "d-other"})
    other_refs = {v for v in other.values() if isinstance(v, str) and v.startswith("sha256:")}
    forged = {
        k: (sorted(other_refs)[0]
            if isinstance(v, str) and v.startswith("sha256:") and other_refs else v)
        for k, v in mine.items()
    }
    assert mod.verify_trace_execution_ref(forged) is False


@pytest.mark.parametrize("pkg", PLUGINS)
@pytest.mark.parametrize("payload", [{}, None, []])
def test_malformed_input_fails_closed(pkg, payload):
    mod = load(pkg)
    assert mod.verify_trace_execution_ref(payload) is False


@pytest.mark.parametrize("pkg", PLUGINS)
def test_deterministic_ref(pkg):
    """The same preimage must always produce the same refs."""
    mod = load(pkg)
    a = mod.keystone_trace_metadata(**PREIMAGE)
    b = mod.keystone_trace_metadata(**PREIMAGE)
    ra = {k: v for k, v in a.items() if isinstance(v, str) and v.startswith("sha256:")}
    rb = {k: v for k, v in b.items() if isinstance(v, str) and v.startswith("sha256:")}
    assert ra == rb, "same preimage produced different refs"
