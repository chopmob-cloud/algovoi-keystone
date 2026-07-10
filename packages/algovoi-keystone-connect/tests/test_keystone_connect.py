"""Tests for algovoi-keystone-connect (the build + test toolkit)."""
import hashlib
import pytest
import rfc8785
from algovoi_execution_ref import execution_ref
from algovoi_keystone_connect import (
    EXECUTION_OUTCOMES, Call, check_connector, check_ref_builder, connector, keystone_ref, synth_ref,
)

DR = "sha256:" + "a" * 64
TS = 1716460800000


# --- a whole S3 connector, declared in ~4 lines via the toolkit ---
keystone_s3 = connector("s3", writes={
    "put_object":    ("put",    lambda call: "%s/%s" % (call.kwargs["Bucket"], call.kwargs["Key"])),
    "delete_object": ("delete", lambda call: "%s/%s" % (call.kwargs["Bucket"], call.kwargs["Key"])),
})


class FakeS3:
    def put_object(self, **k):
        if k.get("Key") == "boom":
            raise RuntimeError("denied")
        return {"ETag": "x"}

    def delete_object(self, **k):
        return {}

    def get_object(self, **k):
        return {"Body": b"data"}   # read -> passthrough


def test_keystone_ref_is_content_addressed():
    obj = {"b": 2, "a": 1}
    assert keystone_ref(obj) == "sha256:" + hashlib.sha256(rfc8785.dumps(obj)).hexdigest()
    assert keystone_ref(obj) == keystone_ref({"a": 1, "b": 2})   # key order irrelevant (JCS)


def test_connector_reproduces_handwritten_s3_bytes():
    """The declarative connector emits the EXACT execution_ref the hand-written algovoi-keystone-s3
    emits -- so 'the easy way' and 'the 130-line way' are provably equivalent."""
    c = keystone_s3(FakeS3(), decision_ref=DR, clock_ms=lambda: TS)
    c.put_object(Bucket="receipts", Key="2026/r1.json", Body=b"{}")
    assert c.execution_ref == execution_ref(DR, "s3:put", "receipts/2026/r1.json", "COMMITTED", TS)
    assert c.executions[0]["action_type"] == "s3:put"
    assert c.executions[0]["scope"] == "receipts/2026/r1.json"


def test_delete_and_failed_and_passthrough():
    c = keystone_s3(FakeS3(), decision_ref=DR, clock_ms=lambda: TS)
    c.delete_object(Bucket="receipts", Key="r1")
    assert c.execution_ref == execution_ref(DR, "s3:delete", "receipts/r1", "COMMITTED", TS)
    with pytest.raises(RuntimeError):
        c.put_object(Bucket="receipts", Key="boom")
    assert c.executions[-1]["outcome"] == "FAILED"
    assert c.get_object(Bucket="receipts", Key="r1") == {"Body": b"data"}   # read unbound
    assert len(c.executions) == 2


def test_factory_tamper_detected():
    ref = execution_ref(DR, "s3:put", "receipts/r1", "COMMITTED", TS)
    assert not keystone_s3.tamper_detected(ref, decision_ref=DR, action="put", scope="receipts/r1", outcome="COMMITTED", executed_at_ms=TS)
    assert keystone_s3.tamper_detected(ref, decision_ref=DR, action="put", scope="receipts/OTHER", outcome="COMMITTED", executed_at_ms=TS)


def test_rejects_bad_spec_and_decision():
    with pytest.raises(ValueError):
        connector("", writes={"x": ("x", lambda c: "s")})
    with pytest.raises(ValueError):
        connector("s3", writes={})
    with pytest.raises(ValueError):
        keystone_s3(FakeS3(), decision_ref="")


def test_scope_fn_can_read_client_for_fixed_context():
    # azure-blob-style: container from a client attribute, blob from the call
    keystone_blob = connector("azureblob", writes={
        "upload_blob": ("upload", lambda call: "%s/%s" % (call.client.container_name, call.kwargs["name"])),
    })
    class Cont:
        container_name = "receipts"
        def upload_blob(self, **k): return {}
    c = keystone_blob(Cont(), decision_ref=DR, clock_ms=lambda: TS)
    c.upload_blob(name="2026/r1.json", data=b"{}")
    assert c.execution_ref == execution_ref(DR, "azureblob:upload", "receipts/2026/r1.json", "COMMITTED", TS)


def test_synth_ref_deterministic_content_addressed():
    a = synth_ref("decision")
    assert a.startswith("sha256:") and len(a) == 71
    assert a == synth_ref("decision")
    assert a != synth_ref("mandate")
    assert a != synth_ref("decision", alt=True)


def test_check_connector_passes_on_valid_bolt_on():
    rep = check_connector(keystone_s3, FakeS3(), [
        ("put_object", {"Bucket": "receipts", "Key": "2026/r1.json"}),
        ("delete_object", {"Bucket": "receipts", "Key": "r1"}),
    ])
    assert rep.ok, repr(rep)
    names = [n for n, _, _ in rep.checks]
    assert "recompute (fields -> execution_ref)" in names
    assert "decision-bound (swap decision -> refs change)" in names
    assert "tamper-evident (mutate scope -> mismatch)" in names


def test_check_connector_catches_broken_bolt_on():
    """A 'connector' that ignores decision_ref and hard-codes a ref must FAIL the battery."""
    class BadBound:
        def __init__(self, *a, **k):
            self.executions = []
            self.execution_ref = None
        def write(self, **k):
            rec = {"decision_ref": "ignored", "scope": "s", "action_type": "bad:write",
                   "outcome": "COMMITTED", "executed_at_ms": 1, "execution_ref": "sha256:" + "0" * 64}
            self.executions.append(rec); self.execution_ref = rec["execution_ref"]
    def bad_factory(client, *, decision_ref, clock_ms=None, on_execution=None):
        return BadBound()
    rep = check_connector(bad_factory, object(), [("write", {})])
    assert not rep.ok   # recompute + decision-bound both fail


def test_check_ref_builder_any_stage():
    # a step bolt-on: builds a mandate_ref that chains to its passport_ref predecessor
    def mandate_ref(payload):
        return keystone_ref(payload)
    passport = synth_ref("passport")
    payload = {"passport_ref": passport, "limit": "100USD", "scope": "payments"}
    rep = check_ref_builder(mandate_ref, payload, prev_field="passport_ref")
    assert rep.ok, repr(rep)
    names = [n for n, _, _ in rep.checks]
    assert any("content-addressed" in n for n in names)
    assert any("predecessor-bound" in n for n in names)


def test_check_ref_builder_flags_non_content_addressed():
    import time as _t
    def bad_builder(payload):
        return "sha256:" + "f" * 64   # constant, not content-addressed
    rep = check_ref_builder(bad_builder, {"a": 1})
    assert not rep.ok


def test_outcomes_constant():
    assert EXECUTION_OUTCOMES == ("COMMITTED", "SKIPPED", "FAILED", "REVERSED")
