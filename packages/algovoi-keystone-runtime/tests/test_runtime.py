"""Runtime + journal: assemble a chain, run it, persist and verify the evidence."""
import json

import pytest

import algovoi_keystone_connect as connect
from algovoi_keystone_agent import Denied
from algovoi_keystone_agent.library import cap_charges, deny_writes_to
from algovoi_keystone_runtime import GENESIS, Journal, Runtime, verify_record

from algovoi_keystone_connect import keystone_ref


class FakeS3:
    def __init__(self):
        self.puts = []

    def put_object(self, **kw):
        self.puts.append(kw)
        return {"ETag": "e"}

    def get_object(self, **kw):
        return {"Body": b"{}"}   # a read: must not journal anything


def _s3_connector():
    return connect.connector("s3", writes={
        "put_object": ("put", lambda c: c.kwargs["Bucket"] + "/" + c.kwargs["Key"]),
    })


def _runtime(journal=None):
    dref = keystone_ref({"grant": "agent-7"})
    j = journal or Journal(":memory:", clock_ms=lambda: 1717000000000)
    return Runtime(j, decision_ref=dref, clock_ms=lambda: 1717000000001), dref


def test_record_stage_journals_and_verifies():
    rt, dref = _runtime()
    pref = rt.record_stage("passport", {"agent": "agent-7", "issuer": "acme"})
    mref = rt.record_stage("mandate", {"passport_ref": pref, "cap": "500USD"})
    assert pref.startswith("sha256:") and mref.startswith("sha256:")
    assert rt.journal.count() == 2
    assert rt.journal.verify().ok, rt.journal.verify()


def test_bind_journals_behaviour_and_execution():
    rt, dref = _runtime()
    inner = FakeS3()
    client = _s3_connector()(inner, decision_ref=dref)
    s3 = rt.bind(client, behaviours=[cap_charges(500), deny_writes_to("Bucket", ["locked"], method="put_object")])

    s3.put_object(Bucket="receipts", Key="r1", Body=b"{}")   # allowed
    assert len(inner.puts) == 1

    kinds = [r for r in rt.journal.by_kind("execution")]
    behs = [r for r in rt.journal.by_kind("behaviour")]
    assert len(kinds) == 1                          # one execution journaled
    assert len(behs) == 1                           # deny_writes_to fired ALLOW (cap has no execution-stage trigger)
    assert rt.journal.verify().ok


def test_blocked_write_journals_block_not_execution():
    rt, dref = _runtime()
    inner = FakeS3()
    client = _s3_connector()(inner, decision_ref=dref)
    s3 = rt.bind(client, behaviours=[deny_writes_to("Bucket", ["locked"], method="put_object")])

    with pytest.raises(Denied):
        s3.put_object(Bucket="locked", Key="r2", Body=b"{}")

    assert inner.puts == []                                   # write never happened
    assert rt.journal.by_kind("execution") == []             # no execution journaled
    blocks = [r for r in rt.journal.by_kind("behaviour") if r["verdict"] == "BLOCK"]
    assert len(blocks) == 1 and blocks[0]["behaviour"] == "deny_writes_Bucket"
    assert rt.journal.verify().ok


def test_read_does_not_journal():
    rt, dref = _runtime()
    inner = FakeS3()
    client = _s3_connector()(inner, decision_ref=dref)
    s3 = rt.bind(client, behaviours=[deny_writes_to("Bucket", ["locked"], method="put_object")])
    s3.put_object(Bucket="receipts", Key="r1", Body=b"{}")
    n = rt.journal.count()
    s3.get_object(Bucket="receipts", Key="r1")               # a read
    assert rt.journal.count() == n                           # nothing added


def test_full_chain_and_query():
    rt, dref = _runtime()
    pref = rt.record_stage("passport", {"agent": "agent-7"})
    rt.record_stage("mandate", {"passport_ref": pref, "cap": "500USD"})
    inner = FakeS3()
    client = _s3_connector()(inner, decision_ref=dref)
    s3 = rt.bind(client, behaviours=[deny_writes_to("Bucket", ["locked"], method="put_object")])
    s3.put_object(Bucket="receipts", Key="r1", Body=b"{}")

    chain = rt.journal.chain(dref)
    stages = [r.get("stage") for r in chain]
    assert "passport" in stages and "mandate" in stages and "execution" in stages
    assert rt.journal.verify().ok


def test_tamper_a_record_breaks_verify():
    rt, dref = _runtime()
    rt.record_stage("passport", {"agent": "agent-7"})
    # tamper the stored record_json directly
    rt.journal._conn.execute(
        "UPDATE entries SET record_json = ? WHERE seq = 1",
        (json.dumps({"agent": "attacker", "stage": "passport",
                     "stage_ref": "sha256:" + "0" * 64}),))
    rt.journal._conn.commit()
    assert not rt.journal.verify().ok


def test_delete_a_row_breaks_chain():
    rt, dref = _runtime()
    rt.record_stage("passport", {"agent": "a"})
    rt.record_stage("mandate", {"cap": "1"})
    rt.record_stage("delegation", {"to": "b"})
    rt.journal._conn.execute("DELETE FROM entries WHERE seq = 2")  # remove the middle
    rt.journal._conn.commit()
    assert not rt.journal.verify().ok                              # chain no longer links


def test_file_backed_persistence(tmp_path):
    db = str(tmp_path / "keystone.db")
    dref = keystone_ref({"grant": "agent-7"})
    j = Journal(db, clock_ms=lambda: 1)
    rt = Runtime(j, decision_ref=dref, clock_ms=lambda: 2)
    rt.record_stage("passport", {"agent": "agent-7"})
    head = j.head()
    j.close()

    j2 = Journal(db)                       # reopen the same file
    assert j2.count() == 1
    assert j2.head() == head
    assert j2.verify().ok
    j2.close()


def test_genesis_head_when_empty():
    j = Journal(":memory:")
    assert j.head() == GENESIS
    assert j.count() == 0
