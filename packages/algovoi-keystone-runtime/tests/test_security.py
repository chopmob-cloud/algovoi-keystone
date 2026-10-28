"""Security regressions: untrusted records, durable state and decision binding."""
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from algovoi_keystone_connect import connector, keystone_ref
from algovoi_keystone_runtime import GENESIS, Journal, Runtime, verify_record


class FakeS3:
    def __init__(self):
        self.puts = []

    def put_object(self, **kwargs):
        self.puts.append(kwargs)
        return {"ETag": "e"}


class ExplodingS3:
    def put_object(self, **kwargs):
        raise RuntimeError("data plane rejected the write")


class MultiRecorder:
    """A client that emits two execution records for one call."""

    def __init__(self, decision_ref):
        from algovoi_execution_ref import execution_ref
        self.executions = []
        self._records = [
            {"decision_ref": decision_ref, "action_type": "s3:put", "scope": scope,
             "outcome": "COMMITTED", "executed_at_ms": 1717000000003,
             "execution_ref": execution_ref(decision_ref, "s3:put", scope, "COMMITTED",
                                            1717000000003)}
            for scope in ("receipts/r1", "receipts/r1.part")]

    def put_object(self, **kwargs):
        self.executions.extend(self._records)
        return {"ETag": "e"}


def _s3_connector():
    return connector("s3", writes={
        "put_object": ("put", lambda c: c.kwargs["Bucket"] + "/" + c.kwargs["Key"]),
    })


def _runtime(journal=None):
    decision = keystone_ref({"grant": "agent-7"})
    journal = journal or Journal(":memory:", clock_ms=lambda: 1717000000000)
    return Runtime(journal, decision_ref=decision, clock_ms=lambda: 1717000000001), decision


def stage_record(**fields):
    body = {"stage": "mandate", "decision_ref": keystone_ref({"grant": 1}), **fields}
    return {**body, "stage_ref": keystone_ref(body)}


@pytest.mark.parametrize("other", ["execution_ref", "behaviour_ref"])
def test_verify_rejects_ambiguous_self_references(other):
    rec = stage_record(**{other: "sha256:" + "a" * 64})
    assert not verify_record(rec)


@pytest.mark.parametrize("record", [None, {}, {"stage_ref": "invalid"}, stage_record(value="before") | {"value": "after"}])
def test_append_rejects_invalid_records_without_mutation(record):
    with Journal() as journal:
        with pytest.raises(ValueError):
            journal.append(record)
        assert journal.count() == 0
        assert journal.head() == GENESIS


@pytest.mark.parametrize("column,value", [
    ("record_json", json.dumps(stage_record(value="replacement"))),
    ("decision_ref", "different decision"), ("stage", "execution"), ("kind", "execution"),
])
def test_verify_binds_stored_record_and_query_indexes(column, value):
    with Journal() as journal:
        journal.append(stage_record(value="original"))
        journal._conn.execute(f"UPDATE entries SET {column} = ?", (value,))
        journal._conn.commit()
        assert not journal.verify().ok


@pytest.mark.parametrize("raw", ["{", "null", "[]", '{"stage_ref": NaN}'])
def test_verify_malformed_persisted_json_returns_failed_report(raw):
    with Journal() as journal:
        journal.append(stage_record())
        journal._conn.execute("UPDATE entries SET record_json = ?", (raw,))
        journal._conn.commit()
        assert not journal.verify().ok


def test_verify_missing_table_returns_failed_report():
    with Journal() as journal:
        journal._conn.execute("DROP TABLE entries")
        assert not journal.verify().ok


def test_verify_expected_head_detects_suffix_truncation():
    with Journal() as journal:
        journal.append(stage_record(n=1))
        expected = journal.append(stage_record(n=2))
        assert journal.verify(expected_head=expected).ok
        journal._conn.execute("DELETE FROM entries WHERE seq = 2")
        journal._conn.commit()
        assert journal.verify().ok  # unpinned verification cannot detect a valid prefix
        assert not journal.verify(expected_head=expected).ok


def test_verify_accepts_published_expect_head_and_expect_count_names():
    with Journal() as journal:
        journal.append(stage_record(n=1))
        head = journal.append(stage_record(n=2))
        assert journal.verify(expect_head=head, expect_count=2).ok
        with pytest.raises(ValueError):
            journal.verify(expected_head=head, expect_head="sha256:" + "0" * 64)


def test_verify_expected_count_detects_truncation_and_rejects_bad_values():
    with Journal() as journal:
        journal.append(stage_record(n=1))
        journal.append(stage_record(n=2))
        assert journal.verify(expected_count=2).ok
        journal._conn.execute("DELETE FROM entries WHERE seq = 2")
        journal._conn.commit()
        assert not journal.verify(expected_count=2).ok
        for bad in (-1, True, "2", 2.0):
            with pytest.raises(ValueError, match="count"):
                journal.verify(expected_count=bad)


@pytest.mark.parametrize("expected", ["", "sha256:abc", "sha256:" + "A" * 64, 123, False])
def test_verify_rejects_malformed_expected_head(expected):
    with Journal() as journal:
        journal.append(stage_record())
        with pytest.raises(ValueError, match="expected_head"):
            journal.verify(expected_head=expected)


def test_read_only_journal_never_creates_or_changes_database(tmp_path):
    missing = tmp_path / "missing.db"
    with pytest.raises(sqlite3.OperationalError):
        Journal(missing, read_only=True)
    assert not missing.exists()
    path = tmp_path / "journal # unicode-é.db"
    with Journal(path) as journal:
        expected = journal.append(stage_record())
    original = path.read_bytes()
    with Journal(path, read_only=True) as journal:
        assert journal.verify(expected_head=expected).ok
        with pytest.raises(ValueError, match="read_only"):
            journal.append(stage_record(other=2))
        with pytest.raises(sqlite3.OperationalError):
            journal._conn.execute("DELETE FROM entries")
    assert path.read_bytes() == original


def test_read_only_does_not_create_schema(tmp_path):
    path = tmp_path / "empty.db"
    sqlite3.connect(path).close()
    with Journal(path, read_only=True) as journal:
        assert not journal.verify().ok
        assert journal._conn.execute("SELECT name FROM sqlite_master").fetchall() == []


def _keystone_record(**overrides):
    from algovoi_execution_ref import bind_keystone
    record = bind_keystone(
        passport_ref=keystone_ref({"passport": 1}),
        mandate_ref=keystone_ref({"mandate": 1}),
        policy_bound_ref=keystone_ref({"policy": 1}), verdict="ALLOW",
        action_type="s3:put", scope="receipts/r1", outcome="COMMITTED",
        executed_at_ms=1717000000002, trust_outcome="TRUSTED")
    record.update(overrides)
    return record


def test_verify_record_accepts_execution_keystone_wrapper():
    assert verify_record(_keystone_record())


@pytest.mark.parametrize("field,value", [
    ("trust_query_ref", "sha256:" + "0" * 64), ("chain", []),
    ("decision_ref", "sha256:" + "1" * 64), ("trust_outcome", "UNTRUSTED"),
])
def test_verify_record_rejects_tampered_execution_keystone(field, value):
    assert not verify_record(_keystone_record(**{field: value}))


def test_verify_record_rejects_incomplete_execution_keystone():
    record = _keystone_record()
    del record["trust_query_ref"]
    assert not verify_record(record)


def test_journal_verifies_wrapper_and_detects_its_tampering():
    with Journal() as journal:
        expected = journal.append(_keystone_record())
        assert journal.verify(expected_head=expected).ok
        journal._conn.execute(
            "UPDATE entries SET record_json = ? WHERE seq = 1",
            (json.dumps(_keystone_record(trust_outcome="UNTRUSTED")),))
        journal._conn.commit()
        assert not journal.verify(expected_head=expected).ok


def test_append_rejects_non_json_serialisable_record_without_mutation():
    from algovoi_execution_ref import execution_ref
    decision = keystone_ref({"grant": 1})
    record = {
        "decision_ref": decision, "action_type": "s3:put", "scope": "receipts/r1",
        "outcome": "COMMITTED", "executed_at_ms": 1717000000003,
        "execution_ref": execution_ref(decision, "s3:put", "receipts/r1", "COMMITTED",
                                       1717000000003),
        "note": b"raw bytes",
    }
    assert verify_record(record)  # a valid execution tier, but not storable JSON

    with Journal() as journal:
        with pytest.raises(ValueError, match="JSON-serialisable"):
            journal.append(record)
        assert journal.count() == 0


def test_append_stores_the_payload_it_validated():
    with Journal() as journal:
        journal.append(stage_record(value="original"))
        stored = journal._conn.execute("SELECT record_json FROM entries").fetchone()[0]
        assert verify_record(json.loads(stored))
        assert json.loads(stored)["value"] == "original"


def test_record_stage_rejects_decision_override_in_payload():
    rt, dref = _runtime()
    with pytest.raises(ValueError, match="decision_ref"):
        rt.record_stage("mandate", {"decision_ref": keystone_ref({"grant": "other"})})
    assert rt.journal.count() == 0


def test_bind_rejects_client_bound_to_another_decision():
    rt, dref = _runtime()
    client = _s3_connector()(FakeS3(), decision_ref=keystone_ref({"grant": "attacker"}))
    with pytest.raises(ValueError, match="decision_ref"):
        rt.bind(client)


def test_failed_execution_is_journaled():
    rt, dref = _runtime()
    client = _s3_connector()(ExplodingS3(), decision_ref=dref)
    s3 = rt.bind(client)

    with pytest.raises(RuntimeError):
        s3.put_object(Bucket="receipts", Key="r1", Body=b"{}")

    assert [r["outcome"] for r in rt.journal.by_kind("execution")] == ["FAILED"]
    assert rt.journal.verify().ok


def test_every_record_emitted_by_one_call_is_journaled():
    rt, dref = _runtime()
    s3 = rt.bind(MultiRecorder(dref))
    s3.put_object(Bucket="receipts", Key="r1")
    assert len(rt.journal.by_kind("execution")) == 2
    assert rt.journal.verify().ok


def test_concurrent_appends_keep_a_single_chain(tmp_path):
    path = tmp_path / "concurrent.db"
    with Journal(path) as journal:
        journal.append(stage_record(seed=True))
    writers = 12
    barrier = Barrier(writers)

    def worker(i):
        journal = Journal(path)
        try:
            barrier.wait()
            journal.append(stage_record(worker=i))
        finally:
            journal.close()

    with ThreadPoolExecutor(writers) as pool:
        list(pool.map(worker, range(writers)))

    with Journal(path) as journal:
        assert journal.count() == writers + 1
        assert journal.verify().ok
