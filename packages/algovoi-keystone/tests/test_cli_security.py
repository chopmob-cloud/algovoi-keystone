"""Fail-closed regressions at the untrusted offline-evidence boundary."""
import json

from algovoi_keystone.cli import main
from algovoi_keystone_connect import keystone_ref


def test_incomplete_execution_cannot_fall_back_to_generic_hash(tmp_path):
    record = {"execution_ref": "sha256:" + "0" * 64, "outcome": "COMMITTED"}
    record["ref"] = keystone_ref(record)
    path = tmp_path / "incomplete.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    assert main(["validate", str(path)]) == 1


def test_incomplete_runtime_record_is_refused(tmp_path):
    """Runtime append never stores a record whose fields do not recompute."""
    from algovoi_keystone import Journal, Runtime

    db = str(tmp_path / "j.db")
    journal = Journal(db, clock_ms=lambda: 1)
    rt = Runtime(journal, decision_ref="sha256:x", clock_ms=lambda: 2)
    rec = {"decision_ref": "sha256:x", "action_type": "s3:put", "scope": "b",
           "outcome": "COMMITTED", "executed_at_ms": 1}
    rec["execution_ref"] = keystone_ref(rec)
    try:
        rt.journal.append(rec)
    except ValueError:
        refused = True
    else:
        refused = False
    rt.journal.close()
    assert refused is True



def test_empty_evidence_does_not_pass(tmp_path):
    path = tmp_path / "empty.json"
    path.write_text("[]", encoding="utf-8")
    assert main(["validate", str(path)]) != 0


def test_duplicate_json_keys_are_rejected(tmp_path):
    body = {"stage": "decision", "verdict": "ALLOW"}
    body["stage_ref"] = keystone_ref(body)
    text = json.dumps(body).replace('"verdict": "ALLOW"',
                                    '"verdict": "BLOCK", "verdict": "ALLOW"')
    path = tmp_path / "ambiguous.json"
    path.write_text(text, encoding="utf-8")
    assert main(["validate", str(path)]) == 2


def test_oversized_evidence_is_rejected(tmp_path):
    body = {"payload": "x" * (8 * 1024 * 1024)}
    body["stage_ref"] = keystone_ref(body)
    path = tmp_path / "large.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    assert main(["validate", str(path)]) == 2


def test_full_chain_wrapped_record_validates(tmp_path):
    """A typed execution_keystone wrapper is still decision-bound and recomputes."""
    from algovoi_execution_ref import bind_keystone

    body = bind_keystone(
        passport_ref=keystone_ref({"passport": 1}),
        mandate_ref=keystone_ref({"mandate": 1}),
        policy_bound_ref=keystone_ref({"policy": 1}), verdict="ALLOW",
        action_type="s3:put", scope="receipts/r1", outcome="COMMITTED",
        executed_at_ms=1700000000000, trust_outcome="TRUSTED")
    path = tmp_path / "wrapped.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    assert main(["validate", str(path)]) == 0


def test_tampered_full_chain_wrapper_is_rejected(tmp_path):
    """CLI must not accept a wrapper whose decision/trust tiers were rewritten."""
    from algovoi_execution_ref import bind_keystone

    body = bind_keystone(
        passport_ref=keystone_ref({"passport": 1}),
        mandate_ref=keystone_ref({"mandate": 1}),
        policy_bound_ref=keystone_ref({"policy": 1}), verdict="ALLOW",
        action_type="s3:put", scope="receipts/r1", outcome="COMMITTED",
        executed_at_ms=1700000000000, trust_outcome="TRUSTED")
    body["trust_outcome"] = "UNTRUSTED"
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    assert main(["validate", str(path)]) == 1


def test_multi_self_reference_record_is_rejected(tmp_path):
    body = {"stage": "mandate", "decision_ref": keystone_ref({"g": 1})}
    body["stage_ref"] = keystone_ref(body)
    body["behaviour_ref"] = "sha256:" + "a" * 64
    path = tmp_path / "mixed.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    assert main(["validate", str(path)]) == 1


def test_arbitrary_ref_field_cannot_prove_integrity(tmp_path):
    """Only real self-references count; a fabricated *_ref must not pass."""
    body = {"verdict": "ALLOW", "amount": 1}
    body["settlement_ref"] = keystone_ref(body)
    path = tmp_path / "fabricated.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    assert main(["validate", str(path)]) == 1


def test_journal_missing_database_reports_failure_without_creating_it(tmp_path):
    """A typo'd or absent journal path must not be silently created as empty."""
    db = tmp_path / "absent.db"
    assert main(["journal", str(db)]) != 0
    assert not db.exists()


def test_journal_corrupt_database_reports_failure(tmp_path):
    """Corrupt state must produce a failed report, not a traceback."""
    db = tmp_path / "corrupt.db"
    db.write_bytes(b"not a sqlite database at all" * 100)
    assert main(["journal", str(db)]) != 0


def test_journal_expected_head_truncation_is_detected(tmp_path, capsys):
    from algovoi_keystone import Journal, Runtime

    db = str(tmp_path / "j.db")
    journal = Journal(db, clock_ms=lambda: 1)
    rt = Runtime(journal, decision_ref=keystone_ref({"grant": 1}), clock_ms=lambda: 2)
    rt.record_stage("mandate", {"passport_ref": keystone_ref({"p": 1})})
    rt.record_stage("mandate", {"passport_ref": keystone_ref({"p": 2})})
    head = journal.head()
    journal.close()
    assert main(["journal", db, "--expected-head", head]) == 0
    assert main(["journal", db, "--expected-head", "sha256:" + "b" * 64]) == 1
