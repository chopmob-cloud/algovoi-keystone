"""algovoi-keystone-runtime -- run a Keystone chain and keep the evidence.

Assemble a chain (stages + connectors + behaviours), run it, and every emitted
reference lands in a durable, queryable, tamper-evident Journal. The runtime gates
writes through the behaviour layer and journals both the governance decision
(behaviour_ref) and the write it authorised (execution_ref), plus any stage refs
you record. Nothing new to trust: every stored reference recomputes offline from
its own fields, and the journal itself is a hash chain over those references.

    from algovoi_keystone_runtime import Journal, Runtime

    rt = Runtime(Journal("keystone.db"), decision_ref=decision_ref)
    rt.record_stage("mandate", {"passport_ref": passport_ref, "cap": "500USD"})
    # Guard behaviours must trigger on the stage the guard dispatches ("execution");
    # a spend cap is a decision-stage behaviour and belongs before the write.
    s3 = rt.bind(keystone_s3_client, behaviours=[deny_writes_to("Bucket", ["locked"])])
    s3.put_object(Bucket="receipts", Key="r1", Body=b"{}")   # gated + journaled
    assert rt.journal.verify().ok                            # whole journal recomputes

This is the open journal. The commercial audit-chain is the same shape with
durable, post-quantum-signed, append-only storage.
"""

from __future__ import annotations

__version__ = "0.5.0"

import json
import re
import sqlite3
import time
from pathlib import Path

try:
    from algovoi_keystone_connect import Report, keystone_ref
except Exception:  # pragma: no cover - standalone fallback
    import hashlib

    import rfc8785

    def keystone_ref(payload):
        return "sha256:" + hashlib.sha256(rfc8785.dumps(payload)).hexdigest()

    class Report:
        def __init__(self):
            self.checks = []

        def add(self, name, passed, detail=""):
            self.checks.append((name, bool(passed), detail))

        @property
        def ok(self):
            return all(p for _, p, _ in self.checks) and bool(self.checks)

        def __repr__(self):
            lines = ["[%s] %s%s" % ("ok" if p else "FAIL", n, (" - " + d) if d else "")
                     for n, p, d in self.checks]
            return "\n".join(lines) + "\n=> %s" % ("PASS" if self.ok else "FAIL")

__all__ = ["Journal", "Runtime", "verify_record", "GENESIS"]

# The prev-link of the first journal entry.
GENESIS = "sha256:" + "0" * 64

# Seconds a writer waits for the IMMEDIATE lock before raising "database is locked".
_BUSY_TIMEOUT_S = 30.0


_SELF_REFS = ("execution_ref", "behaviour_ref", "stage_ref")
# Fields that only a full keystone wrapper (see `bind_keystone`) carries; their
# presence means the record must be validated as a whole, not just its execution tier.
_KEYSTONE_MARKERS = ("trust_query_ref", "chain", "trust_outcome")


def verify_record(record):
    """True when `record`'s own references recompute from its fields.

    Accepted shapes, each carrying exactly one self-reference:

    * a stage_ref or behaviour_ref record -- the reference is a JCS hash over every
      other field, so tampering with any field (decision_ref included) breaks it;
    * a plain execution_ref record -- the reference recomputes from the five
      execution-tier fields;
    * an ``execution_keystone`` wrapper from ``algovoi_execution_ref.bind_keystone``
      -- decision_ref, execution_ref, trust_query_ref and the chain are all
      recomputed by that package, not just the execution tier;
    * records carrying trust material without a valid wrapper are rejected.
    """
    if not isinstance(record, dict):
        return False
    if sum(key in record for key in _SELF_REFS) != 1:
        return False
    if "execution_ref" in record:
        if record.get("type") == "execution_keystone" or any(
                key in record for key in _KEYSTONE_MARKERS):
            return _verify_execution_keystone(record)
        try:
            from algovoi_execution_ref import execution_ref
            want = execution_ref(record["decision_ref"], record["action_type"],
                                 record["scope"], record["outcome"], record["executed_at_ms"])
            return want == record["execution_ref"]
        except Exception:
            return False
    for key in ("behaviour_ref", "stage_ref"):
        if key in record:
            body = {k: v for k, v in record.items() if k != key}
            try:
                return keystone_ref(body) == record[key]
            except Exception:
                return False
    return False


def _verify_execution_keystone(record):
    """Delegate the whole wrapper to the dependency that defines it."""
    try:
        from algovoi_execution_ref import verify_record as verify_execution_keystone
        return bool(verify_execution_keystone(record))
    except Exception:
        return False


def _classify(record):
    for key, kind in (("execution_ref", "execution"), ("behaviour_ref", "behaviour"),
                      ("stage_ref", "stage")):
        if key in record:
            return record[key], kind, record.get("stage") or kind, record.get("decision_ref", "")
    raise ValueError("record has no execution_ref / behaviour_ref / stage_ref self-reference")


class Journal:
    """A durable, queryable store of Keystone records, backed by SQLite.

    Each row keeps the record, its own reference, and a `journal_ref` that hash
    chains it to the previous row, so `verify()` proves both that every record
    recomputes and that nothing has been inserted, removed or reordered.
    """

    def __init__(self, path=":memory:", *, clock_ms=None, read_only=False):
        self.path = path
        self.read_only = bool(read_only)
        self._clock = clock_ms or (lambda: int(time.time() * 1000))
        if self.read_only:
            if str(path) == ":memory:":
                raise ValueError("read_only requires a file-backed journal path")
            # mode=ro never creates the file and never writes the schema; a missing
            # or non-journal database surfaces as sqlite3.Error at connect/verify.
            self._conn = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True,
                                         timeout=_BUSY_TIMEOUT_S)
            self._conn.isolation_level = None
            return
        self._conn = sqlite3.connect(path, timeout=_BUSY_TIMEOUT_S)
        # Explicit transaction control: the head read and the insert that links to it
        # must be one IMMEDIATE transaction, or two writers fork the chain.
        self._conn.isolation_level = None
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS entries (
                seq              INTEGER PRIMARY KEY AUTOINCREMENT,
                record_ref       TEXT NOT NULL,
                decision_ref     TEXT,
                stage            TEXT,
                kind             TEXT,
                record_json      TEXT NOT NULL,
                recorded_at_ms   INTEGER NOT NULL,
                prev_journal_ref TEXT NOT NULL,
                journal_ref      TEXT NOT NULL
            )""")

    # -- append ------------------------------------------------------------- #
    def append(self, record):
        """Append a self-describing record; returns the new journal head ref."""
        if self.read_only:
            raise ValueError("journal was opened read_only; append is not permitted")
        # Serialise once and validate exactly what will be stored: the caller's dict
        # cannot change between the check and the write, and a row that cannot be
        # re-verified later can never be produced.
        try:
            record_json = json.dumps(record, sort_keys=True)
        except (TypeError, ValueError) as exc:
            raise ValueError("record must be JSON-serialisable: %s" % exc) from exc
        stored = json.loads(record_json)
        if not verify_record(stored):
            raise ValueError("record must have one valid self-reference")
        ref, kind, stage, dref = _classify(stored)
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT journal_ref FROM entries ORDER BY seq DESC LIMIT 1").fetchone()
            prev = row[0] if row else GENESIS
            jref = keystone_ref({"prev": prev, "record_ref": ref})
            self._conn.execute(
                "INSERT INTO entries(record_ref,decision_ref,stage,kind,record_json,"
                "recorded_at_ms,prev_journal_ref,journal_ref) VALUES(?,?,?,?,?,?,?,?)",
                (ref, dref, stage, kind, record_json, self._clock(), prev, jref))
            self._conn.execute("COMMIT")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        return jref

    # -- query -------------------------------------------------------------- #
    def _rows(self, where="", params=()):
        cur = self._conn.execute(
            "SELECT record_json FROM entries " + where + " ORDER BY seq", params)
        return [json.loads(r[0]) for r in cur.fetchall()]

    def records(self):
        return self._rows()

    def by_decision(self, decision_ref):
        return self._rows("WHERE decision_ref = ?", (decision_ref,))

    def by_stage(self, stage):
        return self._rows("WHERE stage = ?", (stage,))

    def by_kind(self, kind):
        return self._rows("WHERE kind = ?", (kind,))

    def chain(self, decision_ref):
        """Every record recorded under a decision, in order -- the decision's chain."""
        return self.by_decision(decision_ref)

    def count(self):
        return self._conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]

    def head(self):
        row = self._conn.execute(
            "SELECT journal_ref FROM entries ORDER BY seq DESC LIMIT 1").fetchone()
        return row[0] if row else GENESIS

    # -- verify / replay ---------------------------------------------------- #
    def verify(self, expected_head=None, expected_count=None, *,
               expect_head=None, expect_count=None):
        """Check internal consistency, optionally against a separately trusted anchor.

        `expected_head` / `expected_count` are pins the caller persists elsewhere (a CLI
        flag, a receipt, another ledger). Without a pin, a journal whose newest rows were
        removed still verifies: the rows that remain are a valid prefix.

        `expect_head` / `expect_count` are accepted as aliases -- the names used by the
        0.1.1 release -- and passing both spellings with different values is an error.

        A malformed pin raises ValueError rather than silently verifying anything.
        """
        if expect_head is not None:
            if expected_head is not None and expected_head != expect_head:
                raise ValueError("expected_head and expect_head disagree")
            expected_head = expect_head
        if expect_count is not None:
            if expected_count is not None and expected_count != expect_count:
                raise ValueError("expected_count and expect_count disagree")
            expected_count = expect_count
        if expected_head is not None and not (
                isinstance(expected_head, str) and
                re.fullmatch(r"sha256:[0-9a-f]{64}", expected_head)):
            raise ValueError("expected_head must be sha256: followed by 64 lowercase hex digits")
        if expected_count is not None and not (
                isinstance(expected_count, int) and not isinstance(expected_count, bool)
                and expected_count >= 0):
            raise ValueError("expected_count must be a non-negative int")
        r = Report()
        try:
            rows = self._conn.execute(
                "SELECT record_json, record_ref, prev_journal_ref, journal_ref, "
                "kind, stage, decision_ref FROM entries ORDER BY seq").fetchall()
        except sqlite3.Error as exc:
            r.add("journal readable", False, str(exc))
            return r
        rec_ok = 0
        chain_ok = True
        prev = GENESIS
        for record_json, record_ref, prev_jref, jref, kind, stage, dref in rows:
            try:
                record = json.loads(record_json)
                if verify_record(record) and _classify(record) == (record_ref, kind, stage, dref):
                    rec_ok += 1
                if prev_jref != prev or keystone_ref({"prev": prev, "record_ref": record_ref}) != jref:
                    chain_ok = False
            except (ValueError, TypeError, RecursionError):
                chain_ok = False
            prev = jref
        r.add("all %d records recompute their own reference" % len(rows),
              rec_ok == len(rows) and bool(rows), "%d/%d" % (rec_ok, len(rows)))
        r.add("journal hash chain intact (no insert / remove / reorder)", chain_ok and bool(rows))
        r.add("head = %s" % (str(prev)[:20] + "..."), True)
        if expected_head is not None:
            r.add("head matches expected_head", prev == expected_head)
        if expected_count is not None:
            r.add("entry count matches expected_count", len(rows) == expected_count,
                  "%d/%d" % (len(rows), expected_count))
        return r

    def export(self):
        """Every stored record as a plain list, for external offline verification."""
        return self.records()

    def close(self):
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class Runtime:
    """Binds a decision to a Journal: gate writes through behaviours and record
    every emitted reference (stage, behaviour, execution) as it happens."""

    def __init__(self, journal, *, decision_ref, clock_ms=None):
        self.journal = journal
        self.decision_ref = decision_ref
        self._clock = clock_ms or (lambda: int(time.time() * 1000))

    def record_stage(self, stage, payload):
        """Journal a stage of the chain (passport, mandate, ...); returns its ref.

        The stage is always bound to this Runtime's decision: a payload that claims a
        different decision_ref is rejected rather than silently re-bound, because that
        would launder another decision's evidence into this chain.
        """
        if not isinstance(payload, dict):
            raise ValueError("stage payload must be a dict")
        supplied = payload.get("decision_ref")
        if supplied is not None and supplied != self.decision_ref:
            raise ValueError("payload decision_ref does not match this runtime's decision_ref")
        rec = dict(payload)
        rec["decision_ref"] = self.decision_ref
        rec["stage"] = stage
        rec["stage_ref"] = keystone_ref(rec)
        self.journal.append(rec)
        return rec["stage_ref"]

    def _journal_executions(self, client):
        """Wrap a keystone-connect client so every execution record it emits is journaled.

        Records are taken from the client's ``executions`` list as a slice, not just the
        last entry, and are journaled from a ``finally`` block so a FAILED execution --
        the case an audit trail exists for -- is recorded even though the error propagates.
        """
        journal = self.journal
        decision = self.decision_ref

        class _Journaled:
            def __init__(self, inner):
                self._inner = inner

            def __getattr__(self, name):
                attr = getattr(self._inner, name)
                if not callable(attr):
                    return attr

                def wrapped(*args, **kwargs):
                    execs = getattr(self._inner, "executions", None)
                    before = len(execs) if execs is not None else 0
                    try:
                        return attr(*args, **kwargs)
                    finally:
                        emitted = getattr(self._inner, "executions", None)
                        for record in list(emitted[before:]) if emitted is not None else ():
                            if record.get("decision_ref") != decision:
                                raise ValueError(
                                    "execution record is bound to a different decision_ref")
                            journal.append(record)

                return wrapped

        return _Journaled(client)

    def bind(self, connect_client, behaviours=()):
        """Return a client that gates writes through `behaviours` and journals both
        the behaviour_ref (every firing) and the execution_ref (every committed write)."""
        bound_to = _bound_decision_ref(connect_client)
        if bound_to is not None and bound_to != self.decision_ref:
            raise ValueError("connect client is bound to a different decision_ref")
        from algovoi_keystone_agent import Engine
        engine = Engine(list(behaviours), decision_ref=self.decision_ref,
                        clock_ms=self._clock, on_fire=self.journal.append)
        return engine.guard(self._journal_executions(connect_client))


def _bound_decision_ref(client):
    """The decision a wrapped client was constructed with, when it exposes one."""
    for attr in ("decision_ref", "_decision_ref"):
        try:
            value = getattr(client, attr)
        except Exception:
            continue
        if isinstance(value, str) and value:
            return value
    return None
