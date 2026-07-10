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
    s3 = rt.bind(keystone_s3_client, behaviours=[cap_charges(500)])
    s3.put_object(Bucket="receipts", Key="r1", Body=b"{}")   # gated + journaled
    assert rt.journal.verify().ok                            # whole journal recomputes

This is the open journal. The commercial audit-chain is the same shape with
durable, post-quantum-signed, append-only storage.
"""
from __future__ import annotations

import json
import sqlite3
import time

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


def verify_record(record):
    """True when `record`'s own reference recomputes from its fields. Handles an
    execution_ref record, a behaviour_ref record, and a stage_ref record."""
    if not isinstance(record, dict):
        return False
    if "execution_ref" in record and all(
            k in record for k in ("decision_ref", "action_type", "scope", "outcome", "executed_at_ms")):
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

    def __init__(self, path=":memory:", *, clock_ms=None):
        self.path = path
        self._clock = clock_ms or (lambda: int(time.time() * 1000))
        self._conn = sqlite3.connect(path)
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
        self._conn.commit()

    # -- append ------------------------------------------------------------- #
    def append(self, record):
        """Append a self-describing record; returns the new journal head ref."""
        ref, kind, stage, dref = _classify(record)
        prev = self.head()
        jref = keystone_ref({"prev": prev, "record_ref": ref})
        self._conn.execute(
            "INSERT INTO entries(record_ref,decision_ref,stage,kind,record_json,"
            "recorded_at_ms,prev_journal_ref,journal_ref) VALUES(?,?,?,?,?,?,?,?)",
            (ref, dref, stage, kind, json.dumps(record, sort_keys=True),
             self._clock(), prev, jref))
        self._conn.commit()
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
    def verify(self):
        """Report: every record recomputes and the journal hash chain is intact."""
        r = Report()
        cur = self._conn.execute(
            "SELECT record_json, record_ref, prev_journal_ref, journal_ref FROM entries ORDER BY seq")
        rows = cur.fetchall()
        rec_ok = 0
        chain_ok = True
        prev = GENESIS
        for record_json, record_ref, prev_jref, jref in rows:
            record = json.loads(record_json)
            if verify_record(record):
                rec_ok += 1
            if prev_jref != prev or keystone_ref({"prev": prev, "record_ref": record_ref}) != jref:
                chain_ok = False
            prev = jref
        r.add("all %d records recompute their own reference" % len(rows), rec_ok == len(rows) and rows,
              "%d/%d" % (rec_ok, len(rows)))
        r.add("journal hash chain intact (no insert / remove / reorder)", chain_ok and bool(rows))
        r.add("head = %s" % (prev[:20] + "..."), True)
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
        """Journal a stage of the chain (passport, mandate, ...); returns its ref."""
        rec = dict(payload)
        rec.setdefault("decision_ref", self.decision_ref)
        rec["stage"] = stage
        rec["stage_ref"] = keystone_ref({k: v for k, v in rec.items()})
        self.journal.append(rec)
        return rec["stage_ref"]

    def _journal_executions(self, client):
        """Wrap a keystone-connect client so each new execution record is journaled."""
        journal = self.journal

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
                    result = attr(*args, **kwargs)
                    execs = getattr(self._inner, "executions", None)
                    if execs is not None and len(execs) > before:
                        journal.append(execs[-1])
                    return result

                return wrapped

        return _Journaled(client)

    def bind(self, connect_client, behaviours=()):
        """Return a client that gates writes through `behaviours` and journals both
        the behaviour_ref (every firing) and the execution_ref (every committed write)."""
        from algovoi_keystone_agent import Engine
        engine = Engine(list(behaviours), decision_ref=self.decision_ref,
                        clock_ms=self._clock, on_fire=self.journal.append)
        return engine.guard(self._journal_executions(connect_client))
