"""CLI: bind an execution to the keystone, or verify a record.

  echo '{...}' | algovoi-execution-ref            # build a keystone record
  algovoi-execution-ref --verify < record.json    # verify (exit 0/1)

Build input requires: passport_ref, mandate_ref, policy_bound_ref, verdict,
action_type, scope, outcome, executed_at_ms, trust_outcome.
"""
from __future__ import annotations

import argparse
import json
import sys

from algovoi_execution_ref.refs import (
    ExecutionRefError,
    bind_keystone,
    verify_record,
)


def main() -> None:
    ap = argparse.ArgumentParser(prog="algovoi-execution-ref",
                                 description="Bind an execution to the AlgoVoi keystone")
    ap.add_argument("--verify", action="store_true",
                    help="verify a record from stdin (exit 0 if consistent, 1 if not)")
    ap.add_argument("file", nargs="?", help="input JSON file (default: stdin)")
    args = ap.parse_args()
    raw = open(args.file, encoding="utf-8").read() if args.file else sys.stdin.read()
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"invalid JSON: {e}", file=sys.stderr); sys.exit(2)
    try:
        if args.verify:
            ok = verify_record(obj)
            print("VERIFIED" if ok else "MISMATCH")
            sys.exit(0 if ok else 1)
        print(json.dumps(bind_keystone(**obj), separators=(",", ":"), sort_keys=True))
    except (ExecutionRefError, TypeError) as e:
        print(f"error: {e}", file=sys.stderr); sys.exit(2)


if __name__ == "__main__":
    main()
