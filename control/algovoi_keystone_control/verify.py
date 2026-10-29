"""keystone-verify -- confirm a package is discovered by the AlgoVoi keystone control panel.

A package is "Keystone-enabled" if, when installed alongside ``algovoi-keystone-control``, it
appears in the panel's ``detect()`` -- either because the panel's catalogue recognises it
(commercial parent or open/lite variant) or because it registers an ``algovoi.keystone.steps``
entry point (a callable returning a dict with ``step`` + ``ref``).

Usage:
    keystone-verify <package>            # exit 0 if Keystone-enabled, 1 if not
    python -m algovoi_keystone_control.verify <package>
"""
from __future__ import annotations

import sys

from .detect import detect, integrations


def _norm(name: str) -> str:
    return (name or "").lower().replace("_", "-")


def keystone_status(package: str) -> dict:
    """Return the keystone discovery status for ``package`` in the current environment.

    Two tiers: ``step`` (produces a keystone ref) -> Keystone Enabled; ``integration``
    (consumes / exports / verifies keystone evidence) -> Keystone Integration.
    """
    want = _norm(package)
    for row in detect():
        if want in (_norm(row.get("provider") or ""), _norm(row.get("package") or "")):
            return {
                "package": package, "keystone": True, "tier": "step",
                "step": row["step"], "ref": row["ref"],
                "via": "entry-point" if row.get("_vendor") else "catalogue",
                "version": row.get("version"),
            }
    for row in integrations():
        if want == _norm(row.get("provider") or row.get("package") or ""):
            return {
                "package": package, "keystone": True, "tier": "integration",
                "role": row.get("role"), "posture": row.get("posture"),
                "version": row.get("version"),
            }
    return {"package": package, "keystone": False}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("usage: keystone-verify <package>", file=sys.stderr)
        return 2
    st = keystone_status(argv[0])
    if st.get("keystone") and st["tier"] == "step":
        print(f"PASS  {st['package']} is Keystone Enabled -> step '{st['step']}' "
              f"(emits {st['ref']}, via {st['via']})")
        return 0
    if st.get("keystone") and st["tier"] == "integration":
        print(f"PASS  {st['package']} is a Keystone Integration -> {st['role']} "
              f"({st['posture']})")
        return 0
    print(f"FAIL  {st['package']} is not recognised by the keystone control panel.\n"
          f"      Install it alongside algovoi-keystone-control. Steps register an\n"
          f"      algovoi.keystone.steps entry point or the catalogue; integrations are\n"
          f"      keystone-* tools that consume/export/verify keystone evidence.",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
