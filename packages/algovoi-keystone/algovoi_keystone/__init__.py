"""algovoi-keystone -- the Keystone SDK umbrella.

One install brings the whole bolt-on toolchain:

    pip install algovoi-keystone

and one import surface over it:

    from algovoi_keystone import connector, behaviour, rule, trigger, Engine, keystone_ref

You get the connector builder (keystone-connect), the behaviour layer
(keystone-agent) with its ready-made `behaviours` library, and the `keystone`
command line. Everything still reduces to one primitive:

    keystone_ref(payload) == "sha256:" + SHA-256(RFC 8785 JCS(payload))
"""
__version__ = "0.1.1"

# The connector builder + conformance harness.
from algovoi_keystone_connect import (  # noqa: F401
    Call, EXECUTION_OUTCOMES, Report, check_connector, check_ref_builder,
    connector, execution_ref, keystone_ref, synth_ref,
)

# The agentic behaviour layer.
from algovoi_keystone_agent import (  # noqa: F401
    Denied, Engine, Event, behaviour, check_behaviour, check_rule,
    check_trigger, rule, synth_event, trigger,
)
# Ready-made behaviours: `from algovoi_keystone import behaviours; behaviours.cap_charges(500)`
from algovoi_keystone_agent import library as behaviours  # noqa: F401

# The runtime: run a chain and keep the evidence in a tamper-evident journal.
from algovoi_keystone_runtime import Journal, Runtime, verify_record  # noqa: F401

__all__ = [
    "__version__",
    # primitive + connectors
    "keystone_ref", "synth_ref", "connector", "Call", "execution_ref",
    "EXECUTION_OUTCOMES", "Report", "check_connector", "check_ref_builder",
    # behaviour layer
    "rule", "trigger", "behaviour", "Engine", "Denied", "Event",
    "synth_event", "check_rule", "check_trigger", "check_behaviour",
    "behaviours",
    # runtime + journal
    "Runtime", "Journal", "verify_record",
]
