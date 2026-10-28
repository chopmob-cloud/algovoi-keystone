"""algovoi-cloudevents -- keystone to CloudEvents 1.0 adapter (Apache-2.0)."""
from algovoi_cloudevents.adapter import (  # noqa: F401
    SHA256_PREFIX, SPEC_VERSION, STAGES, TYPE_PREFIX, execution_ref, to_cloudevent,
    verify_cloudevent_execution_ref,
)
__version__ = "0.1.0"
__all__ = ["SHA256_PREFIX", "SPEC_VERSION", "STAGES", "TYPE_PREFIX", "execution_ref",
           "to_cloudevent", "verify_cloudevent_execution_ref", "__version__"]
