"""algovoi-keystone-vc -- keystone to W3C Verifiable Credential adapter (Apache-2.0)."""
from algovoi_keystone_vc.adapter import (  # noqa: F401
    CREDENTIAL_TYPE, KEYSTONE_CONTEXT, SHA256_PREFIX, VC_CONTEXT, execution_ref,
    to_verifiable_credential, verify_vc_execution_ref,
)
__version__ = "0.1.0"
__all__ = ["CREDENTIAL_TYPE", "KEYSTONE_CONTEXT", "SHA256_PREFIX", "VC_CONTEXT", "execution_ref",
           "to_verifiable_credential", "verify_vc_execution_ref", "__version__"]
