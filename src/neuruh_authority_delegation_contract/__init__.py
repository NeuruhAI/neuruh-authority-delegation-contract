from importlib.metadata import PackageNotFoundError, version as _metadata_version

from .core import (
    SCHEMA_VERSION,
    STATUSES,
    AuthorityDelegation,
    DelegationValidationError,
    authorize,
    canonical_json,
    create_root_delegation,
    derive_delegation,
    revoke_delegation,
    sha256_ref,
    verify_child,
)

__all__ = [
    "SCHEMA_VERSION",
    "STATUSES",
    "AuthorityDelegation",
    "DelegationValidationError",
    "authorize",
    "canonical_json",
    "create_root_delegation",
    "derive_delegation",
    "revoke_delegation",
    "sha256_ref",
    "verify_child",
]

try:
    __version__ = _metadata_version("neuruh-authority-delegation-contract")
except PackageNotFoundError:  # running from a source tree that was never installed
    __version__ = "unknown"
