"""Compatibility name for the cross-account copy contract API."""

from s3transfer.contracts import *  # noqa: F403
from s3transfer.contracts import (  # noqa: F401
    AuditRecord,
    ContractAuditLog,
    ContractStageError,
    ContractStageTimeoutError,
    CrossAccountCopyContract,
    EncryptionConfig,
    EncryptionProfile,
    create_copy_contract,
)
