"""Alias module for cross-account copy contract support."""
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
