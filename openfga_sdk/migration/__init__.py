"""
Resumable, journaled batch migration helpers for OpenFGA relationships.

This package is intentionally additive to the generated SDK: it orchestrates
the existing :class:`openfga_sdk.client.client.OpenFgaClient` write and read
calls without changing generated code.
"""

from openfga_sdk.migration.fake_service import (
    FakeOpenFgaService,
    LostResponseError,
)
from openfga_sdk.migration.journal import (
    BatchOperation,
    BatchStatus,
    BatchRecord,
    MigrationJournal,
)
from openfga_sdk.migration.plan import MigrationPlan, MigrationPlanError
from openfga_sdk.migration.runner import (
    MigrationRecoveryError,
    MigrationResult,
    MigrationRunner,
)
from openfga_sdk.migration.tuple_key import TupleKeyError, tuple_identity


__all__ = [
    "BatchOperation",
    "BatchRecord",
    "BatchStatus",
    "FakeOpenFgaService",
    "LostResponseError",
    "MigrationJournal",
    "MigrationPlan",
    "MigrationPlanError",
    "MigrationRecoveryError",
    "MigrationResult",
    "MigrationRunner",
    "TupleKeyError",
    "tuple_identity",
]
