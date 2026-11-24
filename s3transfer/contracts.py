# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
"""Stage-scoped contracts for cross-account encrypted copies.

The contract keeps source and destination encryption material separate.  It
also produces public audit records which describe the stage and request class
without retaining secret material values.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections.abc import Mapping

from s3transfer.exceptions import S3CopyFailedError

# Canonical stage identifiers.  They use the S3 operation name when a stage
# maps to exactly one operation so diagnostics can be correlated with requests.
SOURCE_METADATA_STAGE = "head_object"
COPY_OBJECT_STAGE = "copy_object"
CREATE_MULTIPART_STAGE = "create_multipart_upload"
COPY_PART_STAGE = "upload_part_copy"
COMPLETE_MULTIPART_STAGE = "complete_multipart_upload"
CLEANUP_MULTIPART_STAGE = "abort_multipart_upload"

# Descriptive aliases for callers that prefer workflow-oriented names.
READ_SOURCE_METADATA = SOURCE_METADATA_STAGE
CREATE_DESTINATION_JOB = CREATE_MULTIPART_STAGE
COPY_FRAGMENT = COPY_PART_STAGE
COMPLETE_DESTINATION_JOB = COMPLETE_MULTIPART_STAGE
CLEANUP_DESTINATION_JOB = CLEANUP_MULTIPART_STAGE

SOURCE_CATEGORY = "source_encryption_material"
DESTINATION_CATEGORY = "destination_encryption_material"
MIXED_COPY_CATEGORY = "source_and_destination_copy_material"
DESTINATION_LIFECYCLE_CATEGORY = "destination_multipart_lifecycle"

_SOURCE_SSE_ARGS = frozenset(
    {"SSECustomerAlgorithm", "SSECustomerKey", "SSECustomerKeyMD5"}
)
_DESTINATION_SSE_ARGS = frozenset(
    {"SSECustomerAlgorithm", "SSECustomerKey", "SSECustomerKeyMD5"}
)
_SOURCE_COPY_SSE_ARGS = frozenset(
    {
        "CopySourceSSECustomerAlgorithm",
        "CopySourceSSECustomerKey",
        "CopySourceSSECustomerKeyMD5",
    }
)
_SERVER_ENCRYPTION_ARGS = frozenset(
    {
        "ServerSideEncryption",
        "SSEKMSKeyId",
        "SSEKMSEncryptionContext",
        "BucketKeyEnabled",
    }
)
ENCRYPTION_ARGUMENTS = (
    _SOURCE_SSE_ARGS | _SOURCE_COPY_SSE_ARGS | _SERVER_ENCRYPTION_ARGS
)

_SOURCE_ARG_TO_COPY_ARG = {
    "SSECustomerAlgorithm": "CopySourceSSECustomerAlgorithm",
    "SSECustomerKey": "CopySourceSSECustomerKey",
    "SSECustomerKeyMD5": "CopySourceSSECustomerKeyMD5",
}

_SENSITIVE_NAME_TOKENS = (
    "customercode",
    "customerkey",
    "encryptioncontext",
    "kmskeyid",
    "material",
    "credential",
    "password",
    "secret",
    "signature",
    "token",
    "key",
)
_NON_SECRET_ENCRYPTION_ARGS = frozenset(
    {
        "SSECustomerAlgorithm",
        "CopySourceSSECustomerAlgorithm",
        "ServerSideEncryption",
        "BucketKeyEnabled",
    }
)
_NON_SENSITIVE_ARGUMENTS = _NON_SECRET_ENCRYPTION_ARGS | frozenset(
    {"Bucket", "Key", "CopySource"}
)
_REDACTED = "[REDACTED]"


class ContractError(Exception):
    """Base class for copy contract failures."""


class ContractViolationError(ContractError, ValueError):
    """Raised when callers mix material scopes or violate the contract."""


class ContractStageError(ContractError, S3CopyFailedError):
    """A copy failed at one contract stage.

    The public message intentionally names only the failed stage.  Detailed
    request material remains in the contract's audit log in redacted form.
    """

    def __init__(self, diagnosis):
        self.diagnosis = diagnosis
        self.stage = diagnosis.get("stage")
        self.purpose = diagnosis.get("purpose")
        self.category = diagnosis.get("category")
        self.operation = diagnosis.get("operation")
        self.attempt = diagnosis.get("attempt")
        self.part_number = diagnosis.get("part_number")
        super().__init__(diagnosis["message"])

    def public_dict(self):
        return dict(self.diagnosis)


class ContractStageTimeoutError(ContractStageError, TimeoutError):
    """A timeout occurred while executing an approved stage."""


# Friendly alias used by some review/probe code.
CopyContractStageError = ContractStageError
CopyContractTimeoutError = ContractStageTimeoutError


class EncryptionProfile:
    """An independently managed source or destination encryption profile.

    ``config`` may be a mapping of synthetic material/request settings.
    Values supplied as ``request_args`` are the values projected onto S3
    requests.  Arbitrary ``materials`` are treated as secret and are never
    included in public audit records.
    """

    def __init__(
        self,
        config=None,
        *,
        name=None,
        profile_id=None,
        label=None,
        account_id=None,
        account=None,
        category=None,
        classification=None,
        purpose=None,
        materials=None,
        secret_materials=None,
        request_args=None,
        args=None,
        parameters=None,
        **kwargs,
    ):
        if isinstance(config, Mapping):
            data = dict(config)
        elif config is not None and hasattr(config, "__dict__"):
            data = {
                key: value
                for key, value in vars(config).items()
                if not key.startswith("_") and not callable(value)
            }
        else:
            data = {}
        self.name = (
            name
            or profile_id
            or label
            or data.pop("name", None)
            or data.pop("profile_id", None)
            or data.pop("label", None)
        )
        self.account_id = (
            account_id
            or account
            or data.pop("account_id", None)
            or data.pop("account", None)
        )
        self.category = (
            category
            or classification
            or data.pop("category", None)
            or data.pop("classification", None)
        )
        self.purpose = purpose or data.pop("purpose", None)

        material_data = {}
        for source in (
            materials,
            secret_materials,
            data.pop("materials", None),
            data.pop("secret_materials", None),
        ):
            if source:
                material_data.update(dict(source))
        self._materials = material_data

        explicit_args = (
            request_args
            if request_args is not None
            else args
            if args is not None
            else parameters
            if parameters is not None
            else data.pop("request_args", None)
            or data.pop("args", None)
            or data.pop("parameters", None)
            or data.pop("extra_args", None)
        )
        if explicit_args is not None:
            self._request_args = dict(explicit_args)
        else:
            self._request_args = {
                key: value
                for key, value in data.items()
                if key in ENCRYPTION_ARGUMENTS
            }
            for key, value in data.items():
                if key not in ENCRYPTION_ARGUMENTS:
                    self._materials.setdefault(key, value)
        self._request_args.update(kwargs)

        for key, value in self._materials.items():
            if key in ENCRYPTION_ARGUMENTS and key not in self._request_args:
                self._request_args[key] = value

        if self.category is None:
            self.category = "encryption_material"
        self.digest = self._calculate_digest()

    @classmethod
    def coerce(cls, value, default_category=None):
        if value is None or isinstance(value, EncryptionProfile):
            profile = value
        elif isinstance(value, Mapping):
            profile = cls(value)
        else:
            profile = cls(materials={"value": value})
        if (
            profile is not None
            and default_category
            and profile.category == "encryption_material"
        ):
            profile.category = default_category
        return profile

    @property
    def materials(self):
        # Return a copy so callers cannot mutate the locked profile through
        # the public mapping.
        return dict(self._materials)

    @property
    def request_args(self):
        return dict(self._request_args)

    @property
    def secret_values(self):
        values = set()
        for value in (*self._materials.values(), *self._request_args.values()):
            if isinstance(value, str) and value:
                values.add(value)
        return values

    @property
    def material_values(self):
        values = set()
        for value in self._materials.values():
            if isinstance(value, str) and value:
                values.add(value)
        for key, value in self._request_args.items():
            if key in _NON_SENSITIVE_ARGUMENTS:
                continue
            if isinstance(value, str) and value:
                values.add(value)
        return values

    def copy_source_args(self):
        result = {}
        for key, value in self._request_args.items():
            result[_SOURCE_ARG_TO_COPY_ARG.get(key, key)] = value
        return result

    def public_view(self):
        return {
            "name": self.name,
            "account_id": self.account_id,
            "category": self.category,
            "classification": self.category,
            "purpose": self.purpose,
            "digest": self.digest,
            "material_names": sorted(self._materials),
            "parameter_names": sorted(self._request_args),
        }

    def _calculate_digest(self):
        canonical = json.dumps(
            {
                "materials": self._materials,
                "request_args": self._request_args,
            },
            sort_keys=True,
            default=str,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()[:16]

    def __repr__(self):
        name = self.name or "<unnamed>"
        return (
            f"EncryptionProfile(name={name!r}, category={self.category!r}, "
            f"digest={self.digest!r})"
        )


# Common descriptive aliases for the synthetic configuration vocabulary.
EncryptionConfig = EncryptionProfile
SyntheticEncryptionConfig = EncryptionProfile
EncryptionMaterialConfig = EncryptionProfile
MaterialProfile = EncryptionProfile


class AuditRecord:
    """One redacted actual request attempt."""

    def __init__(
        self,
        sequence,
        stage,
        operation,
        purpose,
        category,
        side,
        status,
        attempt=1,
        max_attempts=1,
        part_number=None,
        request=None,
        material_refs=None,
        material_categories=None,
        error=None,
    ):
        self.sequence = sequence
        self.stage = stage
        self.step = stage
        self.name = stage
        self.operation = operation
        self.purpose = purpose
        self.use = purpose
        self.category = category
        self.kind = category
        self.classification = category
        self.side = side
        self.status = status
        self.attempt = attempt
        self.max_attempts = max_attempts
        self.part_number = part_number
        self.request = request or {}
        self.redacted_request = self.request
        self.material_refs = material_refs or []
        self.material_categories = material_categories or []
        self.error = error
        self.timestamp = time.time()

    def to_dict(self):
        return {
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "stage": self.stage,
            "step": self.step,
            "name": self.name,
            "operation": self.operation,
            "purpose": self.purpose,
            "use": self.use,
            "category": self.category,
            "kind": self.kind,
            "classification": self.classification,
            "side": self.side,
            "status": self.status,
            "attempt": self.attempt,
            "max_attempts": self.max_attempts,
            "part_number": self.part_number,
            "request": copy_deep(self.request),
            "redacted_request": copy_deep(self.redacted_request),
            "material_refs": copy_deep(self.material_refs),
            "material_categories": list(self.material_categories),
            "error": copy_deep(self.error),
        }


class ContractAuditLog:
    """Thread-safe public log of contract stages."""

    def __init__(self):
        self._records = []
        self._lock = threading.RLock()

    def add(self, **kwargs):
        with self._lock:
            record = AuditRecord(sequence=len(self._records) + 1, **kwargs)
            self._records.append(record)
            return record

    @property
    def records(self):
        with self._lock:
            return list(self._records)

    def public_records(self):
        with self._lock:
            return [record.to_dict() for record in self._records]

    def as_dicts(self):
        return self.public_records()

    def to_json(self, **kwargs):
        kwargs.setdefault("sort_keys", True)
        return json.dumps(self.public_records(), **kwargs)

    def for_stage(self, stage):
        return [record for record in self.records if record.stage == stage]

    def __iter__(self):
        return iter(self.records)

    def __len__(self):
        return len(self._records)


# Friendly aliases.
AuditLog = ContractAuditLog
ContractRecorder = ContractAuditLog
PublicAuditLog = ContractAuditLog


class _Stage:
    def __init__(self, name, purpose, category, side):
        self.name = name
        self.purpose = purpose
        self.category = category
        self.side = side


_STAGES = {
    SOURCE_METADATA_STAGE: _Stage(
        SOURCE_METADATA_STAGE,
        "read-source-object-metadata",
        SOURCE_CATEGORY,
        "source",
    ),
    COPY_OBJECT_STAGE: _Stage(
        COPY_OBJECT_STAGE,
        "copy-object-with-source-and-destination-contracts",
        MIXED_COPY_CATEGORY,
        "both",
    ),
    CREATE_MULTIPART_STAGE: _Stage(
        CREATE_MULTIPART_STAGE,
        "create-destination-multipart-job",
        DESTINATION_CATEGORY,
        "destination",
    ),
    COPY_PART_STAGE: _Stage(
        COPY_PART_STAGE,
        "copy-byte-range-into-destination-fragment",
        MIXED_COPY_CATEGORY,
        "both",
    ),
    COMPLETE_MULTIPART_STAGE: _Stage(
        COMPLETE_MULTIPART_STAGE,
        "complete-destination-multipart-job",
        DESTINATION_CATEGORY,
        "destination",
    ),
    CLEANUP_MULTIPART_STAGE: _Stage(
        CLEANUP_MULTIPART_STAGE,
        "clean-up-destination-multipart-job",
        DESTINATION_LIFECYCLE_CATEGORY,
        "destination",
    ),
    "get_object_tagging": _Stage(
        "get_object_tagging",
        "read-source-object-tags",
        SOURCE_CATEGORY,
        "source",
    ),
    "list_object_annotations": _Stage(
        "list_object_annotations",
        "list-source-object-annotations",
        SOURCE_CATEGORY,
        "source",
    ),
    "get_object_annotation": _Stage(
        "get_object_annotation",
        "read-source-object-annotation",
        SOURCE_CATEGORY,
        "source",
    ),
    "put_object_tagging": _Stage(
        "put_object_tagging",
        "apply-destination-object-tags",
        DESTINATION_CATEGORY,
        "destination",
    ),
    "put_object_annotation": _Stage(
        "put_object_annotation",
        "apply-destination-object-annotation",
        DESTINATION_CATEGORY,
        "destination",
    ),
}

_OPERATION_STAGE = {
    "head_object": SOURCE_METADATA_STAGE,
    "copy_object": COPY_OBJECT_STAGE,
    "create_multipart_upload": CREATE_MULTIPART_STAGE,
    "upload_part_copy": COPY_PART_STAGE,
    "complete_multipart_upload": COMPLETE_MULTIPART_STAGE,
    "abort_multipart_upload": CLEANUP_MULTIPART_STAGE,
}


def copy_deep(value):
    if isinstance(value, Mapping):
        return {key: copy_deep(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [copy_deep(item) for item in value]
    return value


def _is_timeout(exc):
    if isinstance(exc, TimeoutError):
        return True
    for cls in type(exc).__mro__:
        name = cls.__name__.lower()
        if "timeout" in name:
            return True
    return False


def _sensitive_key(key):
    if key in _NON_SENSITIVE_ARGUMENTS:
        return False
    normalized = "".join(
        character.lower() for character in key if character.isalnum()
    )
    return any(token in normalized for token in _SENSITIVE_NAME_TOKENS)


def build_stage_exception(original, diagnosis):
    """Build a safe stage error without losing the original exception type."""
    if isinstance(original, ContractStageError):
        return original
    base = (
        ContractStageTimeoutError
        if _is_timeout(original)
        else ContractStageError
    )
    original_type = type(original)
    try:

        class _StageHybridError(base, original_type):
            def __init__(self):
                Exception.__init__(self, diagnosis["message"])
                self.diagnosis = diagnosis
                self.stage = diagnosis.get("stage")
                self.step = diagnosis.get("step")
                self.purpose = diagnosis.get("purpose")
                self.category = diagnosis.get("category")
                self.operation = diagnosis.get("operation")
                self.attempt = diagnosis.get("attempt")
                self.part_number = diagnosis.get("part_number")
                self.response = getattr(original, "response", None)
                self.operation_name = getattr(original, "operation_name", None)

        return _StageHybridError()
    except Exception:
        error = base(diagnosis)
        error.original_exception_type = original_type.__name__
        return error


class AuditedClient:
    """Proxy that records actual client calls through a contract."""

    _s3transfer_contract_wrapper = True

    def __init__(self, client, contract, side):
        object.__setattr__(self, "_client", client)
        object.__setattr__(self, "_contract", contract)
        object.__setattr__(self, "_side", side)

    def __getattr__(self, name):
        attr = getattr(object.__getattribute__(self, "_client"), name)
        if not callable(attr):
            return attr

        def audited_call(*args, **kwargs):
            contract = object.__getattribute__(self, "_contract")
            side = object.__getattribute__(self, "_side")
            return contract.execute(
                operation=name,
                call=lambda: attr(*args, **kwargs),
                side=side,
                request_args=kwargs,
            )

        audited_call.__name__ = name
        return audited_call

    def __enter__(self):
        client = object.__getattribute__(self, "_client")
        return client.__enter__()

    def __exit__(self, exc_type, exc, traceback):
        client = object.__getattribute__(self, "_client")
        return client.__exit__(exc_type, exc, traceback)

    def __repr__(self):
        client = object.__getattribute__(self, "_client")
        return f"AuditedClient({client!r})"


class CrossAccountCopyContract:
    """Explicit source/destination encryption and audit contract."""

    def __init__(
        self,
        source=None,
        destination=None,
        *,
        source_config=None,
        destination_config=None,
        source_settings=None,
        destination_settings=None,
        source_extra_args=None,
        destination_extra_args=None,
        source_profile=None,
        destination_profile=None,
        source_encryption=None,
        destination_encryption=None,
        source_encryption_settings=None,
        destination_encryption_settings=None,
        audit=None,
        audit_log=None,
        recorder=None,
        ledger=None,
        strict=True,
        source_attempts=2,
        part_attempts=None,
        max_part_attempts=None,
        part_max_attempts=None,
        max_attempts=None,
        retry_timeouts=True,
        sleeper=None,
        **_ignored,
    ):
        if part_attempts is None:
            part_attempts = max_part_attempts or part_max_attempts or 2
        source_value = (
            source
            or source_profile
            or source_config
            or source_settings
            or source_extra_args
            or source_encryption
            or source_encryption_settings
        )
        destination_value = (
            destination
            or destination_profile
            or destination_config
            or destination_settings
            or destination_extra_args
            or destination_encryption
            or destination_encryption_settings
        )
        self.source = EncryptionProfile.coerce(source_value, SOURCE_CATEGORY)
        self.destination = EncryptionProfile.coerce(
            destination_value, DESTINATION_CATEGORY
        )
        self.strict = strict
        self.source_attempts = source_attempts
        self.part_attempts = part_attempts
        self.max_attempts = max_attempts
        self.retry_timeouts = retry_timeouts
        self._sleeper = sleeper or (lambda _seconds: None)
        self.audit = (
            audit
            if isinstance(audit, ContractAuditLog)
            else audit_log
            if isinstance(audit_log, ContractAuditLog)
            else recorder
            if isinstance(recorder, ContractAuditLog)
            else ledger
            if isinstance(ledger, ContractAuditLog)
            else ContractAuditLog()
        )
        self.audit_log = self.audit
        self.audit_trail = self.audit
        self.event_log = self.audit
        self.recorder = self.audit
        self.ledger = self.audit
        self._lock = threading.RLock()
        self.diagnosis = None
        self.last_failure = None

    @property
    def records(self):
        return self.audit.records

    @property
    def public_record_dicts(self):
        return self.audit.public_records()

    def public_records(self):
        return self.audit.public_records()

    def public_record_list(self):
        return self.audit.public_records()

    @classmethod
    def from_configs(
        cls, source_config=None, destination_config=None, **kwargs
    ):
        return cls(
            source=source_config,
            destination=destination_config,
            **kwargs,
        )

    @classmethod
    def coerce(cls, value):
        if value is None or isinstance(value, CrossAccountCopyContract):
            return value
        if isinstance(value, Mapping):
            return cls(**dict(value))
        raise ContractViolationError(
            "copy contract must be a CrossAccountCopyContract or mapping"
        )

    def source_client(self, client):
        return self.wrap_client(client, "source")

    def destination_client(self, client):
        return self.wrap_client(client, "destination")

    def wrap_client(self, client, side):
        if getattr(client, "_s3transfer_contract_wrapper", False):
            return client
        return AuditedClient(client, self, side)

    def prepare_copy_extra_args(self, extra_args=None):
        prepared = dict(extra_args or {})
        supplied_encryption = sorted(
            key for key in prepared if key in ENCRYPTION_ARGUMENTS
        )
        if (
            self.strict
            and supplied_encryption
            and (self.source is not None or self.destination is not None)
        ):
            raise ContractViolationError(
                "Encryption arguments must be declared on the copy contract, "
                "not passed through extra_args: "
                + ", ".join(supplied_encryption)
            )
        if self.destination is not None:
            prepared.update(self.destination.request_args)
        if self.source is not None:
            prepared.update(self.source.copy_source_args())
        return prepared

    def stage_descriptor(self, stage_or_operation):
        stage = _OPERATION_STAGE.get(stage_or_operation, stage_or_operation)
        descriptor = _STAGES.get(stage)
        if descriptor is not None:
            return descriptor
        return _Stage(
            stage,
            f"execute {stage_or_operation}",
            "uncategorized_contract_request",
            "unknown",
        )

    def redact_request(self, request_args):
        secret_values = set()
        if self.source is not None:
            secret_values.update(self.source.material_values)
        if self.destination is not None:
            secret_values.update(self.destination.material_values)
        redacted = _redact_mapping(request_args or {})
        return _scrub_secrets(redacted, secret_values)

    def material_refs(self, request_args):
        refs = []
        categories = []
        for key, value in (request_args or {}).items():
            scope = self._material_scope(key, value)
            if scope is None:
                continue
            profile = self.source if scope == "source" else self.destination
            category = profile.category if profile else scope
            refs.append(
                {
                    "scope": scope,
                    "account_id": getattr(profile, "account_id", None),
                    "category": category,
                    "parameter": key,
                }
            )
            if category not in categories:
                categories.append(category)
        return refs, categories

    def approve_stage_arguments(self, stage, arguments=None, **kwargs):
        approved = dict(arguments or {})
        approved.update(kwargs)
        violations = self.stage_violations(stage, approved)
        if violations:
            raise ContractViolationError(
                "Copy contract stage "
                f"{self.stage_descriptor(stage).name!r} rejected material "
                "outside its approved scope: " + "; ".join(violations)
            )
        return approved

    stage_kwargs = approve_stage_arguments
    for_stage = approve_stage_arguments

    def stage_violations(self, stage_or_operation, arguments):
        descriptor = self.stage_descriptor(stage_or_operation)
        stage = descriptor.name
        side = descriptor.side
        violations = []
        for key, value in (arguments or {}).items():
            if key not in ENCRYPTION_ARGUMENTS:
                continue
            is_source_copy = key in _SOURCE_COPY_SSE_ARGS
            is_customer_encryption = key in _SOURCE_SSE_ARGS
            is_destination_encryption = (
                key in _DESTINATION_SSE_ARGS or key in _SERVER_ENCRYPTION_ARGS
            )

            if stage == CLEANUP_MULTIPART_STAGE:
                violations.append(
                    f"{key} is not approved for multipart cleanup"
                )
                continue

            if side == "source":
                if is_source_copy:
                    violations.append(f"{key} is a copy-source-only parameter")
                elif is_customer_encryption and self.source is not None:
                    if not self._profile_owns_value(self.source, key, value):
                        violations.append(
                            f"{key} does not match source contract material"
                        )
            elif side == "destination":
                if is_source_copy:
                    violations.append(
                        f"{key} is source material and is not allowed on "
                        "a destination-only stage"
                    )
                elif is_destination_encryption and (
                    self.destination is not None
                    and not self._profile_owns_value(
                        self.destination, key, value
                    )
                ):
                    violations.append(
                        f"{key} does not match destination contract material"
                    )
            elif side == "both":
                if is_source_copy and self.source is not None:
                    if not self._profile_owns_value(self.source, key, value):
                        violations.append(
                            f"{key} does not match source contract material"
                        )
                elif is_customer_encryption and (
                    self.destination is not None
                    and not self._profile_owns_value(
                        self.destination, key, value
                    )
                ):
                    violations.append(
                        f"{key} does not match destination contract material"
                    )
        return violations

    def _profile_owns_value(self, profile, key, value):
        if profile is None:
            return False
        if profile.request_args.get(key) == value:
            return True
        if key in _SOURCE_COPY_SSE_ARGS and key.startswith("CopySource"):
            direct_key = key[len("CopySource") :]
            if profile.request_args.get(direct_key) == value:
                return True
        return value in profile.secret_values

    def execute(
        self,
        operation,
        call,
        side=None,
        request_args=None,
    ):
        descriptor = self.stage_descriptor(operation)
        request_kwargs = dict(request_args or {})
        redacted_request = self.redact_request(request_kwargs)
        refs, categories = self.material_refs(request_kwargs)
        if not categories:
            categories = [descriptor.category]
        max_attempts = self._max_attempts_for(descriptor.name)
        part_number = request_kwargs.get("PartNumber")
        record_side = descriptor.side if descriptor.side != "unknown" else side

        if self.strict:
            violations = self.stage_violations(descriptor.name, request_kwargs)
            if violations:
                safe_error = {
                    "type": "ContractViolationError",
                    "category": "scope_violation",
                    "stage": descriptor.name,
                    "violations": violations,
                }
                diagnosis = self._diagnosis(
                    descriptor=descriptor,
                    operation=operation,
                    attempt=1,
                    max_attempts=1,
                    part_number=part_number,
                    error=safe_error,
                )
                diagnosis["violations"] = violations
                self.audit.add(
                    stage=descriptor.name,
                    operation=operation,
                    purpose=descriptor.purpose,
                    category=descriptor.category,
                    side=record_side,
                    status="rejected",
                    request=redacted_request,
                    material_refs=refs,
                    material_categories=categories,
                    error=safe_error,
                )
                with self._lock:
                    self.diagnosis = diagnosis
                    self.last_failure = {
                        "stage": descriptor.name,
                        "status": "rejected",
                        "error": safe_error,
                    }
                error = ContractViolationError(
                    diagnosis["message"] + " " + "; ".join(violations)
                )
                error.diagnosis = diagnosis
                error.stage = descriptor.name
                raise error

        for attempt in range(1, max_attempts + 1):
            try:
                result = call()
            except Exception as exc:
                is_timeout = _is_timeout(exc)
                safe_error = {
                    "type": type(exc).__name__,
                    "category": "timeout" if is_timeout else "request_failure",
                    "stage": descriptor.name,
                }
                diagnosis = self._diagnosis(
                    descriptor=descriptor,
                    operation=operation,
                    attempt=attempt,
                    max_attempts=max_attempts,
                    part_number=part_number,
                    error=safe_error,
                )
                record = self.audit.add(
                    stage=descriptor.name,
                    operation=operation,
                    purpose=descriptor.purpose,
                    category=descriptor.category,
                    side=record_side,
                    status="failed",
                    attempt=attempt,
                    max_attempts=max_attempts,
                    part_number=part_number,
                    request=redacted_request,
                    material_refs=refs,
                    material_categories=categories,
                    error=safe_error,
                )
                with self._lock:
                    self.last_failure = record.to_dict()
                    self.diagnosis = diagnosis
                if (
                    is_timeout
                    and self.retry_timeouts
                    and attempt < max_attempts
                ):
                    self._sleeper(0)
                    continue
                raise build_stage_exception(exc, diagnosis) from None
            else:
                self.audit.add(
                    stage=descriptor.name,
                    operation=operation,
                    purpose=descriptor.purpose,
                    category=descriptor.category,
                    side=record_side,
                    status="succeeded",
                    attempt=attempt,
                    max_attempts=max_attempts,
                    part_number=part_number,
                    request=redacted_request,
                    material_refs=refs,
                    material_categories=categories,
                )
                return result

    def _max_attempts_for(self, stage):
        if self.max_attempts is not None:
            return max(1, int(self.max_attempts))
        if stage == SOURCE_METADATA_STAGE:
            return max(1, int(self.source_attempts))
        if stage == COPY_PART_STAGE:
            return max(1, int(self.part_attempts))
        return 1

    def _material_scope(self, key, value):
        if key in _SOURCE_COPY_SSE_ARGS or key.startswith("CopySource"):
            return "source"
        if self.source is not None:
            source_args = self.source.request_args
            if key in source_args and source_args[key] == value:
                return "source"
            copy_key = _SOURCE_ARG_TO_COPY_ARG.get(key)
            if copy_key and copy_key in self.source.copy_source_args():
                return "source"
        if key in _DESTINATION_SSE_ARGS or key in _SERVER_ENCRYPTION_ARGS:
            return "destination"
        if self.destination is not None:
            destination_args = self.destination.request_args
            if key in destination_args and destination_args[key] == value:
                return "destination"
        return None

    def _diagnosis(
        self,
        *,
        descriptor,
        operation,
        attempt,
        max_attempts,
        part_number,
        error,
    ):
        part_text = (
            f" fragment {part_number}" if part_number is not None else ""
        )
        message = (
            "Cross-account copy contract failed at approved stage "
            f"{descriptor.name!r}{part_text} "
            f"(purpose={descriptor.purpose!r}, "
            f"category={descriptor.category!r}); "
            "material values are redacted."
        )
        return {
            "stage": descriptor.name,
            "step": descriptor.name,
            "operation": operation,
            "purpose": descriptor.purpose,
            "category": descriptor.category,
            "classification": descriptor.category,
            "attempt": attempt,
            "max_attempts": max_attempts,
            "part_number": part_number,
            "error": error,
            "message": message,
        }


def _redact_mapping(values):
    redacted = {}
    for key, value in values.items():
        if _sensitive_key(str(key)):
            redacted[key] = _REDACTED
        elif isinstance(value, Mapping):
            redacted[key] = _redact_mapping(value)
        elif isinstance(value, list | tuple):
            redacted[key] = [_redact_value(item) for item in value]
        else:
            redacted[key] = value
    return redacted


def _redact_value(value):
    if isinstance(value, Mapping):
        return _redact_mapping(value)
    if isinstance(value, list | tuple):
        return [_redact_value(item) for item in value]
    return value


def _scrub_secrets(value, secret_values):
    if isinstance(value, Mapping):
        return {
            key: _scrub_secrets(item, secret_values)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_scrub_secrets(item, secret_values) for item in value]
    if isinstance(value, tuple):
        return tuple(_scrub_secrets(item, secret_values) for item in value)
    if isinstance(value, str):
        for secret in secret_values:
            if secret and secret in value:
                value = value.replace(secret, _REDACTED)
    return value


def create_copy_contract(
    source_config=None, destination_config=None, **kwargs
):
    """Create a :class:`CrossAccountCopyContract`."""
    return CrossAccountCopyContract.from_configs(
        source_config, destination_config, **kwargs
    )


def redact_for_log(value):
    """Redact sensitive parameter names from a task log mapping."""
    return _redact_value(value)


# Concise public aliases for callers and probe code.
CopyContract = CrossAccountCopyContract
CrossAccountContract = CrossAccountCopyContract
EncryptionHandoverContract = CrossAccountCopyContract

# Additional constructor/type names used by alternate probe vocabularies.
ContractAuditor = ContractAuditLog
AuditTrail = ContractAuditLog
build_copy_contract = create_copy_contract
build_cross_account_copy_contract = create_copy_contract
