"""
Contract PDF merge service with strict, three-stage authorization.

Strict mode distinguishes three separate decisions:

1. VIEW    -- the password can open (decrypt) the document at all.
2. MERGE   -- the *granted permissions* allow taking pages out of the
              document (EXTRACT + ASSEMBLE_DOC). Opening a file with its
              user password does NOT imply this.
3. EXPORT  -- the merged output must satisfy its own encryption policy
              (its own user/owner passwords and permission flags), which
              is independent of every input's policy.

Authorization for every input is completed BEFORE the output file is
opened, so a permission failure never leaves a partial artifact behind.
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field
from pathlib import Path

from pypdf import PdfReader, PdfWriter
from pypdf._encryption import PasswordType
from pypdf.constants import UserAccessPermissions
from pypdf.errors import PdfReadError

#: Permissions an input must grant before its pages may be merged out.
REQUIRED_MERGE_PERMISSIONS = (
    UserAccessPermissions.EXTRACT | UserAccessPermissions.ASSEMBLE_DOC
)


class AuthorizationError(Exception):
    """Raised when a document may not be used for the requested purpose."""


@dataclass(frozen=True)
class Grant:
    """Record of a single authorization decision (the audit evidence)."""

    path: str
    purpose: str  # "view" or "merge"
    password_type: str  # "owner" / "user" / "none"
    granted: bool
    reason: str


@dataclass(frozen=True)
class OutputPolicy:
    """Encryption policy applied to the merged output, on its own terms."""

    user_password: str
    owner_password: str
    permissions: UserAccessPermissions
    algorithm: str = "AES-256"


@dataclass
class MergeReceipt:
    """What actually happened, suitable for a delivery report."""

    merged_sources: list[str] = field(default_factory=list)
    page_counts: dict[str, int] = field(default_factory=dict)
    total_pages: int = 0
    output_path: str | None = None
    output_user_password: str | None = None
    output_permissions: dict[str, bool] = field(default_factory=dict)
    grants: list[Grant] = field(default_factory=list)


def _open_and_decrypt(path: str | Path, password: str) -> tuple[PdfReader, PasswordType]:
    reader = PdfReader(str(path), strict=True)
    if reader.is_encrypted:
        password_type = reader.decrypt(password)
        if password_type == PasswordType.NOT_DECRYPTED:
            raise AuthorizationError(
                f"{path}: password cannot open the document (view denied)"
            )
    else:
        password_type = PasswordType.OWNER_PASSWORD  # nothing to restrict
    return reader, password_type


def _effective_permissions(reader: PdfReader, password_type: PasswordType) -> UserAccessPermissions:
    """Permissions actually granted to this session, in strict mode."""
    if password_type == PasswordType.OWNER_PASSWORD:
        # The owner password authenticates full control over the document.
        return UserAccessPermissions.all()
    if reader.are_permissions_valid is False:
        # AES-256 /Perms integrity check failed: the /P flags may have been
        # tampered with, so in strict mode they cannot be trusted at all.
        raise AuthorizationError(
            "permission flags failed the /Perms integrity check; "
            "refusing to rely on them"
        )
    return reader.user_access_permissions or UserAccessPermissions(0)


def authorize(path: str | Path, password: str, purpose: str) -> tuple[PdfReader, Grant]:
    """
    Authorize one document for one purpose ("view" or "merge").

    Returns the decrypted reader plus the audit grant. Raises
    AuthorizationError if the purpose is not permitted.
    """
    reader, password_type = _open_and_decrypt(path, password)
    permissions = _effective_permissions(reader, password_type)
    kind = "owner" if password_type == PasswordType.OWNER_PASSWORD else "user"

    if purpose == "view":
        grant = Grant(str(path), purpose, kind, True, "password opens the document")
        return reader, grant

    if purpose == "merge":
        missing = REQUIRED_MERGE_PERMISSIONS & ~permissions
        if missing:
            raise AuthorizationError(
                f"{path}: opens fine, but merging is not granted "
                f"(missing: {missing!r})"
            )
        grant = Grant(
            str(path),
            purpose,
            kind,
            True,
            "EXTRACT and ASSEMBLE_DOC granted",
        )
        return reader, grant

    raise ValueError(f"unknown purpose: {purpose!r}")


def merge_contracts(
    inputs: list[tuple[str | Path, str]],
    output_path: str | Path,
    output_policy: OutputPolicy,
) -> MergeReceipt:
    """
    Merge protected contract PDFs into one newly encrypted document.

    Every input is authorized for "merge" BEFORE the output is touched;
    on any failure nothing is written.
    """
    receipt = MergeReceipt()

    # Stage 1+2: authorize every input up front. Nothing is written yet.
    readers: list[PdfReader] = []
    for path, password in inputs:
        reader, grant = authorize(path, password, purpose="merge")
        readers.append(reader)
        receipt.grants.append(grant)
        receipt.merged_sources.append(str(path))
        receipt.page_counts[str(path)] = len(reader.pages)

    # Stage 3: build the merged document in memory only.
    writer = PdfWriter()
    for reader in readers:
        for page in reader.pages:
            writer.add_page(page)

    # The output gets its own policy, unrelated to any input's passwords.
    writer.encrypt(
        user_password=output_policy.user_password,
        owner_password=output_policy.owner_password,
        permissions_flag=output_policy.permissions,
        algorithm=output_policy.algorithm,
    )

    buffer = io.BytesIO()
    writer.write(buffer)

    # Only now, with all authorizations done, does the file appear.
    Path(output_path).write_bytes(buffer.getvalue())

    receipt.total_pages = len(writer.pages)
    receipt.output_path = str(output_path)
    receipt.output_user_password = output_policy.user_password
    receipt.output_permissions = output_policy.permissions.to_dict()
    return receipt
