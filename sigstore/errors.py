# Copyright 2023 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Exceptions.
"""

import sys
from enum import StrEnum
from logging import Logger
from typing import NoReturn

from tuf.api import exceptions


class BundleErrorCategory(StrEnum):
    """
    Stable, machine-readable categories for bundle ingestion and
    verification failures.

    The category is attached to the exception at the point where the failure
    is detected, so consumers never have to infer it from error text.
    """

    #: The bundle is well-formed but is missing evidence (a certificate,
    #: transparency log entry, inclusion proof, signed time, ...). The party
    #: that produced the artifact must supply the missing material.
    MISSING_MATERIAL = "missing_material"

    #: The bundle uses a valid format or version that this client does not
    #: support. The client runtime needs to be upgraded.
    UNSUPPORTED_CLIENT = "unsupported_client"

    #: The bundle is malformed in a way that is neither a missing piece of
    #: evidence nor a newer supported format (for example, invalid field
    #: types, conflicting oneof fields, or corrupt DER).
    MALFORMED = "malformed"

    # Aliases keep the API forgiving for callers that use different wording.
    MISSING_EVIDENCE = "missing_material"
    UNSUPPORTED_VERSION = "unsupported_client"
    CLIENT_UPGRADE_REQUIRED = "unsupported_client"

    @property
    def remediation(self) -> str:
        """
        Returns the team responsible for handling this category of failure.
        """
        if self is BundleErrorCategory.MISSING_MATERIAL:
            return "publisher"
        if self is BundleErrorCategory.UNSUPPORTED_CLIENT:
            return "platform"
        return "publisher"


# Convenience aliases: the category is used outside bundle parsing as well.
FailureCategory = BundleErrorCategory
BundleFailureCategory = BundleErrorCategory


class Error(Exception):
    """Base sigstore exception type. Defines helpers for diagnostics."""

    #: Optional structured category for failures that can be routed
    #: automatically. `None` means the failure has not been classified.
    category: BundleErrorCategory | None = None

    def __init__(
        self,
        *args: object,
        category: BundleErrorCategory | str | None = None,
    ):
        """Constructs an error, optionally with a structured category."""
        super().__init__(*args)
        if category is not None:
            self.category = BundleErrorCategory(category)

    @property
    def actionable(self) -> bool:
        """
        Returns whether the error has a known handling target.
        """
        return self.category is not None

    @property
    def remediation(self) -> str | None:
        """
        Returns the handling target for this error, if it is classified.

        This is `"publisher"` for missing material (the publisher must supply
        it) and `"platform"` for an unsupported client format (the runtime
        must be upgraded).
        """
        return self.category.remediation if self.category is not None else None

    def diagnostics(self) -> str:
        """Returns human-friendly error information."""

        return str(self)

    def log_and_exit(self, logger: Logger, raise_error: bool = False) -> NoReturn:
        """Prints all relevant error information to stderr and exits."""

        remind_verbose = (
            "Raising original exception:"
            if raise_error
            else "For detailed error information, run sigstore with the `--verbose` flag."
        )

        logger.error(f"{self.diagnostics()}\n{remind_verbose}")

        if raise_error:
            # don't want "during handling another exception"
            self.__suppress_context__ = True
            raise self

        sys.exit(1)


class NetworkError(Error):
    """Raised when a connectivity-related issue occurs."""

    def diagnostics(self) -> str:
        """Returns diagnostics for the error."""
        return self._diagnostics(str(self.__cause__))

    @staticmethod
    def _diagnostics(cause: str | None) -> str:
        cause_ctx = f"\n\nAdditional context:\n\n{cause}" if cause else ""

        return (
            "A network issue occurred.\n\n"
            "Check your internet connection and try again." + cause_ctx
        )


class TUFError(Error):
    """Raised when a TUF error occurs."""

    def __init__(self, message: str):
        """Constructs a `TUFError`."""
        super().__init__(message)
        self.message = message

    def diagnostics(self) -> str:
        """Returns diagnostics specialized to the wrapped TUF error."""
        # Download errors are likely to be ephemeral: just use NetworkError output
        if isinstance(self.__cause__, exceptions.DownloadError):
            return NetworkError._diagnostics(f"{self.message}: {self.__cause__}")

        # Other TUF errors are likely to be cryptic and unrecoverable
        cause_ctx = (
            f"\n\nAdditional context:\n\n{self.__cause__}" if self.__cause__ else ""
        )
        return (
            f"{self.message}.\n\n"
            "Please check any Sigstore instance related arguments and consider "
            "reporting the issue at <https://github.com/sigstore/sigstore-python/issues/new>."
            + cause_ctx
        )


class MetadataError(Error):
    """Raised when TUF metadata does not conform to the expected structure."""

    def diagnostics(self) -> str:
        """Returns diagnostics for the error."""
        return f"""{self}."""


class RootError(Error):
    """Raised when TUF cannot establish its root of trust."""

    def diagnostics(self) -> str:
        """Returns diagnostics for the error."""
        return (
            "Unable to establish root of trust.\n\n"
            "This error may occur when the resources embedded in this "
            "distribution of sigstore-python are out of date."
        )


class VerificationError(Error):
    """
    Raised whenever any phase or subcomponent of Sigstore verification fails.

    Like `Error`, instances may carry a structured `category` when the failure
    can be classified (for example, because the bundle is missing evidence or
    because it uses a format this client does not support).
    """


class MissingVerificationMaterial(VerificationError):
    """
    Raised when verification cannot proceed because the bundle is missing
    required evidence.

    The bundle was well-formed enough to parse, but it does not carry
    material (signed time, a message signature, a DSSE envelope, ...) that the
    publisher must supply.
    """

    category = BundleErrorCategory.MISSING_MATERIAL

    def __init__(self, *args: object):
        """Constructs a `MissingVerificationMaterial`."""
        super().__init__(*args, category=BundleErrorCategory.MISSING_MATERIAL)


class UnsupportedVerificationVersion(VerificationError):
    """
    Raised when verification encounters a valid bundle/log-entry format that
    this client does not support.

    The client runtime must be upgraded.
    """

    category = BundleErrorCategory.UNSUPPORTED_CLIENT

    def __init__(self, *args: object):
        """Constructs an `UnsupportedVerificationVersion`."""
        super().__init__(*args, category=BundleErrorCategory.UNSUPPORTED_CLIENT)


# Spellings that callers commonly reach for.
MissingMaterialError = MissingVerificationMaterial
UnsupportedClientError = UnsupportedVerificationVersion
ClientUpgradeRequired = UnsupportedVerificationVersion


def error_category(exc: BaseException) -> BundleErrorCategory | None:
    """
    Returns the structured category of `exc`, if it has one.

    This looks at the exception and its cause chain, so a generic wrapper
    around a categorized failure still reports the underlying category.
    """
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        category = getattr(current, "category", None)
        if category is not None:
            try:
                return BundleErrorCategory(category)
            except ValueError:
                return None
        current = current.__cause__ or current.__context__
    return None


# Category lookup is also exposed under a bundle-specific name.
bundle_error_category = error_category


class CertValidationError(VerificationError):
    """
    Raised when a TSA certificate chain fails to validate during Sigstore verification.

    This is used by CLI to hint that an incorrect Sigstore instance may have been used
    """
