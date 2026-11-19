from collections.abc import Iterable
from collections.abc import Mapping
from dataclasses import dataclass

from django.core.exceptions import ImproperlyConfigured

OPERATIONS = ("open", "list", "url", "modify")

_READ_ONLY_NAMES = {"read", "read_only", "readonly"}
_FULL_NAMES = {"all", "read_write", "readwrite", "rw"}


@dataclass(frozen=True)
class StorageCapabilities:
    """
    Declarative, opt-in list of the operations a storage alias may perform.

    By default every operation is allowed, so existing configurations keep
    working.  Pass ``capabilities=...`` (or the backend-specific setting) to
    tighten an alias, for example::

        StorageCapabilities.read_only()

    ``open`` covers reading object data and metadata, ``list`` covers
    directory enumeration, ``url`` covers link/presigned URL generation, and
    ``modify`` covers saving, deleting and presigned upload URLs.
    """

    open: bool = True
    list: bool = True
    url: bool = True
    modify: bool = True

    @classmethod
    def all(cls):
        return cls()

    @classmethod
    def read_only(cls):
        """Allow reading, listing and link generation but no modification."""
        return cls(modify=False)

    @classmethod
    def from_value(cls, value):
        """
        Coerce ``value`` into a ``StorageCapabilities`` instance.

        Accepted forms are an instance, a preset string (``"all"`` or
        ``"read_only"``), an iterable of allowed operation names, or a mapping
        of operation names to booleans.
        """
        if value is None:
            return cls()
        if isinstance(value, cls):
            return value

        if isinstance(value, str):
            key = value.strip().lower().replace("-", "_")
            if key in _READ_ONLY_NAMES:
                return cls.read_only()
            if key in _FULL_NAMES:
                return cls()
            value = [part.strip() for part in value.split(",") if part.strip()]

        if isinstance(value, Mapping):
            unknown = set(value) - set(OPERATIONS)
            if unknown:
                raise ImproperlyConfigured(
                    "Unknown storage capability(ies): {}.".format(
                        ", ".join(sorted(unknown))
                    )
                )
            return cls(**{name: bool(value.get(name, True)) for name in OPERATIONS})

        if isinstance(value, Iterable):
            allowed = set(value)
            unknown = allowed - set(OPERATIONS)
            if unknown:
                raise ImproperlyConfigured(
                    "Unknown storage capability(ies): {}.".format(
                        ", ".join(sorted(unknown))
                    )
                )
            return cls(**{name: name in allowed for name in OPERATIONS})

        raise ImproperlyConfigured(
            "Invalid storage capabilities declaration: {!r}.".format(value)
        )

    def allows(self, operation):
        if operation not in OPERATIONS:
            raise ValueError("Unknown storage operation: %s" % operation)
        return getattr(self, operation)

    def deconstruct(self):
        """Allow storages configured with capabilities to be serialized."""
        return (
            "{}.{}".format(self.__class__.__module__, self.__class__.__qualname__),
            (),
            {name: getattr(self, name) for name in OPERATIONS},
        )
