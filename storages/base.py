from django.core.exceptions import ImproperlyConfigured
from django.core.files.storage import Storage

from storages.utils import is_within_root
from storages.utils import validate_relative_name


class BaseStorage(Storage):
    def __init__(self, **settings):
        default_settings = self.get_default_settings()

        for name, value in default_settings.items():
            if not hasattr(self, name):
                setattr(self, name, value)

        for name, value in settings.items():
            if name not in default_settings:
                raise ImproperlyConfigured(
                    "Invalid setting '{}' for {}".format(
                        name,
                        self.__class__.__name__,
                    )
                )
            setattr(self, name, value)

    def get_default_settings(self):
        return {}

    def _normalize_name(self, name):
        """
        Validate a caller-provided name against the root-directory contract
        and return it joined to the storage root (``self.location``).
        """
        return validate_relative_name(name, self.location)

    def _is_within_root(self, name):
        """
        Check a backend-provided name against the root-directory contract,
        e.g. to keep adjacent namespaces out of listing results.
        """
        return is_within_root(name, self.location)
