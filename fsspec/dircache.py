import time
from collections import OrderedDict
from collections.abc import MutableMapping


class DirCache(MutableMapping):
    """
    Caching of directory listings, in a structure like::

        {"path0": [
            {"name": "path0/file0",
             "size": 123,
             "type": "file",
             ...
            },
            {"name": "path0/file1",
            },
            ...
            ],
         "path1": [...]
        }

    Parameters to this class control listing expiry or indeed turn
    caching off. A cache can additionally be restricted to a subset of the
    fields present in each entry; see ``fields``.
    """

    def __init__(
        self,
        use_listings_cache=True,
        listings_expiry_time=None,
        max_paths=None,
        fields=None,
        **kwargs,
    ):
        """
        Parameters
        ----------
        use_listings_cache: bool
            If False, this cache never returns items, but always reports KeyError,
            and setting items has no effect.
        listings_expiry_time: int or float (optional)
            Time in seconds that a listing is considered valid. If None,
            listings do not expire. Time is measured from when the entry was set.
        max_paths: int (optional)
            The maximum number of directory listings to retain in the cache.
            When the cache exceeds this limit, the least recently used
            (set or accessed) listings are evicted. If None, 0, or negative,
            there is no limit.
        fields: iterable of str (optional)
            If given, only these fields are retained from each listing entry.
            ``"name"`` is mandatory because it is how entries are matched in
            the cache. ``None`` (the default) retains every field, which is
            the historical behaviour.

            The policy is applied on every write and every read, so a caller
            that obtains a full record from the backend cannot widen the
            cache by assigning it here. Changing ``fields`` on an existing
            cache also discards fields that are no longer allowed.
        """
        # max_paths is normalized to be either positive or None.
        self.max_paths = max_paths if max_paths and max_paths > 0 else None
        self._cache = OrderedDict() if self.max_paths else {}
        self._times = {}
        self.use_listings_cache = use_listings_cache
        self.listings_expiry_time = listings_expiry_time
        self._fields = self._normalize_fields(fields)

    @staticmethod
    def _normalize_fields(fields):
        if fields is None:
            return None
        if isinstance(fields, str):
            raise TypeError("fields must be an iterable of field names, not a string")
        fields = tuple(fields)
        if not fields:
            raise ValueError("fields must contain at least one field name")
        if not all(isinstance(field, str) for field in fields):
            raise TypeError("field names must be strings")
        if "name" not in fields:
            raise ValueError(
                "the 'name' field must be retained; it identifies cached entries"
            )
        return fields

    @property
    def fields(self):
        """Fields retained in cached entries, or None for all fields."""
        return self._fields

    @fields.setter
    def fields(self, value):
        self._fields = self._normalize_fields(value)
        # Re-project entries created under a previous, possibly broader policy.
        for key in list(self._cache):
            self._cache[key] = self._project(self._cache[key])

    def _project_dict(self, value):
        return {field: value[field] for field in self._fields if field in value}

    def _project(self, value):
        """Return a copy of ``value`` containing only the allowed fields."""
        if self._fields is None:
            return value
        if isinstance(value, dict):
            return self._project_dict(value)
        if isinstance(value, tuple) and len(value) == 2 and isinstance(value[1], dict):
            # Some implementations cache ``(name, details)`` pairs.
            return value[0], self._project_dict(value[1])
        if isinstance(value, list):
            return [self._project(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self._project(item) for item in value)
        return value

    def __getitem__(self, item):
        if not self.use_listings_cache:
            raise KeyError(item)

        if self.listings_expiry_time is not None and item in self._cache:
            if time.time() - self._times.get(item, 0) > self.listings_expiry_time:
                del self[item]
                raise KeyError(item)

        val = self._cache[item]
        if self.max_paths:
            self._cache.move_to_end(item)
        return self._project(val)

    def clear(self):
        self._cache.clear()
        self._times.clear()

    def __len__(self):
        return len(self._cache)

    def __contains__(self, item):
        if not self.use_listings_cache or item not in self._cache:
            return False

        if self.listings_expiry_time is not None:
            if time.time() - self._times.get(item, 0) > self.listings_expiry_time:
                del self[item]
                return False

        return True

    def __setitem__(self, key, value):
        if not self.use_listings_cache:
            return

        # Copy and project, so the cache never keeps a reference to a full
        # record held by the caller.
        self._cache[key] = self._project(value)
        if self.listings_expiry_time is not None:
            self._times[key] = time.time()

        if self.max_paths:
            self._cache.move_to_end(key)
            if len(self._cache) > self.max_paths:
                oldest, _ = self._cache.popitem(last=False)
                self._times.pop(oldest, None)

    def __delitem__(self, key):
        del self._cache[key]
        self._times.pop(key, None)

    def __iter__(self):
        if not self.use_listings_cache:
            return

        if self.listings_expiry_time is None:
            yield from self._cache
            return

        now = time.time()
        for key in list(self._cache):
            if now - self._times.get(key, 0) > self.listings_expiry_time:
                del self[key]
            else:
                yield key

    def __reduce__(self):
        return (
            DirCache,
            (
                self.use_listings_cache,
                self.listings_expiry_time,
                self.max_paths,
                self._fields,
            ),
        )
