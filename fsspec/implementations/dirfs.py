from .. import filesystem
from ..asyn import AsyncFileSystem
from ..dircache import DirCache
from ..utils import stringify_path
from .chained import ChainedFileSystem
from .local import LocalFileSystem


def _escapes_root(path):
    """Whether a relative path would resolve above its root via ".." segments."""
    depth = 0
    for part in path.split("/"):
        if part == "..":
            depth -= 1
            if depth < 0:
                return True
        elif part and part != ".":
            depth += 1
    return False


class DirFileSystem(AsyncFileSystem, ChainedFileSystem):
    """Directory prefix filesystem

    The DirFileSystem is a filesystem-wrapper. It assumes every path it is dealing with
    is relative to the `path`. After performing the necessary paths operation it
    delegates everything to the wrapped filesystem.
    """

    protocol = "dir"

    def __init__(
        self,
        path=None,
        fs=None,
        fo=None,
        target_protocol=None,
        target_options=None,
        **storage_options,
    ):
        """
        Parameters
        ----------
        path: str
            Path to the directory.
        fs: AbstractFileSystem
            An instantiated filesystem to wrap.
        target_protocol, target_options:
            if fs is none, construct it from these
        fo: str
            Alternate for path; do not provide both
        """
        super().__init__(**storage_options)
        if fs is None:
            # Pass the listing-cache policy on to an instance this wrapper
            # creates, so the underlying filesystem does not keep broader
            # records than the wrapper is allowed to retain.
            target_options = dict(target_options or {})
            for name in (
                "use_listings_cache",
                "listings_expiry_time",
                "max_paths",
                "fields",
            ):
                if name not in target_options and storage_options.get(name) is not None:
                    target_options[name] = storage_options[name]
            fs = filesystem(protocol=target_protocol, **target_options)
        path = path or fo

        if self.asynchronous and not fs.async_impl:
            raise ValueError("can't use asynchronous with non-async fs")

        if fs.async_impl and self.asynchronous != fs.asynchronous:
            raise ValueError("both dirfs and fs should be in the same sync/async mode")

        self.path = fs._strip_protocol(path)
        self.fs = fs
        self.async_impl = fs.async_impl

        # A shared instance can outlive this wrapper, so its own listing cache
        # must obey the same retention policy. Narrowing an already-shared
        # cache is fail-closed and safe; widening it would not be, so a cache
        # that is already narrower is left alone.
        backend_cache = getattr(fs, "dircache", None)
        if self.dircache.fields is not None and isinstance(backend_cache, DirCache):
            backend_cache.fields = self._narrow_fields(
                backend_cache.fields, self.dircache.fields
            )

    @staticmethod
    def _narrow_fields(current, new):
        """Return a retention policy no broader than either argument."""
        if current is None:
            return new
        if new is None:
            return current
        return tuple(field for field in current if field in new)

    @property
    def _root(self):
        return self._cache_key(self.path)

    def _cache_key(self, backend_path):
        """Normalise a backend path for this wrapper's own directory cache."""
        if not backend_path:
            return ""
        return stringify_path(self.fs._strip_protocol(backend_path)).rstrip(self.fs.sep)

    def _backend_path(self, path):
        """Resolve either spelling of a path to the wrapped path space.

        Callers may name a path relative to the wrapper root (the usual
        form), or use the wrapped filesystem's own name for the same object
        (as listings and ``info`` return it). Both must update and invalidate
        the same cache entry.
        """
        path = self._strip_protocol(stringify_path(path))
        root = self._root
        if not path:
            return self.path
        if not root:
            # An unrooted wrapper shares the wrapped filesystem's path space.
            return path
        if path == root:
            return self.path
        sep = self.fs.sep
        prefix = root if root.endswith(sep) else root + sep
        if path.startswith(prefix):
            return path
        # Backend names may omit a leading separator that the root carries.
        if root.startswith(sep) and not path.startswith(sep):
            stripped = root.lstrip(sep)
            if path == stripped or path.startswith(stripped + sep):
                return root + path[len(stripped) :]
        return self._join(path)

    def _ls_from_cache(self, path):
        """Check this wrapper's cache for a listing, translating aliases.

        The wrapper and the wrapped filesystem may spell the same path
        differently, so both spellings address the same entry.
        """
        backend = self._backend_path(path)
        key = self._cache_key(backend)
        try:
            entries = self.dircache[key]
        except KeyError:
            pass
        else:
            return self._relative_entries(entries, self._relpath)

        parent = self._cache_key(self.fs._parent(backend))
        try:
            entries = self.dircache[parent]
        except KeyError:
            return None
        matches = [entry for entry in entries if self._cache_key(entry["name"]) == key]
        if matches:
            return self._relative_entries(matches, self._relpath)
        raise FileNotFoundError(path)

    def _cache_after_mutation(self, *paths):
        """Drop this wrapper's cached listings affected by a write."""
        flat = []
        for path in paths:
            if isinstance(path, dict):
                flat.extend(path)
            elif isinstance(path, (list, tuple)):
                flat.extend(path)
            else:
                flat.append(path)
        for path in flat:
            self._drop_cached(self._join(path))

    def _drop_cached(self, backend_path):
        """Drop cached listings for a backend path, its parent and its subtree.

        A changed object also changes the listing that contains it, so the
        parent entry must be refreshed rather than served from the cache.
        """
        key = self._cache_key(backend_path)
        sep = self.fs.sep
        prefix = key + sep
        drop = {key}
        parent = key.rsplit(sep, 1)[0] if sep in key else ""
        root = self._root
        if parent and (not root or parent == root or parent.startswith(root + sep)):
            drop.add(parent)
        for cached in list(self.dircache):
            if cached in drop or cached.startswith(prefix):
                self.dircache.pop(cached, None)

    def _join(self, path):
        path = stringify_path(path)
        if isinstance(path, str):
            if not self.path:
                return path
            if not path:
                return self.path
            # a trailing slash requests "copy the contents" in bulk
            # operations (docs/source/copying.rst), so preserve it across the
            # join even though _strip_protocol removes it
            suffix = "/" if path.endswith("/") else ""
            path = self._strip_protocol(path)
            # ".." only navigates above the root on filesystems that resolve it
            # against a real directory tree; on object stores it is a literal
            # path part, so only guard the local case here.
            if isinstance(self.fs, LocalFileSystem) and _escapes_root(path):
                raise ValueError(
                    f"path {path!r} escapes the {self.path!r} root of the filesystem"
                )
            joined = self.fs.sep.join((self.path, path))
            if suffix and not joined.endswith("/"):
                joined += "/"
            return joined
        if isinstance(path, dict):
            return {self._join(_path): value for _path, value in path.items()}
        return [self._join(_path) for _path in path]

    def _relpath(self, path):
        if isinstance(path, str):
            if not self.path:
                return path
            # We need to account for S3FileSystem returning paths that do not
            # start with a '/'
            if path == self.path or (
                self.path.startswith(self.fs.sep) and path == self.path[1:]
            ):
                return ""
            prefix = self.path + self.fs.sep
            if self.path.startswith(self.fs.sep) and not path.startswith(self.fs.sep):
                prefix = prefix[1:]
            assert path.startswith(prefix)
            return path[len(prefix) :]
        return [self._relpath(_path) for _path in path]

    def _relpath_detail(self, paths):
        out = {}
        for path, info in paths.items():
            path = self._relpath(path)
            info = info.copy()
            info["name"] = path
            out[path] = info
        return out

    # Wrappers below

    @property
    def sep(self):
        return self.fs.sep

    @property
    def local_file(self):
        return getattr(self.fs, "local_file", False)

    async def set_session(self, *args, **kwargs):
        return await self.fs.set_session(*args, **kwargs)

    async def _rm_file(self, path, **kwargs):
        ret = await self.fs._rm_file(self._join(path), **kwargs)
        self._cache_after_mutation(path)
        return ret

    def rm_file(self, path, **kwargs):
        ret = self.fs.rm_file(self._join(path), **kwargs)
        self._cache_after_mutation(path)
        return ret

    async def _rm(self, path, *args, **kwargs):
        ret = await self.fs._rm(self._join(path), *args, **kwargs)
        self._cache_after_mutation(path)
        return ret

    def rm(self, path, *args, **kwargs):
        ret = self.fs.rm(self._join(path), *args, **kwargs)
        self._cache_after_mutation(path)
        return ret

    def delete(self, path, recursive=False, maxdepth=None):
        ret = self.fs.delete(self._join(path), recursive=recursive, maxdepth=maxdepth)
        self._cache_after_mutation(path)
        return ret

    async def _cp_file(self, path1, path2, **kwargs):
        ret = await self.fs._cp_file(self._join(path1), self._join(path2), **kwargs)
        self._cache_after_mutation(path2)
        return ret

    def cp_file(self, path1, path2, **kwargs):
        ret = self.fs.cp_file(self._join(path1), self._join(path2), **kwargs)
        self._cache_after_mutation(path2)
        return ret

    async def _copy(
        self,
        path1,
        path2,
        *args,
        **kwargs,
    ):
        ret = await self.fs._copy(
            self._join(path1),
            self._join(path2),
            *args,
            **kwargs,
        )
        self._cache_after_mutation(path2)
        return ret

    def copy(self, path1, path2, *args, **kwargs):
        ret = self.fs.copy(
            self._join(path1),
            self._join(path2),
            *args,
            **kwargs,
        )
        self._cache_after_mutation(path2)
        return ret

    async def _pipe(self, path, *args, **kwargs):
        ret = await self.fs._pipe(self._join(path), *args, **kwargs)
        self._cache_after_mutation(path)
        return ret

    def pipe(self, path, *args, **kwargs):
        ret = self.fs.pipe(self._join(path), *args, **kwargs)
        self._cache_after_mutation(path)
        return ret

    async def _pipe_file(self, path, *args, **kwargs):
        ret = await self.fs._pipe_file(self._join(path), *args, **kwargs)
        self._cache_after_mutation(path)
        return ret

    def pipe_file(self, path, *args, **kwargs):
        ret = self.fs.pipe_file(self._join(path), *args, **kwargs)
        self._cache_after_mutation(path)
        return ret

    def write_text(
        self, path, value, encoding=None, errors=None, newline=None, **kwargs
    ):
        ret = self.fs.write_text(
            self._join(path),
            value,
            encoding=encoding,
            errors=errors,
            newline=newline,
            **kwargs,
        )
        self._cache_after_mutation(path)
        return ret

    async def _cat_file(self, path, *args, **kwargs):
        return await self.fs._cat_file(self._join(path), *args, **kwargs)

    def cat_file(self, path, *args, **kwargs):
        return self.fs.cat_file(self._join(path), *args, **kwargs)

    async def _cat(self, path, *args, **kwargs):
        ret = await self.fs._cat(
            self._join(path),
            *args,
            **kwargs,
        )

        if isinstance(ret, dict):
            return {self._relpath(key): value for key, value in ret.items()}

        return ret

    def cat(self, path, *args, **kwargs):
        ret = self.fs.cat(
            self._join(path),
            *args,
            **kwargs,
        )

        if isinstance(ret, dict):
            return {self._relpath(key): value for key, value in ret.items()}

        return ret

    async def _cat_ranges(self, paths, starts, ends, *args, **kwargs):
        return await self.fs._cat_ranges(
            self._join(paths), starts, ends, *args, **kwargs
        )

    def cat_ranges(self, paths, starts, ends, *args, **kwargs):
        return self.fs.cat_ranges(self._join(paths), starts, ends, *args, **kwargs)

    async def _put_file(self, lpath, rpath, **kwargs):
        return await self.fs._put_file(lpath, self._join(rpath), **kwargs)

    def put_file(self, lpath, rpath, **kwargs):
        return self.fs.put_file(lpath, self._join(rpath), **kwargs)

    async def _put(
        self,
        lpath,
        rpath,
        *args,
        **kwargs,
    ):
        return await self.fs._put(
            lpath,
            self._join(rpath),
            *args,
            **kwargs,
        )

    def put(self, lpath, rpath, *args, **kwargs):
        return self.fs.put(
            lpath,
            self._join(rpath),
            *args,
            **kwargs,
        )

    async def _get_file(self, rpath, lpath, **kwargs):
        return await self.fs._get_file(self._join(rpath), lpath, **kwargs)

    def get_file(self, rpath, lpath, **kwargs):
        return self.fs.get_file(self._join(rpath), lpath, **kwargs)

    async def _get(self, rpath, *args, **kwargs):
        return await self.fs._get(self._join(rpath), *args, **kwargs)

    def get(self, rpath, *args, **kwargs):
        return self.fs.get(self._join(rpath), *args, **kwargs)

    async def _isfile(self, path):
        return await self.fs._isfile(self._join(path))

    def isfile(self, path):
        return self.fs.isfile(self._join(path))

    async def _isdir(self, path):
        return await self.fs._isdir(self._join(path))

    def isdir(self, path):
        return self.fs.isdir(self._join(path))

    async def _size(self, path):
        return await self.fs._size(self._join(path))

    def size(self, path):
        return self.fs.size(self._join(path))

    async def _sizes(self, paths):
        return await self.fs._sizes(self._join(paths))

    def sizes(self, paths):
        return self.fs.sizes(self._join(paths))

    def invalidate_cache(self, path=None):
        # With no path, clear only what is cached under this directory. An
        # unrooted dirfs joins to "", which means everything on the wrapped fs.
        if path is None:
            backend_path = self._join("") or None
            self.dircache.clear()
        else:
            backend_path = self._backend_path(path)
            self._drop_cached(backend_path)
        self.fs.invalidate_cache(backend_path)

    def ukey(self, path):
        return self.fs.ukey(self._join(path))

    def checksum(self, path):
        return self.fs.checksum(self._join(path))

    async def _exists(self, path):
        return await self.fs._exists(self._join(path))

    def exists(self, path):
        return self.fs.exists(self._join(path))

    async def _info(self, path, **kwargs):
        info = await self.fs._info(self._join(path), **kwargs)
        info = info.copy()
        info["name"] = self._relpath(info["name"])
        return info

    def info(self, path, **kwargs):
        info = self.fs.info(self._join(path), **kwargs)
        info = info.copy()
        info["name"] = self._relpath(info["name"])
        return info

    @staticmethod
    def _relative_entries(entries, relpath):
        out = []
        for entry in entries:
            entry = entry.copy()
            entry["name"] = relpath(entry["name"])
            out.append(entry)
        return out

    def _cache_listings(self):
        """Whether the wrapper keeps its own listings.

        Without a retention policy the wrapper stays a pass-through and lets
        the wrapped filesystem decide about caching, as before.
        """
        return self.dircache.fields is not None

    async def _ls(self, path, detail=True, refresh=None, **kwargs):
        backend_path = self._join(path)
        key = self._cache_key(backend_path)
        cached = None
        if self._cache_listings() and refresh is not True:
            cached = self.dircache.get(key)
        if cached is not None:
            if detail:
                return self._relative_entries(cached, self._relpath)
            return sorted(self._relpath(entry["name"]) for entry in cached)

        call_kwargs = kwargs
        if refresh is not None:
            call_kwargs = {**kwargs, "refresh": refresh}
        if self._cache_listings() and not detail:
            # Populate the approved record once, then answer names from it.
            ret = (await self.fs._ls(backend_path, detail=True, **call_kwargs)).copy()
            self.dircache[key] = [entry.copy() for entry in ret]
            return sorted(self._relpath(entry["name"]) for entry in ret)

        ret = (await self.fs._ls(backend_path, detail=detail, **call_kwargs)).copy()
        if detail:
            # The cache stores the wrapped filesystem's own names and applies
            # the configured field-retention policy, so a full source record
            # cannot widen what is retained; the reply is still translated to
            # wrapper-relative names.
            if self._cache_listings():
                self.dircache[key] = [entry.copy() for entry in ret]
            return self._relative_entries(ret, self._relpath)

        return self._relpath(ret)

    def ls(self, path, detail=True, refresh=None, **kwargs):
        backend_path = self._join(path)
        key = self._cache_key(backend_path)
        cached = None
        if self._cache_listings() and refresh is not True:
            cached = self.dircache.get(key)
        if cached is not None:
            if detail:
                return self._relative_entries(cached, self._relpath)
            return sorted(self._relpath(entry["name"]) for entry in cached)

        call_kwargs = kwargs
        if refresh is not None:
            call_kwargs = {**kwargs, "refresh": refresh}
        if self._cache_listings() and not detail:
            ret = self.fs.ls(backend_path, detail=True, **call_kwargs).copy()
            self.dircache[key] = [entry.copy() for entry in ret]
            return sorted(self._relpath(entry["name"]) for entry in ret)

        ret = self.fs.ls(backend_path, detail=detail, **call_kwargs).copy()
        if detail:
            if self._cache_listings():
                self.dircache[key] = [entry.copy() for entry in ret]
            return self._relative_entries(ret, self._relpath)

        return self._relpath(ret)

    def _relpath_walk_entries(self, entries):
        # with detail=True, walk gives dicts keyed by basename whose infos
        # still carry the full name in the wrapped filesystem
        if not isinstance(entries, dict):
            return entries
        # Keep the mapping so callers can prune the wrapped walk in place.
        for name, info in entries.items():
            entries[name] = {**info, "name": self._relpath(info["name"])}
        return entries

    async def _walk(self, path, *args, **kwargs):
        async for root, dirs, files in self.fs._walk(self._join(path), *args, **kwargs):
            yield (
                self._relpath(root),
                self._relpath_walk_entries(dirs),
                self._relpath_walk_entries(files),
            )

    def walk(self, path, *args, **kwargs):
        for root, dirs, files in self.fs.walk(self._join(path), *args, **kwargs):
            yield (
                self._relpath(root),
                self._relpath_walk_entries(dirs),
                self._relpath_walk_entries(files),
            )

    async def _glob(self, path, **kwargs):
        detail = kwargs.get("detail", False)
        ret = await self.fs._glob(self._join(path), **kwargs)
        if detail:
            return self._relpath_detail(ret)
        return self._relpath(ret)

    def glob(self, path, **kwargs):
        detail = kwargs.get("detail", False)
        ret = self.fs.glob(self._join(path), **kwargs)
        if detail:
            return self._relpath_detail(ret)
        return self._relpath(ret)

    async def _du(self, path, *args, **kwargs):
        total = kwargs.get("total", True)
        ret = await self.fs._du(self._join(path), *args, **kwargs)
        if total:
            return ret

        return {self._relpath(path): size for path, size in ret.items()}

    def du(self, path, *args, **kwargs):
        total = kwargs.get("total", True)
        ret = self.fs.du(self._join(path), *args, **kwargs)
        if total:
            return ret

        return {self._relpath(path): size for path, size in ret.items()}

    async def _find(self, path, *args, **kwargs):
        detail = kwargs.get("detail", False)
        ret = await self.fs._find(self._join(path), *args, **kwargs)
        if detail:
            return self._relpath_detail(ret)
        return self._relpath(ret)

    def find(self, path, *args, **kwargs):
        detail = kwargs.get("detail", False)
        ret = self.fs.find(self._join(path), *args, **kwargs)
        if detail:
            return self._relpath_detail(ret)
        return self._relpath(ret)

    async def _expand_path(self, path, *args, **kwargs):
        return self._relpath(
            await self.fs._expand_path(self._join(path), *args, **kwargs)
        )

    def expand_path(self, path, *args, **kwargs):
        return self._relpath(self.fs.expand_path(self._join(path), *args, **kwargs))

    async def _mkdir(self, path, *args, **kwargs):
        ret = await self.fs._mkdir(self._join(path), *args, **kwargs)
        self._cache_after_mutation(path)
        return ret

    def mkdir(self, path, *args, **kwargs):
        ret = self.fs.mkdir(self._join(path), *args, **kwargs)
        self._cache_after_mutation(path)
        return ret

    async def _makedirs(self, path, *args, **kwargs):
        ret = await self.fs._makedirs(self._join(path), *args, **kwargs)
        self._cache_after_mutation(path)
        return ret

    def makedirs(self, path, *args, **kwargs):
        ret = self.fs.makedirs(self._join(path), *args, **kwargs)
        self._cache_after_mutation(path)
        return ret

    def rmdir(self, path):
        ret = self.fs.rmdir(self._join(path))
        self._cache_after_mutation(path)
        return ret

    def mv(self, path1, path2, **kwargs):
        ret = self.fs.mv(
            self._join(path1),
            self._join(path2),
            **kwargs,
        )
        self._cache_after_mutation(path1, path2)
        return ret

    def touch(self, path, **kwargs):
        ret = self.fs.touch(self._join(path), **kwargs)
        self._cache_after_mutation(path)
        return ret

    def created(self, path):
        return self.fs.created(self._join(path))

    def modified(self, path):
        return self.fs.modified(self._join(path))

    def sign(self, path, *args, **kwargs):
        return self.fs.sign(self._join(path), *args, **kwargs)

    def __repr__(self):
        return f"{self.__class__.__qualname__}(path='{self.path}', fs={self.fs})"

    def open(
        self,
        path,
        *args,
        **kwargs,
    ):
        return self.fs.open(
            self._join(path),
            *args,
            **kwargs,
        )

    async def open_async(
        self,
        path,
        *args,
        **kwargs,
    ):
        return await self.fs.open_async(
            self._join(path),
            *args,
            **kwargs,
        )
