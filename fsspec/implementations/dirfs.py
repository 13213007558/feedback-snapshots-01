import os
import posixpath

from .. import filesystem
from ..asyn import AsyncFileSystem
from ..spec import AbstractFileSystem
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


def _uses_local_filesystem(fs):
    """Whether *fs* presents paths from a local filesystem unchanged.

    Only unwrapping layers that forward the same path space (such as
    ``AsyncFileSystemWrapper``) is safe: a nested ``DirFileSystem`` or cache
    reinterprets paths, so the OS-level containment check would compare the
    wrong directory.
    """
    while True:
        if isinstance(fs, LocalFileSystem):
            return True
        inner = getattr(fs, "sync_fs", None)
        if not isinstance(inner, AbstractFileSystem):
            return False
        fs = inner


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
        strict=False,
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
        strict: bool
            If True, treat ``path`` as a hard boundary. Paths are normalized
            before being joined to the root, ``..`` segments that would resolve
            above the root are rejected, and names returned by the wrapped
            filesystem are verified to lie below the root. The check applies to
            single and batch sync/async operations alike.
        """
        super().__init__(**storage_options)
        if fs is None:
            fs = filesystem(protocol=target_protocol, **(target_options or {}))
        if path is None:
            path = "" if fo is None else fo

        if self.asynchronous and not fs.async_impl:
            raise ValueError("can't use asynchronous with non-async fs")

        if fs.async_impl and self.asynchronous != fs.asynchronous:
            raise ValueError("both dirfs and fs should be in the same sync/async mode")

        self.path = fs._strip_protocol(path)
        self.fs = fs
        self.async_impl = fs.async_impl
        self.strict = strict
        self._local = _uses_local_filesystem(fs)

    def _join(self, path):
        path = stringify_path(path)
        if isinstance(path, str):
            # a trailing slash requests "copy the contents" in bulk
            # operations (docs/source/copying.rst), so preserve it across the
            # join even though _strip_protocol removes it
            suffix = "/" if path.endswith("/") else ""
            if self.strict:
                return self._strict_join(path, suffix)
            if not self.path:
                return path
            if not path:
                return self.path
            path = self._strip_protocol(path)
            # ".." only navigates above the root on filesystems that resolve
            # it against a real directory tree; on object stores it is a
            # literal path part, so only guard the local case here.
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

    def _strict_join(self, path, suffix=""):
        normalized = self._strict_relative(path)
        if not normalized:
            joined = self.path
        elif not self.path:
            joined = normalized
        elif self.path == self.fs.sep:
            joined = self.fs.sep + normalized
        else:
            joined = self.path.rstrip(self.fs.sep) + self.fs.sep + normalized
        if suffix and joined and not joined.endswith("/"):
            joined += "/"
        return joined

    def _strict_relative(self, path):
        """Validate and normalize a path relative to the strict root.

        Absolute spellings are accepted only when they point inside the root
        (relative paths returned by listings may be absolute on some
        backends); anything resolving above the root is rejected.
        """
        path = self._strip_protocol(path)
        if path in ("", self.fs.sep):
            return ""
        if path.startswith(self.fs.sep):
            if self.path in ("", self.fs.sep):
                # The view is the backend root, or has no prefix of its own;
                # every absolute spelling is inside.
                path = path.lstrip(self.fs.sep)
            else:
                # Compare after normalizing, so an absolute name that climbs
                # out and re-enters the root ("/root/../root/x") still counts
                # as inside, while one that stays above is rejected.
                path = posixpath.normpath(path)
                root = self.path.rstrip(self.fs.sep)
                if path == root:
                    path = ""
                elif path.startswith(root + self.fs.sep):
                    path = path[len(root) + 1 :]
                else:
                    raise ValueError(
                        f"path {path!r} escapes the {self.path!r} root "
                        "of the filesystem"
                    )
        normalized = posixpath.normpath(path) if path else ""
        if normalized in (".", "/"):
            normalized = ""
        if normalized == ".." or normalized.startswith("../"):
            raise ValueError(
                f"path {path!r} escapes the {self.path!r} root of the filesystem"
            )
        if self._local and normalized:
            root = os.path.realpath(os.path.abspath(self.path))
            target = os.path.realpath(
                os.path.join(root, *normalized.split(self.fs.sep))
            )
            try:
                inside = os.path.commonpath([root, target]) == root
            except ValueError:
                # Different drives on Windows cannot share a common path.
                inside = False
            if not inside:
                raise ValueError(
                    f"path {path!r} escapes the {self.path!r} root of the filesystem"
                )
        return normalized

    def _relpath(self, path):
        if isinstance(path, str):
            if self.strict and self.path in ("", self.fs.sep):
                relative = path.lstrip(self.fs.sep)
                if relative == ".." or relative.startswith("../"):
                    raise ValueError(
                        f"backend path {path!r} lies outside the {self.path!r} "
                        "root of the filesystem"
                    )
                return relative
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
            if not path.startswith(prefix):
                if self.strict:
                    raise ValueError(
                        f"backend path {path!r} lies outside the {self.path!r} "
                        "root of the filesystem"
                    )
                assert path.startswith(prefix)
            relative = path[len(prefix) :]
            if self.strict and (relative == ".." or relative.startswith("../")):
                raise ValueError(
                    f"backend path {path!r} lies outside the {self.path!r} "
                    "root of the filesystem"
                )
            return relative
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
        return await self.fs._rm_file(self._join(path), **kwargs)

    def rm_file(self, path, **kwargs):
        return self.fs.rm_file(self._join(path), **kwargs)

    async def _rm(self, path, *args, **kwargs):
        return await self.fs._rm(self._join(path), *args, **kwargs)

    def rm(self, path, *args, **kwargs):
        return self.fs.rm(self._join(path), *args, **kwargs)

    def delete(self, path, recursive=False, maxdepth=None):
        return self.fs.delete(self._join(path), recursive=recursive, maxdepth=maxdepth)

    async def _cp_file(self, path1, path2, **kwargs):
        return await self.fs._cp_file(self._join(path1), self._join(path2), **kwargs)

    def cp_file(self, path1, path2, **kwargs):
        return self.fs.cp_file(self._join(path1), self._join(path2), **kwargs)

    async def _copy(
        self,
        path1,
        path2,
        *args,
        **kwargs,
    ):
        return await self.fs._copy(
            self._join(path1),
            self._join(path2),
            *args,
            **kwargs,
        )

    def copy(self, path1, path2, *args, **kwargs):
        return self.fs.copy(
            self._join(path1),
            self._join(path2),
            *args,
            **kwargs,
        )

    async def _mv(self, path1, path2, *args, **kwargs):
        # Validate both sides before touching the backend; ``_join`` checks
        # every element of a batch. Prefer the wrapped backend's move so it can
        # keep its native semantics, and fall back to copy-then-delete as
        # ``AbstractFileSystem.mv`` does.
        path1, path2 = self._join(path1), self._join(path2)
        if hasattr(self.fs, "_mv"):
            return await self.fs._mv(path1, path2, *args, **kwargs)
        await self.fs._copy(path1, path2, *args, **kwargs)
        return await self.fs._rm(path1, *args, **kwargs)

    async def _pipe(self, path, *args, **kwargs):
        return await self.fs._pipe(self._join(path), *args, **kwargs)

    def pipe(self, path, *args, **kwargs):
        return self.fs.pipe(self._join(path), *args, **kwargs)

    async def _pipe_file(self, path, *args, **kwargs):
        return await self.fs._pipe_file(self._join(path), *args, **kwargs)

    def pipe_file(self, path, *args, **kwargs):
        return self.fs.pipe_file(self._join(path), *args, **kwargs)

    def write_text(
        self, path, value, encoding=None, errors=None, newline=None, **kwargs
    ):
        return self.fs.write_text(
            self._join(path),
            value,
            encoding=encoding,
            errors=errors,
            newline=newline,
            **kwargs,
        )

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
        self.fs.invalidate_cache(self._join(path or "") or None)

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

    async def _ls(self, path, detail=True, **kwargs):
        ret = (await self.fs._ls(self._join(path), detail=detail, **kwargs)).copy()
        if detail:
            out = []
            for entry in ret:
                entry = entry.copy()
                entry["name"] = self._relpath(entry["name"])
                out.append(entry)
            return out

        return self._relpath(ret)

    def ls(self, path, detail=True, **kwargs):
        ret = self.fs.ls(self._join(path), detail=detail, **kwargs).copy()
        if detail:
            out = []
            for entry in ret:
                entry = entry.copy()
                entry["name"] = self._relpath(entry["name"])
                out.append(entry)
            return out

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
        # Validate before returning the generator, so an out-of-view root is
        # rejected at the call site rather than on the first iteration.
        joined = self._join(path)
        return self._walk_joined(joined, *args, **kwargs)

    def _walk_joined(self, path, *args, **kwargs):
        for root, dirs, files in self.fs.walk(path, *args, **kwargs):
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
        return await self.fs._mkdir(self._join(path), *args, **kwargs)

    def mkdir(self, path, *args, **kwargs):
        return self.fs.mkdir(self._join(path), *args, **kwargs)

    async def _makedirs(self, path, *args, **kwargs):
        return await self.fs._makedirs(self._join(path), *args, **kwargs)

    def makedirs(self, path, *args, **kwargs):
        return self.fs.makedirs(self._join(path), *args, **kwargs)

    def rmdir(self, path):
        return self.fs.rmdir(self._join(path))

    def mv(self, path1, path2, **kwargs):
        return self.fs.mv(
            self._join(path1),
            self._join(path2),
            **kwargs,
        )

    def touch(self, path, **kwargs):
        return self.fs.touch(self._join(path), **kwargs)

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
