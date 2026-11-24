"""Manage several filesystems through a single view.
"""

from __future__ import absolute_import, print_function, unicode_literals

import typing

from collections import OrderedDict, namedtuple
from operator import itemgetter
from six import text_type

from . import errors
from .base import FS
from .mode import check_writable
from .opener import open_fs
from .path import abspath, join, normpath

if typing.TYPE_CHECKING:
    from typing import (
        IO,
        Any,
        BinaryIO,
        Collection,
        FrozenSet,
        Iterator,
        List,
        MutableMapping,
        MutableSet,
        Optional,
        Text,
        Tuple,
    )

    from .enums import ResourceType
    from .info import Info, RawInfo
    from .permissions import Permissions
    from .subfs import SubFS

    M = typing.TypeVar("M", bound="MultiFS")


_PrioritizedFS = namedtuple("_PrioritizedFS", ["priority", "fs"])


class MultiFS(FS):
    """A filesystem that delegates to a sequence of other filesystems.

    Operations on the MultiFS will try each 'child' filesystem in order,
    until it succeeds. In effect, creating a filesystem that combines
    the files and dirs of its children.

    Paths may be *masked* (see `add_mask`). A masked path -- and all of
    its descendants -- is hidden from every read operation on the
    combined filesystem, even if one or more child filesystems still
    contain resources at that path. This allows an upper layer to
    declare that a resource has been withdrawn from publication while
    the lower, archival layers retain their copies.

    If a child filesystem raises an error other than
    `~fs.errors.ResourceNotFound` while it is being consulted, the
    remaining filesystems are still tried but the incomplete result is
    signalled to the caller with `~fs.errors.BackendUnavailable`.

    """

    _meta = {"virtual": True, "read_only": False, "case_insensitive": False}

    def __init__(self, auto_close=True):
        # type: (bool) -> None
        """Create a new MultiFS.

        Arguments:
            auto_close (bool): If `True` (the default), the child
                filesystems will be closed when `MultiFS` is closed.

        """
        super(MultiFS, self).__init__()

        self._auto_close = auto_close
        self.write_fs = None  # type: Optional[FS]
        self._write_fs_name = None  # type: Optional[Text]
        self._sort_index = 0
        self._filesystems = {}  # type: MutableMapping[Text, _PrioritizedFS]
        self._fs_sequence = None  # type: Optional[List[Tuple[Text, FS]]]
        self._masks = set()  # type: MutableSet[Text]
        self._closed = False

    def __repr__(self):
        # type: () -> Text
        if self._auto_close:
            return "MultiFS()"
        else:
            return "MultiFS(auto_close=False)"

    def __str__(self):
        # type: () -> Text
        return "<multifs>"

    def add_fs(self, name, fs, write=False, priority=0):
        # type: (Text, FS, bool, int) -> None
        """Add a filesystem to the MultiFS.

        Arguments:
            name (str): A unique name to refer to the filesystem being
                added.
            fs (FS or str): The filesystem (instance or URL) to add.
            write (bool): If this value is True, then the ``fs`` will
                be used as the writeable FS (defaults to False).
            priority (int): An integer that denotes the priority of the
                filesystem being added. Filesystems will be searched in
                descending priority order and then by the reverse order
                they were added. So by default, the most recently added
                filesystem will be looked at first.

        """
        if isinstance(fs, text_type):
            fs = open_fs(fs)

        if not isinstance(fs, FS):
            raise TypeError("fs argument should be an FS object or FS URL")

        self._filesystems[name] = _PrioritizedFS(
            priority=(priority, self._sort_index), fs=fs
        )
        self._sort_index += 1
        self._resort()

        if write:
            self.write_fs = fs
            self._write_fs_name = name

    def get_fs(self, name):
        # type: (Text) -> FS
        """Get a filesystem from its name.

        Arguments:
            name (str): The name of a filesystem previously added.

        Returns:
            FS: the filesystem added as ``name`` previously.

        Raises:
            KeyError: If no filesystem with given ``name`` could be found.

        """
        return self._filesystems[name].fs

    def _resort(self):
        # type: () -> None
        """Force `iterate_fs` to re-sort on next reference."""
        self._fs_sequence = None

    def iterate_fs(self):
        # type: () -> Iterator[Tuple[Text, FS]]
        """Get iterator that returns (name, fs) in priority order."""
        if self._fs_sequence is None:
            self._fs_sequence = [
                (name, fs)
                for name, (_order, fs) in sorted(
                    self._filesystems.items(), key=itemgetter(1), reverse=True
                )
            ]
        return iter(self._fs_sequence)

    @property
    def masks(self):
        # type: () -> FrozenSet[Text]
        """The paths currently masked from the combined filesystem.

        Returns:
            frozenset: A snapshot of the masked paths, each normalized to
            an absolute path. A mask hides the path itself and all of its
            descendants from read operations.

        """
        return frozenset(self._masks)

    def add_mask(self, path):
        # type: (Text) -> None
        """Mask a path from the combined filesystem.

        A masked resource -- along with everything beneath it -- is no
        longer exposed by `getinfo`, `open`, `scandir`, `listdir` or any
        other read operation, even if it still exists on one or more of
        the child filesystems. The decision is taken at the MultiFS
        level, so it applies to every layer.

        Arguments:
            path (str): A path on the filesystem. Masking a directory
                hides that directory and all of its descendants.

        """
        self._masks.add(abspath(normpath(path)))
        self._resort()

    def remove_mask(self, path):
        # type: (Text) -> None
        """Remove a mask previously added with `add_mask`.

        Arguments:
            path (str): A path previously passed to `add_mask`.

        Raises:
            KeyError: If ``path`` is not currently masked.

        """
        self._masks.remove(abspath(normpath(path)))
        self._resort()

    def _is_masked(self, path, masks):
        # type: (Text, FrozenSet[Text]) -> bool
        """Check if ``path`` is one of the masked paths or below one."""
        for mask in masks:
            if path == mask or path.startswith(mask.rstrip("/") + "/"):
                return True
        return False

    def _snapshot(self):
        # type: () -> Tuple[List[Tuple[Text, FS]], FrozenSet[Text]]
        """Take a consistent snapshot of the layers and masks.

        Capturing both the ordered child filesystems and the current mask
        set together ensures that a single read, or a single directory
        traversal, observes one explainable configuration even if the
        MultiFS is reconfigured while it is running.

        """
        return list(self.iterate_fs()), self.masks

    def _find_delegate(self, path, sequence=None):
        # type: (Text, Optional[List[Tuple[Text, FS]]]) -> Tuple[Optional[Text], Optional[FS], List[Tuple[Text, Text, Exception]]]  # noqa: E501
        """Find the first reachable layer exposing ``path``.

        Returns a tuple of ``(name, fs, failures)``. ``name`` and ``fs``
        are `None` when no reachable layer exposes the path. ``failures``
        records every ``(name, path, exc)`` for a layer that raised an
        error other than `~fs.errors.ResourceNotFound`, so that callers
        can report an incomplete result rather than silently ignoring a
        backend that was unavailable.

        """
        if sequence is None:
            sequence, _masks = self._snapshot()
        failures = []  # type: List[Tuple[Text, Text, Exception]]
        for name, fs in sequence:
            try:
                if fs.exists(path):
                    return name, fs, failures
            except errors.ResourceNotFound:
                continue
            except errors.ResourceInvalid:
                # A definitive answer about the resource type, not an
                # unavailable backend: let it reach the caller.
                raise
            except errors.FSError as exc:
                failures.append((name, path, exc))
        return None, None, failures

    def _delegate(self, path):
        # type: (Text) -> Optional[FS]
        """Get a filesystem which has a given path."""
        sequence, masks = self._snapshot()
        if self._is_masked(abspath(normpath(path)), masks):
            return None
        _name, fs, failures = self._find_delegate(path, sequence)
        if fs is None and failures:
            raise errors.BackendUnavailable(
                failures, path=abspath(normpath(path))
            )
        return fs

    def _delegate_required(self, path):
        # type: (Text) -> FS
        """Check that there is a filesystem with the given ``path``."""
        fs = self._delegate(path)
        if fs is None:
            raise errors.ResourceNotFound(path)
        return fs

    def _writable_required(self, path):
        # type: (Text) -> FS
        """Check that ``path`` is writeable."""
        if self.write_fs is None:
            raise errors.ResourceReadOnly(path)
        return self.write_fs

    def which(self, path, mode="r"):
        # type: (Text, Text) -> Tuple[Optional[Text], Optional[FS]]
        """Get a tuple of (name, fs) that the given path would map to.

        Arguments:
            path (str): A path on the filesystem.
            mode (str): An `io.open` mode.

        """
        if check_writable(mode):
            return self._write_fs_name, self.write_fs
        sequence, masks = self._snapshot()
        abs_path = abspath(normpath(path))
        if self._is_masked(abs_path, masks):
            return None, None
        name, fs, failures = self._find_delegate(path, sequence)
        if fs is None and failures:
            raise errors.BackendUnavailable(failures, path=abs_path)
        return name, fs

    def close(self):
        # type: () -> None
        self._closed = True
        if self._auto_close:
            try:
                for _order, fs in self._filesystems.values():
                    fs.close()
            finally:
                self._filesystems.clear()
                self._resort()

    def getinfo(self, path, namespaces=None):
        # type: (Text, Optional[Collection[Text]]) -> Info
        self.check()
        namespaces = namespaces or ()
        _path = abspath(normpath(path))
        fs = self._delegate(_path)
        if fs is None:
            raise errors.ResourceNotFound(path)
        info = fs.getinfo(_path, namespaces=namespaces)
        return info

    def listdir(self, path):
        # type: (Text) -> List[Text]
        self.check()
        directory = []
        exists = False
        sequence, masks = self._snapshot()
        abs_path = abspath(normpath(path))
        if self._is_masked(abs_path, masks):
            raise errors.ResourceNotFound(path)
        failures = []  # type: List[Tuple[Text, Text, Exception]]
        for name, _fs in sequence:
            try:
                entries = _fs.listdir(path)
            except errors.ResourceNotFound:
                continue
            except errors.ResourceInvalid:
                raise
            except errors.FSError as exc:
                failures.append((name, abs_path, exc))
                continue
            exists = True
            for entry in entries:
                if not self._is_masked(join(abs_path, entry), masks):
                    directory.append(entry)
        if not exists:
            if failures:
                raise errors.BackendUnavailable(failures, path=abs_path)
            raise errors.ResourceNotFound(path)
        directory = list(OrderedDict.fromkeys(directory))
        if failures:
            raise errors.BackendUnavailable(
                failures, partial=directory, path=abs_path
            )
        return directory

    def makedir(
        self,  # type: M
        path,  # type: Text
        permissions=None,  # type: Optional[Permissions]
        recreate=False,  # type: bool
    ):
        # type: (...) -> SubFS[FS]
        self.check()
        write_fs = self._writable_required(path)
        return write_fs.makedir(path, permissions=permissions, recreate=recreate)

    def openbin(self, path, mode="r", buffering=-1, **options):
        # type: (Text, Text, int, **Any) -> BinaryIO
        self.check()
        if check_writable(mode):
            _fs = self._writable_required(path)
        else:
            _fs = self._delegate_required(path)
        return _fs.openbin(path, mode=mode, buffering=buffering, **options)

    def remove(self, path):
        # type: (Text) -> None
        self.check()
        fs = self._delegate_required(path)
        return fs.remove(path)

    def removedir(self, path):
        # type: (Text) -> None
        self.check()
        fs = self._delegate_required(path)
        return fs.removedir(path)

    def scandir(
        self,
        path,  # type: Text
        namespaces=None,  # type: Optional[Collection[Text]]
        page=None,  # type: Optional[Tuple[int, int]]
    ):
        # type: (...) -> Iterator[Info]
        self.check()
        # Snapshot the layers and masks up front so a single traversal
        # keeps returning one explainable, consistent view even if the
        # configuration changes while iteration is in progress.
        sequence, masks = self._snapshot()
        abs_path = abspath(normpath(path))
        if self._is_masked(abs_path, masks):
            raise errors.ResourceNotFound(path)
        seen = set()  # type: MutableSet[Text]
        exists = False
        failures = []  # type: List[Tuple[Text, Text, Exception]]
        yielded = []  # type: List[Text]
        for name, fs in sequence:
            try:
                infos = list(fs.scandir(path, namespaces=namespaces, page=page))
            except errors.ResourceNotFound:
                continue
            except errors.ResourceInvalid:
                raise
            except errors.FSError as exc:
                failures.append((name, abs_path, exc))
                continue
            exists = True
            for info in infos:
                if info.name in seen:
                    continue
                if self._is_masked(join(abs_path, info.name), masks):
                    continue
                yield info
                seen.add(info.name)
                yielded.append(info.name)

        if not exists and failures:
            raise errors.BackendUnavailable(
                failures, partial=yielded, path=abs_path
            )
        if not exists:
            raise errors.ResourceNotFound(path)
        if failures:
            raise errors.BackendUnavailable(
                failures, partial=yielded, path=abs_path
            )

    def readbytes(self, path):
        # type: (Text) -> bytes
        self.check()
        fs = self._delegate(path)
        if fs is None:
            raise errors.ResourceNotFound(path)
        return fs.readbytes(path)

    def download(self, path, file, chunk_size=None, **options):
        # type: (Text, BinaryIO, Optional[int], **Any) -> None
        fs = self._delegate_required(path)
        return fs.download(path, file, chunk_size=chunk_size, **options)

    def readtext(self, path, encoding=None, errors=None, newline=""):
        # type: (Text, Optional[Text], Optional[Text], Text) -> Text
        self.check()
        fs = self._delegate_required(path)
        return fs.readtext(path, encoding=encoding, errors=errors, newline=newline)

    def getsize(self, path):
        # type: (Text) -> int
        self.check()
        fs = self._delegate_required(path)
        return fs.getsize(path)

    def getsyspath(self, path):
        # type: (Text) -> Text
        self.check()
        fs = self._delegate_required(path)
        return fs.getsyspath(path)

    def gettype(self, path):
        # type: (Text) -> ResourceType
        self.check()
        fs = self._delegate_required(path)
        return fs.gettype(path)

    def geturl(self, path, purpose="download"):
        # type: (Text, Text) -> Text
        self.check()
        fs = self._delegate_required(path)
        return fs.geturl(path, purpose=purpose)

    def hassyspath(self, path):
        # type: (Text) -> bool
        self.check()
        fs = self._delegate(path)
        return fs is not None and fs.hassyspath(path)

    def hasurl(self, path, purpose="download"):
        # type: (Text, Text) -> bool
        self.check()
        fs = self._delegate(path)
        return fs is not None and fs.hasurl(path, purpose=purpose)

    def isdir(self, path):
        # type: (Text) -> bool
        self.check()
        fs = self._delegate(path)
        return fs is not None and fs.isdir(path)

    def isfile(self, path):
        # type: (Text) -> bool
        self.check()
        fs = self._delegate(path)
        return fs is not None and fs.isfile(path)

    def setinfo(self, path, info):
        # type:(Text, RawInfo) -> None
        self.check()
        write_fs = self._writable_required(path)
        return write_fs.setinfo(path, info)

    def validatepath(self, path):
        # type: (Text) -> Text
        self.check()
        if self.write_fs is not None:
            self.write_fs.validatepath(path)
        else:
            super(MultiFS, self).validatepath(path)
        path = abspath(normpath(path))
        return path

    def makedirs(
        self,
        path,  # type: Text
        permissions=None,  # type: Optional[Permissions]
        recreate=False,  # type: bool
    ):
        # type: (...) -> SubFS[FS]
        self.check()
        write_fs = self._writable_required(path)
        return write_fs.makedirs(path, permissions=permissions, recreate=recreate)

    def open(
        self,
        path,  # type: Text
        mode="r",  # type: Text
        buffering=-1,  # type: int
        encoding=None,  # type: Optional[Text]
        errors=None,  # type: Optional[Text]
        newline="",  # type: Text
        **kwargs  # type: Any
    ):
        # type: (...) -> IO
        self.check()
        if check_writable(mode):
            _fs = self._writable_required(path)
        else:
            _fs = self._delegate_required(path)
        return _fs.open(
            path,
            mode=mode,
            buffering=buffering,
            encoding=encoding,
            errors=errors,
            newline=newline,
            **kwargs
        )

    def upload(self, path, file, chunk_size=None, **options):
        # type: (Text, BinaryIO, Optional[int], **Any) -> None
        self._writable_required(path).upload(
            path, file, chunk_size=chunk_size, **options
        )

    def writebytes(self, path, contents):
        # type: (Text, bytes) -> None
        self._writable_required(path).writebytes(path, contents)

    def writetext(
        self,
        path,  # type: Text
        contents,  # type: Text
        encoding="utf-8",  # type: Text
        errors=None,  # type: Optional[Text]
        newline="",  # type: Text
    ):
        # type: (...) -> None
        write_fs = self._writable_required(path)
        return write_fs.writetext(
            path, contents, encoding=encoding, errors=errors, newline=newline
        )
