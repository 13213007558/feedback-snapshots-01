"""Approval-scoped delegation of a virtual directory to a plugin.

A reporting service may hand an *approved* virtual directory to an
untrusted plugin.  The plugin is free to open and copy files and to open
further sub-directories, but the two ways in which it could escape the
virtual interface -- obtaining a real *system path*
(`~fs.base.FS.getsyspath`) or a transferable *download URL*
(`~fs.base.FS.geturl`) -- are granted separately, and only for the
sub-trees that were explicitly approved.

This module provides:

* `DelegationScope` -- one approved sub-tree together with the
  capabilities granted on it.
* `DelegationPolicy` -- the set of approved scopes plus the audit log
  that records every delegation decision.
* `DelegatedFS` -- a `~fs.wrapfs.WrapFS` wrapper that enforces the
  policy.  Normal virtual reads and writes, as well as cross-backend
  copies, keep using the regular FS interface; only direct system paths
  and URLs are gated.
* `DelegatedSubFS` -- the object returned by `~fs.base.FS.opendir` on a
  delegated filesystem.  It carries the *same* policy, so recursively
  opened directories can never widen the approval.

Capabilities are expressed with the constants on `DelegationScope`
(``READ``, ``WRITE``, ``SYSPATH`` and ``URL``).
"""

from __future__ import unicode_literals

import typing
from datetime import datetime

import six

from . import errors
from .path import abspath, isbase, normpath
from .subfs import SubFS
from .wrapfs import WrapFS

if typing.TYPE_CHECKING:
    from typing import (
        Any,
        AnyStr,
        BinaryIO,
        Callable,
        Collection,
        IO,
        Iterable,
        Iterator,
        List,
        Mapping,
        Optional,
        Sequence,
        Text,
        Tuple,
        Union,
    )

    from .base import FS
    from .info import Info, RawInfo
    from .permissions import Permissions

_F = typing.TypeVar("_F", bound="FS", covariant=True)
_D = typing.TypeVar("_D", bound="DelegatedFS")


class PermissionDenied(errors.FSError):
    """An operation was requested outside of the approved delegation.

    Raised when a plugin reaches for a path or capability that was not
    part of its approval (for instance writing into a read-only
    sub-tree, or asking for a system path that was never granted).
    """

    default_message = "access to '{path}' is not part of the delegation"

    def __init__(self, path, msg=None, exc=None):  # noqa: D107
        # type: (Text, Optional[Text], Optional[Exception]) -> None
        self.path = path
        self.exc = exc
        super(PermissionDenied, self).__init__(msg=msg)

    def __reduce__(self):
        return type(self), (self.path, self._msg, self.exc)


@six.python_2_unicode_compatible
class DelegationScope(object):
    """An approved sub-tree and the capabilities granted on it.

    Attributes:
        path (str): The root of the approved sub-tree (an absolute,
            normalized FS path).
        read (bool): Virtual reads are permitted below ``path``.
        write (bool): Virtual writes are permitted below ``path``.
        syspath (bool): The real operating-system path may be handed
            out via `~fs.base.FS.getsyspath`.
        url (bool): A transferable download URL may be handed out via
            `~fs.base.FS.geturl`.
        label (str): Human readable name, used in audit records.
    """

    #: Virtual read capability (open / list / copy-from).
    READ = 1
    #: Virtual write capability (create / modify / copy-to).
    WRITE = 2
    #: Direct system path capability (`getsyspath`).
    SYSPATH = 4
    #: Download URL capability (`geturl`).
    URL = 8

    def __init__(
        self,
        path,  # type: Text
        read=False,  # type: bool
        write=False,  # type: bool
        syspath=False,  # type: bool
        url=False,  # type: bool
        label=None,  # type: Optional[Text]
    ):
        # type: (...) -> None
        self.path = abspath(normpath(path))
        self.read = bool(read)
        self.write = bool(write)
        self.syspath = bool(syspath)
        self.url = bool(url)
        self.label = label or self.path

    @classmethod
    def read_only(cls, path, **options):
        # type: (Text, **Any) -> DelegationScope
        """Create a scope that only permits virtual reads."""
        options.setdefault("read", True)
        return cls(path, **options)

    @classmethod
    def read_write(cls, path, **options):
        # type: (Text, **Any) -> DelegationScope
        """Create a scope that permits virtual reads and writes."""
        options.setdefault("read", True)
        options.setdefault("write", True)
        return cls(path, **options)

    def capabilities(self):
        # type: () -> Text
        """Render the granted capabilities as a short flag string."""
        flags = ""
        flags += "r" if self.read else "-"
        flags += "w" if self.write else "-"
        flags += "s" if self.syspath else "-"
        flags += "u" if self.url else "-"
        return flags

    def __str__(self):
        # type: () -> Text
        return "{} [{}]".format(self.label, self.capabilities())

    def __repr__(self):
        # type: () -> Text
        return (
            "DelegationScope({!r}, read={!r}, write={!r}, "
            "syspath={!r}, url={!r})".format(
                self.path, self.read, self.write, self.syspath, self.url
            )
        )


@six.python_2_unicode_compatible
class DelegationRecord(object):
    """A single entry in the `DelegationPolicy` audit log."""

    def __init__(self, action, path, allowed, capability, detail=None):
        # type: (Text, Text, bool, Text, Optional[Text]) -> None
        self.time = datetime.utcnow()
        self.action = action
        self.path = abspath(normpath(path))
        self.allowed = bool(allowed)
        self.capability = capability
        self.detail = detail

    def __str__(self):
        # type: () -> Text
        decision = "ALLOW" if self.allowed else "DENY"
        detail = " ({})".format(self.detail) if self.detail else ""
        return "{} {} {} on {}{}".format(
            decision, self.capability, self.action, self.path, detail
        )


class DelegationPolicy(object):
    """The approval that governs a delegated virtual directory.

    A policy holds one or more `DelegationScope` objects.  For any given
    path the *most specific* (longest) matching scope wins, which lets a
    broadly read-only tree contain a smaller explicitly approved
    export tree.  Paths that match no scope are fully denied.
    """

    def __init__(self, scopes=None, name="plugin"):
        # type: (Optional[Iterable[DelegationScope]], Text) -> None
        self.name = name
        self.scopes = list(scopes or [])  # type: List[DelegationScope]
        self.audit_log = []  # type: List[DelegationRecord]

    def add_scope(self, scope):
        # type: (DelegationScope) -> DelegationScope
        """Append another approved scope to the policy."""
        self.scopes.append(scope)
        return scope

    def scope_for(self, path):
        # type: (Text) -> Optional[DelegationScope]
        """Return the most specific scope that covers ``path``.

        Returns `None` when no approved scope covers the path.
        """
        _path = abspath(normpath(path))
        matches = [
            scope for scope in self.scopes if isbase(scope.path, _path)
        ]
        if not matches:
            return None
        return sorted(matches, key=lambda scope: len(scope.path))[-1]

    def record(self, action, path, allowed, capability, detail=None):
        # type: (Text, Text, bool, Text, Optional[Text]) -> DelegationRecord
        """Append a decision to the audit log and return it."""
        entry = DelegationRecord(action, path, allowed, capability, detail)
        self.audit_log.append(entry)
        return entry

    def _check(self, action, path, capability, attr):
        # type: (Text, Text, Text, Text) -> DelegationScope
        scope = self.scope_for(path)
        allowed = scope is not None and bool(getattr(scope, attr))
        if not allowed:
            detail = "outside approved scopes" if scope is None else "not granted"
            self.record(action, path, False, capability, detail)
            raise PermissionDenied(
                path,
                msg="{} access to '{}' is not part of the '{}' delegation".format(
                    capability, abspath(normpath(path)), self.name
                ),
            )
        self.record(action, path, True, capability, scope.label)
        return scope

    def require_read(self, action, path):
        # type: (Text, Text) -> DelegationScope
        """Authorize a virtual read, raising `PermissionDenied` otherwise."""
        return self._check(action, path, "read", "read")

    def require_write(self, action, path):
        # type: (Text, Text) -> DelegationScope
        """Authorize a virtual write, raising `PermissionDenied` otherwise."""
        return self._check(action, path, "write", "write")

    def require_syspath(self, action, path):
        # type: (Text, Text) -> DelegationScope
        """Authorize handing out a real system path."""
        return self._check(action, path, "syspath", "syspath")

    def require_url(self, action, path):
        # type: (Text, Text) -> DelegationScope
        """Authorize handing out a download URL."""
        return self._check(action, path, "url", "url")

    def denied(self):
        # type: () -> List[DelegationRecord]
        """Return all denied audit records."""
        return [entry for entry in self.audit_log if not entry.allowed]

    def granted(self):
        # type: () -> List[DelegationRecord]
        """Return all granted audit records."""
        return [entry for entry in self.audit_log if entry.allowed]

    def __str__(self):
        # type: () -> Text
        scopes = ", ".join(str(scope) for scope in self.scopes)
        return "DelegationPolicy({}): {}".format(self.name, scopes)


def delegate(fs, scopes, name="plugin"):
    # type: (FS, Sequence[DelegationScope], Text) -> DelegatedFS
    """Wrap ``fs`` in a `DelegatedFS` governed by ``scopes``.

    Arguments:
        fs (FS): The backing (real) filesystem to delegate.
        scopes (list[DelegationScope]): The approved sub-trees.
        name (str): A name for the delegate, used in audit messages.

    Returns:
        DelegatedFS: A policy-enforcing view of ``fs``.
    """
    policy = DelegationPolicy(scopes, name=name)
    return DelegatedFS(fs, policy)


class DelegatedFS(WrapFS[_F], typing.Generic[_F]):
    """A virtual directory handed to a plugin under an approved policy.

    Every operation is checked against the wrapped `DelegationPolicy`:

    * virtual reads require the ``READ`` capability;
    * virtual writes require the ``WRITE`` capability;
    * `getsyspath` additionally requires ``SYSPATH``;
    * `geturl` additionally requires ``URL``.

    The ordinary virtual interface (including cross-backend copy) is
    unchanged for approved paths.  A directory opened with `opendir`
    returns a `DelegatedSubFS` bound to the same policy, so the
    restrictions propagate recursively.
    """

    wrap_name = "delegated"

    def __init__(self, wrap_fs, policy):  # noqa: D107
        # type: (_F, DelegationPolicy) -> None
        self._policy = policy
        super(DelegatedFS, self).__init__(wrap_fs)

    @property
    def policy(self):
        # type: () -> DelegationPolicy
        """The delegation policy enforced by this filesystem."""
        return self._policy

    # --- privileged escape hatches ------------------------------
    # These are the only two ways to leave the virtual interface, so
    # they are gated independently of ordinary read/write approval.

    def getsyspath(self, path):
        # type: (Text) -> Text
        self.check()
        _fs, _path = self.delegate_path(path)
        self._policy.require_syspath("getsyspath", path)
        return _fs.getsyspath(_path)

    def hassyspath(self, path):
        # type: (Text) -> bool
        self.check()
        try:
            self._policy.require_syspath("hassyspath", path)
        except PermissionDenied:
            return False
        _fs, _path = self.delegate_path(path)
        return _fs.hassyspath(_path)

    def geturl(self, path, purpose="download"):
        # type: (Text, Text) -> Text
        self.check()
        _fs, _path = self.delegate_path(path)
        self._policy.require_url("geturl", path)
        return _fs.geturl(_path, purpose=purpose)

    def hasurl(self, path, purpose="download"):
        # type: (Text, Text) -> bool
        self.check()
        try:
            self._policy.require_url("hasurl", path)
        except PermissionDenied:
            return False
        _fs, _path = self.delegate_path(path)
        return _fs.hasurl(_path, purpose=purpose)

    # --- virtual reads -------------------------------------------

    def getinfo(self, path, namespaces=None):
        # type: (Text, Optional[Collection[Text]]) -> Info
        self.check()
        self._policy.require_read("getinfo", path)
        return super(DelegatedFS, self).getinfo(path, namespaces=namespaces)

    def listdir(self, path):
        # type: (Text) -> List[Text]
        self.check()
        self._policy.require_read("listdir", path)
        return super(DelegatedFS, self).listdir(path)

    def scandir(self, path, namespaces=None, page=None):
        # type: (Text, Optional[Collection[Text]], Optional[Tuple[int, int]]) -> Iterator[Info]  # noqa: E501
        self.check()
        self._policy.require_read("scandir", path)
        return super(DelegatedFS, self).scandir(
            path, namespaces=namespaces, page=page
        )

    def filterdir(
        self,
        path,
        files=None,
        dirs=None,
        exclude_dirs=None,
        exclude_files=None,
        namespaces=None,
        page=None,
    ):
        self.check()
        self._policy.require_read("filterdir", path)
        return super(DelegatedFS, self).filterdir(
            path,
            files=files,
            dirs=dirs,
            exclude_dirs=exclude_dirs,
            exclude_files=exclude_files,
            namespaces=namespaces,
            page=page,
        )

    def exists(self, path):
        # type: (Text) -> bool
        self.check()
        self._policy.require_read("exists", path)
        return super(DelegatedFS, self).exists(path)

    def isdir(self, path):
        # type: (Text) -> bool
        self.check()
        self._policy.require_read("isdir", path)
        return super(DelegatedFS, self).isdir(path)

    def isfile(self, path):
        # type: (Text) -> bool
        self.check()
        self._policy.require_read("isfile", path)
        return super(DelegatedFS, self).isfile(path)

    def islink(self, path):
        # type: (Text) -> bool
        self.check()
        self._policy.require_read("islink", path)
        return super(DelegatedFS, self).islink(path)

    def getsize(self, path):
        # type: (Text) -> int
        self.check()
        self._policy.require_read("getsize", path)
        return super(DelegatedFS, self).getsize(path)

    def gettype(self, path):
        # type: (Text) -> object
        self.check()
        self._policy.require_read("gettype", path)
        return super(DelegatedFS, self).gettype(path)

    def readbytes(self, path):
        # type: (Text) -> bytes
        self.check()
        self._policy.require_read("readbytes", path)
        return super(DelegatedFS, self).readbytes(path)

    def readtext(self, path, encoding=None, errors=None, newline=""):
        self.check()
        self._policy.require_read("readtext", path)
        return super(DelegatedFS, self).readtext(
            path, encoding=encoding, errors=errors, newline=newline
        )

    def desc(self, path):
        # type: (Text) -> Text
        self.check()
        self._policy.require_read("desc", path)
        return super(DelegatedFS, self).desc(path)

    def hash(self, path, name):
        # type: (Text, Text) -> Text
        self.check()
        self._policy.require_read("hash", path)
        return super(DelegatedFS, self).hash(path, name)

    def openbin(self, path, mode="r", buffering=-1, **options):
        # type: (Text, Text, int, **Any) -> BinaryIO
        self.check()
        self._authorize_mode(path, mode)
        return super(DelegatedFS, self).openbin(
            path, mode=mode, buffering=buffering, **options
        )

    def open(
        self,
        path,
        mode="r",
        buffering=-1,
        encoding=None,
        errors=None,
        newline="",
        line_buffering=False,
        **options
    ):
        self.check()
        self._authorize_mode(path, mode)
        return super(DelegatedFS, self).open(
            path,
            mode=mode,
            buffering=buffering,
            encoding=encoding,
            errors=errors,
            newline=newline,
            line_buffering=line_buffering,
            **options
        )

    def download(self, path, file, chunk_size=None, **options):
        # type: (Text, BinaryIO, Optional[int], **Any) -> None
        self.check()
        self._policy.require_read("download", path)
        return super(DelegatedFS, self).download(
            path, file, chunk_size=chunk_size, **options
        )

    def _authorize_mode(self, path, mode):
        # type: (Text, Text) -> None
        if any(flag in mode for flag in ("w", "a", "x", "+")):
            self._policy.require_write("open({})".format(mode), path)
        else:
            self._policy.require_read("open({})".format(mode), path)

    # --- virtual writes ------------------------------------------

    def create(self, path, wipe=False):
        # type: (Text, bool) -> bool
        self.check()
        self._policy.require_write("create", path)
        return super(DelegatedFS, self).create(path, wipe=wipe)

    def touch(self, path):
        # type: (Text) -> None
        self.check()
        self._policy.require_write("touch", path)
        return super(DelegatedFS, self).touch(path)

    def writebytes(self, path, contents):
        # type: (Text, bytes) -> None
        self.check()
        self._policy.require_write("writebytes", path)
        return super(DelegatedFS, self).writebytes(path, contents)

    def writetext(self, path, contents, encoding="utf-8", errors=None, newline=""):
        self.check()
        self._policy.require_write("writetext", path)
        return super(DelegatedFS, self).writetext(
            path, contents, encoding=encoding, errors=errors, newline=newline
        )

    def appendbytes(self, path, data):
        # type: (Text, bytes) -> None
        self.check()
        self._policy.require_write("appendbytes", path)
        return super(DelegatedFS, self).appendbytes(path, data)

    def appendtext(
        self, path, text, encoding="utf-8", errors=None, newline=""
    ):
        self.check()
        self._policy.require_write("appendtext", path)
        return super(DelegatedFS, self).appendtext(
            path, text, encoding=encoding, errors=errors, newline=newline
        )

    def upload(self, path, file, chunk_size=None, **options):
        # type: (Text, BinaryIO, Optional[int], **Any) -> None
        self.check()
        self._policy.require_write("upload", path)
        return super(DelegatedFS, self).upload(
            path, file, chunk_size=chunk_size, **options
        )

    def writefile(self, path, file, encoding=None, errors=None, newline=""):
        self.check()
        self._policy.require_write("writefile", path)
        return super(DelegatedFS, self).writefile(
            path, file, encoding=encoding, errors=errors, newline=newline
        )

    def remove(self, path):
        # type: (Text) -> None
        self.check()
        self._policy.require_write("remove", path)
        return super(DelegatedFS, self).remove(path)

    def removedir(self, path):
        # type: (Text) -> None
        self.check()
        self._policy.require_write("removedir", path)
        return super(DelegatedFS, self).removedir(path)

    def removetree(self, dir_path):
        # type: (Text) -> None
        self.check()
        self._policy.require_write("removetree", dir_path)
        return super(DelegatedFS, self).removetree(dir_path)

    def makedir(self, path, permissions=None, recreate=False):
        # type: (Text, Optional[Permissions], bool) -> DelegatedSubFS
        self.check()
        self._policy.require_write("makedir", path)
        super(DelegatedFS, self).makedir(
            path, permissions=permissions, recreate=recreate
        )
        return self.opendir(path)

    def makedirs(self, path, permissions=None, recreate=False):
        # type: (Text, Optional[Permissions], bool) -> DelegatedSubFS
        self.check()
        self._policy.require_write("makedirs", path)
        super(DelegatedFS, self).makedirs(
            path, permissions=permissions, recreate=recreate
        )
        return self.opendir(path)

    def setinfo(self, path, info):
        # type: (Text, RawInfo) -> None
        self.check()
        self._policy.require_write("setinfo", path)
        return super(DelegatedFS, self).setinfo(path, info)

    def settimes(self, path, accessed=None, modified=None):
        self.check()
        self._policy.require_write("settimes", path)
        return super(DelegatedFS, self).settimes(
            path, accessed=accessed, modified=modified
        )

    def move(self, src_path, dst_path, overwrite=False, preserve_time=False):
        self.check()
        self._policy.require_read("move-src", src_path)
        self._policy.require_write("move-dst", dst_path)
        return super(DelegatedFS, self).move(
            src_path,
            dst_path,
            overwrite=overwrite,
            preserve_time=preserve_time,
        )

    def movedir(self, src_path, dst_path, create=False, preserve_time=False):
        self.check()
        self._policy.require_read("movedir-src", src_path)
        self._policy.require_write("movedir-dst", dst_path)
        return super(DelegatedFS, self).movedir(
            src_path, dst_path, create=create, preserve_time=preserve_time
        )

    def copy(self, src_path, dst_path, overwrite=False, preserve_time=False):
        # Virtual cross-backend copy keeps using the regular interface;
        # it simply needs read approval on the source and write on the
        # destination -- no syspath/URL grant is involved.
        self.check()
        self._policy.require_read("copy-src", src_path)
        self._policy.require_write("copy-dst", dst_path)
        return super(DelegatedFS, self).copy(
            src_path,
            dst_path,
            overwrite=overwrite,
            preserve_time=preserve_time,
        )

    def copydir(self, src_path, dst_path, create=False, preserve_time=False):
        self.check()
        self._policy.require_read("copydir-src", src_path)
        self._policy.require_write("copydir-dst", dst_path)
        return super(DelegatedFS, self).copydir(
            src_path, dst_path, create=create, preserve_time=preserve_time
        )

    # --- recursive sub-directories -------------------------------

    def opendir(self, path, factory=None):
        # type: (Text, Optional[Callable]) -> DelegatedSubFS
        if not self.getinfo(path).is_dir:
            raise errors.DirectoryExpected(path=path)
        return DelegatedSubFS(self, path, self._policy)


class DelegatedSubFS(SubFS[_F], typing.Generic[_F]):
    """A sub-directory of a `DelegatedFS`, bound to the same policy.

    Because the policy is shared (not re-derived), opening ever deeper
    sub-directories can never broaden the original approval.
    """

    wrap_name = "delegated-sub"

    def __init__(self, parent_fs, path, policy):  # noqa: D107
        # type: (DelegatedFS, Text, DelegationPolicy) -> None
        super(DelegatedSubFS, self).__init__(parent_fs, path)
        self._policy = policy

    @property
    def policy(self):
        # type: () -> DelegationPolicy
        return self._policy

    def opendir(self, path, factory=None):
        # type: (Text, Optional[Callable]) -> DelegatedSubFS
        if not self.getinfo(path).is_dir:
            raise errors.DirectoryExpected(path=path)
        return DelegatedSubFS(self, path, self._policy)

    def makedir(self, path, permissions=None, recreate=False):
        # type: (Text, Optional[Permissions], bool) -> DelegatedSubFS
        super(DelegatedSubFS, self).makedir(
            path, permissions=permissions, recreate=recreate
        )
        return self.opendir(path)

    def makedirs(self, path, permissions=None, recreate=False):
        # type: (Text, Optional[Permissions], bool) -> DelegatedSubFS
        super(DelegatedSubFS, self).makedirs(
            path, permissions=permissions, recreate=recreate
        )
        return self.opendir(path)
