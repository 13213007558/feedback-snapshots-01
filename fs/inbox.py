"""Securely move files between filesystems while preserving access levels.

The generic :func:`fs.move.move_file` copies a file's contents and then
deletes the source, but it does not carry over the *access* metadata
(permissions).  When a restricted file is moved onto a backend that cannot
represent those permissions, the destination copy would silently be created
with more open access than the source -- a privilege escalation -- while the
restricted original is removed.

This module treats the move as a guarded, all-or-nothing operation:

1. The destination's ability to store the source's access level is checked
   *before* anything is written.  A move that cannot be honoured aborts up
   front and leaves the source untouched.
2. On a capable destination the file is copied and the source permissions are
   re-applied and verified before the source is deleted.
3. If the final source deletion fails, the destination copy is rolled back
   (unless explicitly disabled) so the object remains visible, with its
   original access level, in exactly one place.
"""

from __future__ import print_function, unicode_literals

import os
import typing

from . import errors
from .copy import copy_file_internal
from .error_tools import convert_os_errors
from .opener import manage_fs
from .permissions import Permissions

if typing.TYPE_CHECKING:
    from typing import List, Optional, Text, Union

    from .base import FS
    from .info import Info

_ACCESS_NAMESPACE = "access"
_PERMISSIONS_KEY = "permissions"


class PermissionUnsupported(errors.Unsupported):
    """A filesystem cannot preserve the required access level.

    Raised when a restricted file is moved to a destination that has no way
    of storing the source's *access* metadata (for example an in-memory
    filesystem).  The move is rejected before any data is written so the
    restricted source is never left behind in a less protected location.
    """

    default_message = (
        "destination filesystem cannot preserve the source access level"
    )

    def __init__(self, path=None, required_permissions=None, exc=None, msg=None):
        # type: (Optional[Text], Optional[List[Text]], Optional[Exception], Optional[Text]) -> None  # noqa: E501
        self.required_permissions = required_permissions
        super(PermissionUnsupported, self).__init__(path=path, exc=exc, msg=msg)


def _supports_access(fs):
    # type: (FS) -> bool
    """Return whether ``fs`` exposes an *access* info namespace."""
    probe = fs.getinfo("/", namespaces=("basic", _ACCESS_NAMESPACE))
    return _ACCESS_NAMESPACE in probe.namespaces


def _get_permissions(info):
    # type: (Info) -> Optional[List[Text]]
    """Return the serialized permission names held by ``info``, if any."""
    access = info.raw.get(_ACCESS_NAMESPACE)
    if not access:
        return None
    permissions = access.get(_PERMISSIONS_KEY)
    if not permissions:
        return None
    return list(permissions)


def _read_permissions(fs, path):
    # type: (FS, Text) -> Optional[List[Text]]
    info = fs.getinfo(path, namespaces=("basic", _ACCESS_NAMESPACE))
    return _get_permissions(info)


def _apply_permissions(fs, path, permissions):
    # type: (FS, Text, List[Text]) -> None
    """Best-effort application of ``permissions`` to a resource.

    Filesystems that own a real OS path can be re-stated directly with
    :func:`os.chmod`; everything else is asked through the generic
    :meth:`~fs.base.FS.setinfo` *access* namespace.
    """
    mode = Permissions(names=permissions).mode
    if fs.hassyspath(path):
        with convert_os_errors("setinfo", path):
            os.chmod(fs.getsyspath(path), mode)
        return
    fs.setinfo(path, {_ACCESS_NAMESPACE: {_PERMISSIONS_KEY: permissions}})


def _permissions_match(fs, path, expected):
    # type: (FS, Text, List[Text]) -> bool
    actual = _read_permissions(fs, path)
    if actual is None:
        return False
    return set(actual) == set(expected)


def secure_move_file(
    src_fs,  # type: Union[Text, FS]
    src_path,  # type: Text
    dst_fs,  # type: Union[Text, FS]
    dst_path,  # type: Text
    preserve_time=False,  # type: bool
    cleanup_dst_on_error=True,  # type: bool
):
    # type: (...) -> None
    """Move a file while guaranteeing its access level is preserved.

    Arguments:
        src_fs (FS or str): Source filesystem (instance or URL).
        src_path (str): Path to a file on ``src_fs``.
        dst_fs (FS or str): Destination filesystem (instance or URL).
        dst_path (str): Path to a file on ``dst_fs``.
        preserve_time (bool): If `True`, try to preserve the modification
            time of the resource (defaults to `False`).
        cleanup_dst_on_error (bool): If `True`, delete the destination copy
            when the final source deletion fails, so the object survives in
            its original location (defaults to `True`).

    Raises:
        fs.errors.ResourceNotFound: If ``src_path`` does not exist.
        PermissionUnsupported: If the source carries permissions the
            destination filesystem is incapable of storing.
        fs.errors.FSError: If the source cannot be removed; the destination
            copy is rolled back first (when ``cleanup_dst_on_error`` is set).
    """
    with manage_fs(src_fs, writeable=True) as _src_fs:
        with manage_fs(dst_fs, writeable=True, create=True) as _dst_fs:

            required_permissions = _read_permissions(_src_fs, src_path)

            if _src_fs is _dst_fs:
                # Same filesystem: an atomic rename keeps both the contents
                # and every attribute, including the access level.
                _src_fs.move(
                    src_path, dst_path, overwrite=True, preserve_time=preserve_time
                )
                return

            if required_permissions is not None and not _supports_access(_dst_fs):
                # Refuse before writing anything: the destination could not
                # honour the restricted access level, so copying would only
                # produce a less protected duplicate.
                raise PermissionUnsupported(
                    path=dst_path, required_permissions=required_permissions
                )

            with _src_fs.lock(), _dst_fs.lock():
                copy_file_internal(
                    _src_fs,
                    src_path,
                    _dst_fs,
                    dst_path,
                    preserve_time=preserve_time,
                    lock=False,
                )

                if required_permissions is not None:
                    _apply_permissions(_dst_fs, dst_path, required_permissions)
                    if not _permissions_match(_dst_fs, dst_path, required_permissions):
                        # The destination claimed support but failed to retain
                        # the access level.  Roll the copy back and abort.
                        _dst_fs.remove(dst_path)
                        raise PermissionUnsupported(
                            path=dst_path,
                            required_permissions=required_permissions,
                        )

                try:
                    _src_fs.remove(src_path)
                except errors.FSError as error:
                    if cleanup_dst_on_error and _dst_fs.exists(dst_path):
                        _dst_fs.remove(dst_path)
                    raise error
