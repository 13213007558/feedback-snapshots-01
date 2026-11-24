fs.delegation
=============

Approval-scoped delegation of a virtual directory to an untrusted plugin.

A reporting service can wrap a filesystem with `DelegatedFS` and hand
the wrapper to a plugin.  The plugin keeps the ordinary virtual
interface -- opening and copying files and opening sub-directories --
but the two ways of escaping that interface are granted separately and
only on explicitly approved sub-trees:

* a real *system path* (`~fs.base.FS.getsyspath`);
* a transferable *download URL* (`~fs.base.FS.geturl`).

A `DelegationPolicy` holds one or more `DelegationScope` objects.  The
most specific (longest) matching scope wins for any path, so a broadly
read-only tree can contain a smaller, explicitly approved export tree.
Every decision is written to the policy's audit log.  Directories
opened with `~fs.base.FS.opendir` return a `DelegatedSubFS` bound to
the same policy, so restrictions propagate recursively and derived
directories can never widen the approval.

.. automodule:: fs.delegation
    :members:
