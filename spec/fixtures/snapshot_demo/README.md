Two small, independent advisory database versions used by
`spec/snapshot_spec.rb`.

Both directories are plain (non-git) databases. The spec copies each one
into a scratch directory and turns the scratch directory into a git
repository, so the demo runs without network access.

Version 1:

* `demo-gem` 1.0.0 is vulnerable to `CVE-2026-0001`.

Version 2:

* `demo-gem` 1.0.0 is vulnerable to `CVE-2026-0001`.
* `demo-gem` 1.0.0 is vulnerable to `CVE-2026-0002`.
* `CVE-2026-0001` was edited (title changed) to prove file contents, not
  only file names, are pinned by the snapshot digest.

Version 3:

* `CVE-2026-0002` was removed, while `CVE-2026-0001` remains unchanged
  from version two.  This proves that a snapshot keeps deleted advisories
  visible for scans that started before the deletion.
