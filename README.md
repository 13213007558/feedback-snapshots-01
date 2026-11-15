# dissect.squashfs

A Dissect module implementing a parser for the SquashFS file system, commonly used in appliance or device firmware. For more
information, please see [the documentation](https://docs.dissect.tools/en/latest/projects/dissect.squashfs/index.html).

## Requirements

This project is part of the Dissect framework and requires Python.

Information on the supported Python versions can be found in the Getting Started section of [the documentation](https://docs.dissect.tools/en/latest/index.html#getting-started).

## Installation

`dissect.squashfs` is available on [PyPI](https://pypi.org/project/dissect.squashfs/).

```bash
pip install dissect.squashfs
```

This project decompresses LZO and LZ4 compressed file systems and can use a faster, native (Rust-based) LZO or LZ4 implementation,
instead of a slower pure Python implementation. Both implementations are provided by `dissect.util`.
Pre-build wheels are available for most common platforms and the native implementation will automatically be used if available.
In the rare case that a pre-build wheel is not available, please refer to `dissect.util` for build instructions.

## Build and test instructions

This project uses `tox` to build source and wheel distributions. Run the following command from the root folder to build
these:

```bash
tox -e build
```

The build artifacts can be found in the `dist/` directory.

`tox` is also used to run linting and unit tests in a self-contained environment. To run both linting and unit tests
using the default installed Python version, run:

```bash
tox
```

For a more elaborate explanation on how to build and test the project, please see [the
documentation](https://docs.dissect.tools/en/latest/contributing/tooling.html).

## Contributing

The Dissect project encourages any contribution to the codebase. To make your contribution fit into the project, please
refer to [the development guide](https://docs.dissect.tools/en/latest/contributing/developing.html).

## Copyright and license

Dissect is released as open source by Fox-IT (<https://www.fox-it.com>) part of NCC Group Plc
(<https://www.nccgroup.com>).

Developed by the Dissect Team (<dissect@fox-it.com>) and made available at <https://github.com/fox-it/dissect>.

License terms: AGPL3 (<https://www.gnu.org/licenses/agpl-3.0.html>). For more information, see the LICENSE file.

## Permission evidence inventory

`dissect.squashfs` includes a read-only inventory for permission-sensitive
firmware objects. It reports setuid, setgid, sticky and world-writable inodes
while keeping the identity evidence separate from the permission bits.

SquashFS inode headers store 16-bit indexes into a filesystem-wide id table,
not numeric uid/gid values. The inventory therefore always reports both the raw
index (`squashfs_base_inode_header.uid` / `.guid`) and the numeric ID resolved
from the id table. It never consults local account databases.

```python
from dissect.squashfs import build_permission_manifest

manifest = build_permission_manifest("firmware.sqfs")

for entry in manifest:
    print(entry.paths, oct(entry.raw_mode), entry.owner_id, entry.group_id, entry.classification)
```

The manifest de-duplicates hard links by underlying inode while retaining every
path that references the object; `object_count` counts inodes and `path_count`
counts path references. A missing or corrupt id-table entry produces an unknown
identity (`owner_id is None`, `owner_known is False`) rather than uid/gid 0.
Use `entry.definitely_root_owned_setuid` only for a setuid object whose index
actually resolves to numeric uid 0.

For a machine-readable report including raw field evidence:

```bash
python -m dissect.squashfs.manifest --json firmware.sqfs
```
