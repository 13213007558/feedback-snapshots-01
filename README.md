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

## Permission evidence inventory

For firmware audits, `dissect.squashfs.audit` produces a read-only inventory of objects carrying setuid,
setgid, sticky or world-writable bits. It never extracts or modifies the image and never consults the local
account database.

Inode headers store *indices* into the SquashFS ID table rather than numeric UIDs/GIDs. The inventory keeps
both the raw `uid`/`guid` index and the numeric ID it resolves to, routing basic inodes, extended inodes and
hard links sharing an index through one parsing path. An out-of-range or truncated table entry is reported as
an unknown identity (with the original index and reason), never coerced to zero, so a definite root-owned
setuid file is distinguished from one whose owner cannot be determined. Hard links are counted once per
underlying inode while retaining every path that reaches it.

```bash
python -m dissect.squashfs.audit firmware.sqfs            # text evidence report
python -m dissect.squashfs.audit firmware.sqfs --format json
```

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
