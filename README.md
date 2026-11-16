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

## Extended attributes and file capabilities

`INode` exposes SquashFS extended attributes, including values stored in the shared
out-of-line value area. Each attribute retains its full name and provenance:

```python
squashfs = SquashFS(fh)
inode = squashfs.get("/bin/busybox")

for attribute in inode.xattrs:
    print(attribute.name, attribute.value, attribute.source)
```

For static firmware auditing, `INode.file_capabilities(namespace_rootid=...)` decodes
the `security.capability` attribute. The report keeps the raw stored value, the
applicability and origin of every capability set, recognised capability names, and
unrecognised bit positions. It distinguishes the stored declaration from the
conclusion for the caller-supplied user namespace:

```python
report = inode.file_capabilities(namespace_rootid=0)
print(report.declaration.permitted.names)
print(report.namespace.effective, report.namespace.reason)
```

Revision 3 values are matched against the supplied namespace rootid. Revision 2
values are only valid in the initial user namespace. Unknown revisions, truncated
values and conflicting attributes never produce a definite "effective" conclusion.
`SquashFS.iter_file_capabilities(namespace_rootid=...)` walks the filesystem without
reading or executing any file contents.
