# dissect.database

A Dissect module implementing parsers for various database formats, including:

- Berkeley DB, used for example in older RPM databases
- Microsofts Extensible Storage Engine (ESE), used for example in Active Directory, Exchange and Windows Update
- SQLite3, commonly used by applications to store configuration data

For more information, please see [the documentation](https://docs.dissect.tools/en/latest/projects/dissect.database/index.html).

## SQLite3 record evidence

The SQLite3 parser keeps a convenience `Row` interface and adds a lossless record view:

```python
from dissect.database.sqlite3 import SQLite3

with SQLite3("evidence.db") as db:
    for record in db.table("items").records():
        field = record.field("value")

        print(field.declared_type)   # e.g. "BLOB", the declared column type
        print(field.storage_class)   # actual storage class of this record
        print(field.serial_type)     # serial type, e.g. 7 for a real
        print(field.raw)             # the bytes as stored
        print(field.raw_range)       # (start, end) in the record payload
        print(field.file_ranges)     # byte ranges in the database file
        print(field.error)           # decoding error, if any
```

Records are parsed directly from the pages and never execute SQL from the database.
A field that cannot be decoded as text keeps its bytes and the decoding error; other
fields in the same record remain available.

## Installation

`dissect.database` is available on [PyPI](https://pypi.org/project/dissect.database/).

```bash
pip install dissect.database
```

This module is also automatically installed if you install the `dissect` package.

## Tools

Some CLI tools related to specific databases exists. These tools allow you to dump or inspect database content.

| Commands           | Description                                                                                                                                                       |
|--------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `dissect-ntds`     | Windows NTDS (Active Directory database).                                                                                                                         |
| `dissect-ual`      | Windows [User Access Logging](https://learn.microsoft.com/en-us/windows-server/administration/user-access-logging/get-started-with-user-access-logging) database. |
| `dissect-sru`      | Windows System Resources And Usage Monitor database.                                                                                                              |
| `dissect-certlog`  | Windows [AD CS database](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/active-directory-certificate-services-overview) database.                |
| `dissect-rpm`      | [Red Hat Package Manager](https://rpm.org/) database.                                                                                                             |
| `dissect-impacket` | Impacket compatibility shim for `secretsdump.py`.                                                                                                                 |

### Impacket compatibility shim for secretsdump.py

Impacket does not ([yet](https://github.com/fortra/impacket/pull/1452)) have native support for `dissect.database`,
so in the meantime a compatibility shim is provided. To use this shim, simply install `dissect.database` using the
instructions above, and execute `secretsdump.py` like so:

```bash
dissect-impacket /path/to/impacket/examples/secretsdump.py -h
```

Impacket `secretsdump.py` will now use `dissect.database` for parsing the `NTDS.dit` file, resulting in a significant performance improvement!

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

License terms: Apache License 2.0 (<https://www.apache.org/licenses/LICENSE-2.0>). For more information, see the LICENSE file.
