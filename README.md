# dissect.regf

A Dissect module implementing a parser for Windows registry file format, used to store application and OS configuration
on Windows operating systems. For more information, please see [the
documentation](https://docs.dissect.tools/en/latest/projects/dissect.regf/index.html).

## Requirements

This project is part of the Dissect framework and requires Python.

Information on the supported Python versions can be found in the Getting Started section of [the documentation](https://docs.dissect.tools/en/latest/index.html#getting-started).

## Installation

`dissect.regf` is available on [PyPI](https://pypi.org/project/dissect.regf/).

```bash
pip install dissect.regf
```

This module is also automatically installed if you install the `dissect` package.

## Offline composite views

`dissect.regf.RegistryView` composes explicitly supplied hive files
into registry paths such as `HKEY_LOCAL_MACHINE\SYSTEM` and
`HKEY_CURRENT_USER`. It never reads the registry of the analysis machine.

```python
from dissect.regf import RegistryHive, RegistryView

with open("SYSTEM", "rb") as system, open("SOFTWARE", "rb") as software, open("NTUSER.DAT", "rb") as ntuser:
    view = RegistryView(
        system=RegistryHive(system),
        software=RegistryHive(software),
        users={"S-1-5-21-1001": RegistryHive(ntuser)},
        user="S-1-5-21-1001",
    )

    key = view.open("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa")
    print(key.physical_path)  # e.g. ControlSet001\Control\Lsa
    print(key.expand())       # source hive, physical path and Select evidence
```

`CurrentControlSet` is resolved only from the SYSTEM hive's own `Select`
values. `Current`, `Default` and `LastKnownGood` are separate pointers and are
never used as fallbacks for each other. When `Select\Current` is missing or
refers to a control set that is not present, use `RegistryView(..., control_set=1)`
or `with_control_set(1)` to supply explicit physical context. When more than one
user hive is mounted, select a user with `with_user(sid)` or a path such as
`HKU\S-1-5-21-1001\...`.

Views are immutable: `with_user()` and `with_control_set()` return a new view,
and keys obtained from an earlier view keep their original source hive,
physical path and selection evidence.

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
