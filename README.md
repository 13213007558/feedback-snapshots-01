# dissect.etl

A Dissect module implementing a parser for Event Trace Log (ETL) files, used by the Windows operating system to log
kernel events. For more information, please see [the
documentation](https://docs.dissect.tools/en/latest/projects/dissect.etl/index.html).

## Requirements

This project is part of the Dissect framework and requires Python.

Information on the supported Python versions can be found in the Getting Started section of [the documentation](https://docs.dissect.tools/en/latest/index.html#getting-started).

## Installation

`dissect.etl` is available on [PyPI](https://pypi.org/project/dissect.etl/).

```bash
pip install dissect.etl
```

This module is also automatically installed if you install the `dissect` package.

## WPP MessageTrace records

WPP `MessageTrace` records start with an 8 byte `MESSAGE_HEADER` and are followed by an optional header whose contents
are selected by the record's `EventProperty` flags. `MessageTraceHeader` parses those values in the declared order
(sequence number, GUID, component id, timestamp, performance timestamp, system information) and exposes the untouched
message bytes after them:

```python
from dissect.etl import ETL
from dissect.etl.headers.headers import MessageTraceHeader

with open("sample.etl", "rb") as fh:
    for record in ETL(fh):
        header = record.header
        if not isinstance(header, MessageTraceHeader):
            continue

        print(header.sequence_number, header.process_id, header.thread_id)
        print(header.timestamp)  # None when the record carries no timestamp
        print(header.message)  # bytes after the optional header
        if header.truncated_fields:
            print("missing:", header.truncated_fields, header.truncation)
```

`timestamp` is only set when the record declares `TRACE_MESSAGE_TIMESTAMP`; the value is an absolute FILETIME and is
never anchored to the start of the logfile. A truncated optional header or record is reported through
`truncated_fields`, `truncation` and `record_truncated`, and `message_offset` stays `None` because the message boundary
cannot be established. `limitations` lists flags or values that are preserved but not interpreted, such as
conflicting pointer flags.

A runnable example that prints an investigation summary for a file, or a generated two-record demo, is available at
`examples/message_trace_investigation.py`:

```bash
python examples/message_trace_investigation.py sample.etl
python examples/message_trace_investigation.py --demo
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
