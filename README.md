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

## Offline activity correlation

Besides parsing, this module can correlate activities offline. Events are grouped by their `ActivityId`, linked
through the `RelatedActivityId` extended data item and attributed to process instances using the process start key,
so a reused PID does not merge two different processes. Only events carrying actual evidence are connected; missing
parent activities and ambiguous process attributions are reported separately, and cycles or multiple parents in the
activity graph are surfaced as anomalies instead of being forced into a tree. Every edge keeps the raw record
locations (buffer index, record offset and file offset) of both endpoints for manual review.

```python
from dissect.etl import ETL, correlate_etl

with open("dissect.etl", "rb") as fh:
    result = correlate_etl(ETL(fh))

print(result.render())
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
