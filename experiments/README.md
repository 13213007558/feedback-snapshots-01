# Offline CIM recoverability experiment

Review question: what can `dissect.cim` recover from disk for every class
property, including dynamic properties and qualifiers?

Files:

- `CIM_OFFLINE_RECOVERABILITY.md` — findings, capability table, and the split
  between "fixable from existing bytes" and "requires extra collection".
- `cim_recoverability_probe.py` — runnable probe. Re-parses the instance tail
  itself and labels every result as `stored`, `default`, `uninitialized`,
  `unsupported`, `unavailable`, or `conflict`. Never prints `""`/`False` for
  unknown data.
- `test_cim_recoverability_probe.py` — regression tests pinning each state.
- `SOURCE_MAP.md` — source locations for each behavior.

```sh
.venv/bin/python experiments/cim_recoverability_probe.py --data tests/_data
.venv/bin/python experiments/cim_recoverability_probe.py --data tests/_data --json
.venv/bin/python -m pytest -q -o addopts= experiments/test_cim_recoverability_probe.py
```

No live WMI access is used. `--data` accepts raw CIM files or the repository's
gzipped fixture directory.
