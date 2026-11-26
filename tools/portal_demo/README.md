# Cloud build portal: staged PEP 723 script pipeline

A minimal, fully offline model of the build portal described in the security
review. Administrators can view the PEP 723 dependency summary of any external
single-file script, but preparing an environment or running the script requires
an execution approval for the exact content and the selected environment.

## The three states the portal keeps apart

| State       | Produced by                         | Side effects                                   |
|-------------|-------------------------------------|------------------------------------------------|
| `parsed`    | preview phase                       | metadata only; no virtualenv, no project command |
| `installed` | approved run, environment creation  | installer (`python -I -m pip install ...`) call |
| `executed`  | approved run, command execution     | interpreter (`python <script>`) call           |

A new version of a file at an already watched path is always previewable. It
gets a new content digest, so it cannot reuse the previous version's approval.
Reusing an existing, already warmed environment goes through the same decision
as creating a new one.

## Layout

- `portal/gateway.py` - the state machine: `preview()` parses with tox's own
  PEP 723 parser and runs `tox config --no-provision` (no environment is
  created); `request_execution()` re-checks the approval before launching tox.
- `portal/policy.py` - the platform baseline (vetted offline wheelhouse) and
  the approval store keyed by `(content sha256, environment)`.
- `portal/audit.py` - append-only audit trail, including the actual installer
  and interpreter argv harvested from tox's per-command execute logs.
- `portal_demo/tox.toml` - the explicit phased tox configuration:
  - `script-preview` inherits the PEP 723 runner settings but declares no
    commands and is only ever inspected via `tox config`;
  - `script-run` shares the same `env_dir` (`{work_dir}/script`), so an
    approved run reuses the environment the first run warmed;
  - `PIP_NO_INDEX=1` and `PIP_FIND_LINKS` pin installs to the approved
    wheelhouse, standing in for the platform's vetted index mirror.
- `fixtures/` - pristine script versions. The watched path is always
  `portal_demo/scripts/temp_script.py`; only its contents change.
- `wheelhouse/` + `baseline.json` - the approved baseline, built from the
  wheels virtualenv bundles (no network access required).
- `run_demo.py` - the end-to-end scenario; `tests/` - pytest coverage.

## Scenario

1. Preview a temporary PEP 723 script: parsed summary, no `.tox` created.
2. Approve its digest + `script-run`, then execute: the environment is created,
   the dependency is installed from the wheelhouse, and the script runs.
3. Re-request the same approved content: the cached environment is reused and
   no installer call happens.
4. Swap an ordinary script (no inline metadata) into the same path, keeping the
   cache: re-preview works, but an execution request without a new approval is
   blocked before any process launches.
5. Approve the new content: execution proceeds through the reused environment.

## Run it

```sh
# one-time: (re)build the offline wheelhouse and baseline manifest
.venv/bin/python tools/portal_demo/build_wheelhouse.py

# end-to-end scenario with evidence in tools/portal_demo/reports/
.venv/bin/python tools/portal_demo/run_demo.py

# behavior tests (standalone pytest config, no network)
.venv/bin/pytest tools/portal_demo
```

`reports/audit.json` records every invocation. The `installer` and
`project-command` phases capture the exact argv tox used internally; a
`denied` record means the gate stopped the request before a tox process was
started.
