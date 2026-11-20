# Per-environment trust config demo

A small verification service that checks internal *preview* and official
*release* packages, where each environment loads its own fixed-identity,
versioned trust configuration.

Guarantees demonstrated:

- **Fixed identity per environment** — a config declares its environment;
  updates into a slot must carry the same identity and a strictly greater
  version, and are swapped in atomically.
- **Consistent root material mid-swap** — a verification that has already
  started (`VerificationSession`) keeps the immutable config snapshot it
  began with, even if the config is rotated meanwhile.
- **Inspectable version** — `TrustConfigManager.current_version(env)`
  reports the active config version.
- **No cross-environment borrowing** — if one environment's config is
  unavailable, verification fails instead of falling back to the other
  environment's root material.

Run the scenario demo (generates two local configs and two valid
artifacts in a temp dir):

```sh
.venv/bin/python -m demo.demo
```

Run the tests:

```sh
.venv/bin/python -m pytest -q test/unit/test_trust_config_service.py
```
