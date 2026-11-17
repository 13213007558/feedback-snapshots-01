# Offline RPZ rehearsal

This example pre-rehearses a DNS Response Policy Zone (RPZ) policy entirely
offline. No name server is started and no query is sent; the only inputs are
the local zone files and the JSON documents in this directory.

## Files

- `exceptions.rpz` — higher-priority policy zone (PASSTHRU exceptions).
- `threats.rpz` — lower-priority threat policy zone, including deliberately
  unsupported rules that the interpreter keeps pending.
- `config.json` — trusted configuration. The `zones` array order fixes policy
  priority; the first entry has the highest priority.
- `probes.json` — the offline probes (QNAME lookups and response addresses).
- `rehearse.py` — loads the zones and probes, then prints which rule fires,
  which candidates were overridden, the source RR behind each decision, and
  every pending (uninterpreted) rule.

## Run

From the repository root:

```sh
python examples/rpz_rehearsal/rehearse.py            # human-readable report
python examples/rpz_rehearsal/rehearse.py --json     # machine-readable report
```

## Scope

Only QNAME, `rpz-ip` and `rpz-ip6` triggers and the NXDOMAIN, NODATA and
PASSTHRU actions are interpreted. NSDNAME/NSIP triggers, wildcard address
triggers, non-CNAME action RRs, the legacy DROP action and unknown action
names are reported as pending and are never enforced. Synthetic policy
answers are marked as non-authoritative (the AA bit is never set).
