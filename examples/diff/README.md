# Report diff example

A self-contained example where **both** the dependencies and the advisory
database change between two scans. Nothing here requires network access.

```
before/            yesterday's project (Gemfile.lock + .bundler-audit.yml)
after/             today's project
db_before/gems/    yesterday's advisory database snapshot
db_after/gems/     today's advisory database snapshot
```

Run it:

```shell
$ bundle-audit diff examples/diff/before examples/diff/after \
    --database-before examples/diff/db_before \
    --database-after  examples/diff/db_after
$ bundle-audit diff ... --format json   # machine-readable output
```

## What changed and how each difference is explained

| Gem | Finding | Classification | Causal evidence |
| --- | --- | --- | --- |
| `bar` | appeared | `new_dependency` | `bar` is absent from the before lockfile; the dependency change introduced the risk. |
| `rack` | appeared | `newly_disclosed` | `rack 2.0.8` is locked in both scans; `CVE-2026-1001` exists only in the after database. |
| `json` | appeared | `advisory_revised` | `CVE-2020-10663` exists in both databases, but its patched range moved from `>= 1.7.0` to `>= 2.4.0`, now covering the locked `1.8.0`. |
| `nokogiri` | appeared | `exemption_expired` | `CVE-2026-9999` flags `1.10.0` in both databases; the before config ignores it, the after config does not. |
| `ffi` | disappeared | `fixed` | `1.9.23-x64-mingw32` was upgraded to `1.9.24`, which the after database lists as patched. Platform is preserved in the output. |
| `mystery` | disappeared | `unexplained` | The advisory was withdrawn from the after database while the locked version stayed vulnerable, so the fix cannot be confirmed. |
| `baz` | no entry | — | The advisory file was renamed `CVE-2020-1234.yml` → `GHSA-aaaa-bbbb-cccc.yml` and retitled, but the shared CVE identifier keeps the findings matched; alias/title changes alone never create a difference. |

## Closing an alert

Every appeared entry prints its closure conditions:

* upgrade to one of the advisory's `patched_versions` (or move to an
  `unaffected_versions` range), or
* suppress it by adding one of the advisory's identifiers (CVE/GHSA) to the
  `ignore` list of `.bundler-audit.yml`.

An alert only disappears from a future diff as `fixed` when the after
database confirms the locked version is patched or unaffected (or the gem
is gone from the lockfile); otherwise it stays `unexplained`.
