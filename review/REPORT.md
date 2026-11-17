# http-cookie / domain_name upgrade review: public suffixes and parent-domain cookies

Scope: `http-cookie` as checked out here (`1.2.0.beta`, Ruby 4.0.7), with
`domain_name` 0.6.20240107 installed against the gemspec constraint
`~> 0.5` (`http-cookie.gemspec:33`). No live site is contacted and no
production cookie store is read; every origin and probe URL is a synthetic
`http://` literal and all suffix input comes from `review/fixtures/`.

## Verdict

The upgrade is **safe to take for name matching, but it changes one
authorization boundary**. The only modeled data delta (`web.app` becoming a
suffix) makes `Set-Cookie: Domain=web.app` newly rejectable. Host-only
cookies, cookies below the new suffix, multi-level ICANN suffixes, wildcard
and exception rules, and an existing private suffix (`github.io`,
`s3.amazonaws.com`) are unchanged.

Two operational rules follow from the evidence:

- **Refuse new declarations** that name a suffix. The library already does
  this; keep it and test it.
- **Re-review stored records separately.** Do not widen, and do not
  "migrate", an existing cookie just because its displayed `domain` string
  is unchanged. Both persisted formats still contain `web.app`; what changes
  is the scope they are *allowed* to reach at send time.

A library change is **not required** for the security question. A review
must not, however, assume that dropping the pinned data refreshes suffix
semantics without re-auditing stored rows.

## Where the classification comes from

`HTTP::Cookie#domain=` consults exactly one gate:

```ruby
# lib/http/cookie.rb:419
if domain_name.domain.nil? # a public suffix or IP address
  @for_domain = false
```

`DomainName#domain` is nil when the name is itself a suffix (or an IP), and
that nil is what turns a `Domain=` declaration into a host-only cookie.
`#acceptable_from_uri?` then asks `DomainName#cookie_domain?`
(`lib/http/cookie.rb:565`), which for non-host-only cookies requires the
host and the declaration to share a registrable domain
(`domain_name.rb:162`). `#valid_for_uri?` reuses that check for the Cookie
header (`lib/http/cookie.rb:589`).

`domain_name` builds the table by merging every PSL rule into one hash
(`tool/gen_etld_data.rb:46-57`): plain rules become `0`, `*.` rules become
`-1`, and `!` exceptions become `1`. **The ICANN vs PRIVATE section is
discarded at generation time.** http-cookie therefore cannot tell a
"private" suffix from an ICANN one; both are simply `domain` = nil. The
report below attributes the change to the PSL rule and section anyway,
because that is the reviewable source fact.

## Fixed catalogs and the modeled delta

- `review/fixtures/psl-baseline.txt`
- `review/fixtures/psl-upgraded.txt`

Both are scoped excerpts, not general-purpose PSL copies. The upgraded file
was verified rule-by-rule against the installed
`lib/domain_name/etld_data.rb` (all 11 rules match; `web.app` => `0`). The
baseline is a reviewed reconstruction whose *only* difference is the absence
of `web.app`, so every observed difference below is attributable to that one
rule. Provenance, not just outcome, is in `review/output/upgrade-matrix.json`
under `catalog_diff` and `classification.<host>.deciding_rules`.

Catalog diff:

| rule | value | PSL section | source line (upgraded fixture) |
|---|---|---|---|
| `web.app` | 0 (plain) | PRIVATE | 26 |

Rules held constant: `com`, `jp`, `co.jp`, `*.kawasaki.jp`,
`!city.kawasaki.jp`, `app`, `dev`, `io`, `github.io`, `s3.amazonaws.com`.

## Method

`review/run_review.rb` injects each catalog into `DomainName.etld_data` for
the duration of a run and restores the original method in `ensure`
(`review/domain_upgrade_review.rb`). Every result is then produced by the
real `HTTP::Cookie.parse` / `HTTP::CookieJar#cookies` code path, and the
reported value is the actual `Cookie` header string. Legacy rows are replayed
through the real `HTTP::CookieJar#load` for YAML and cookies.txt.

Run:

```console
$ ruby review/run_review.rb          # table + review/output/upgrade-matrix.json
$ ruby review/run_tests.rb           # 9 regression tests
$ ruby .feedback/baseline.rb         # upstream suite, unchanged: 99 tests / 2684 assertions
```

## Observed results

### Newly rejected (the security-relevant change)

`Set-Cookie: sid=parent-web-app; Domain=web.app; Path=/` from
`http://alice.web.app/`.

| phase | `web.app/` | `alice.web.app/` | `bob.web.app/` |
|---|---|---|---|
| baseline | `sid=parent-web-app` | `sid=parent-web-app` | `sid=parent-web-app` |
| upgraded | *(empty)* | *(empty)* | *(empty)* |

Why: under the baseline `web.app` is an ordinary registrable name, so the
declaration is a legitimate parent-domain cookie. Under the upgraded
catalog `web.app` is a PRIVATE suffix, `domain` becomes nil, the intended
`for_domain` is negated (`lib/http/cookie.rb:419-420`), and the declaration
is refused because the origin host `alice.web.app` does not match the suffix
host-only (`lib/http/cookie.rb:562`). Note `accepted` is 0, not
"accepted but unsent": `HTTP::Cookie.parse` drops it at
`lib/http/cookie.rb:323`.

### Unchanged, and why that is the correct control

| scenario | Set-Cookie (from) | baseline Cookie | upgraded Cookie |
|---|---|---|---|
| host-only `web.app` | `sid=host-web-app; Path=/` (`web.app`) | `web.app/`=`sid=host-web-app`; `alice.web.app/`=empty | identical |
| host-only `alice.web.app` | `sid=host-alice; Path=/` (`alice.web.app`) | `alice.web.app/`=`sid=host-alice`; `bob.web.app/`=empty | identical |
| below the new suffix | `sid=child; Domain=alice.web.app; Path=/` (`api.alice.web.app`) | `api.`+`www.alice.web.app/`=`sid=child`; `bob.web.app/`=empty | identical |
| multi-level ICANN | `sid=co-jp; Domain=example.co.jp; Path=/` (`shop.example.co.jp`) | `shop.`+`other.example.co.jp/`=`sid=co-jp`; `notexample.co.jp/`=empty | identical |
| ICANN suffix itself | `sid=co-jp-suffix; Domain=co.jp; Path=/` | empty everywhere | identical |
| private suffix (pre-existing) | `sid=github-parent; Domain=github.io; Path=/` (`alice.github.io`) | empty | identical |
| below that private suffix | `sid=child; Domain=alice.github.io; Path=/` (`api.alice.github.io`) | `api.`+`www.alice.github.io/`=`sid=child`; `bob.github.io/`=empty | identical |
| wildcard rule | `sid=kawasaki; Domain=a.foo.kawasaki.jp; Path=/` (`www.a.foo.kawasaki.jp`) | `www.a.`+`api.a.foo.kawasaki.jp/`=`sid=kawasaki`; `www.b.foo.kawasaki.jp/`=empty | identical |
| wildcard exception | `sid=city-kawasaki; Domain=city.kawasaki.jp; Path=/` (`www.city.kawasaki.jp`) | `www.city.kawasaki.jp/`=`sid=city-kawasaki`; `www.foo.kawasaki.jp/`=empty | identical |
| private suffix `s3` | `sid=s3; Domain=s3.amazonaws.com; Path=/` (`bucket.s3.amazonaws.com`) | empty | identical |
| local-TLD fallback | `sid=local; Domain=example.local; Path=/` (`www.example.local`) | `www.`+`other.example.local/`=`sid=local` | identical |
| local-TLD single label | `sid=local-suffix; Domain=local; Path=/` | empty | identical |

These establish the blast radius: **only a declaration whose `Domain=` is
exactly a newly-added suffix changes**. Registrable names below it, host-only
cookies, and every other rule kind keep the same wire output.

### Stored cookies: reject-new and re-review-old are different operations

Two legacy records persisted by 1.1.x are replayed through the real loaders.
They share `web.app` in storage; the two formats differ in what they keep in
memory.

`legacy-web-app.yml` (YAML) after upgrade:

| record | stored `domain` | stored `for_domain` | `web.app/` | `alice.web.app/` | `bob.web.app/` |
|---|---|---|---|---|---|
| `legacy_parent` | `web.app` | **true** (preserved) | `legacy_parent=from-parent-record` | *(empty)* | *(empty)* |
| `legacy_host` | `web.app` | false | `legacy_host=from-host-record` | *(empty)* | *(empty)* |

`legacy-web-app.cookies.txt` after upgrade:

| record | stored `domain` | stored `for_domain` | `web.app/` | `alice.web.app/` | `bob.web.app/` |
|---|---|---|---|---|---|
| `legacy_parent` | `web.app` | **false** (recomputed on load) | `legacy_parent=from-parent-record` | *(empty)* | *(empty)* |
| `legacy_host` | `web.app` | false | `legacy_host=from-host-record` | *(empty)* | *(empty)* |

Both formats stop delivering to `alice.web.app`/`bob.web.app`, because
`valid_for_uri?` re-evaluates the scope at send time. But:

- YAML restores `@for_domain` verbatim, so the row *still claims* parent
  scope in memory (`for_domain=true`) even though the suffix gate refuses it.
  Any later export or tool that trusts the flag without re-checking the
  classification can reintroduce the wider scope.
- cookies.txt re-runs `HTTP::Cookie#domain=` while loading, which silently
  rewrites the same record to `for_domain=false`
  (`lib/http/cookie_jar/cookiestxt_saver.rb:33`). The displayed domain is
  identical; the authorization meaning is not.

`DomainUpgradeReview.reaudit` therefore reports
`display_domain_unchanged=true` **and** `recommendation=keep_narrowed` for
both. "Keep" means do not delete or widen a working narrowed record; it does
**not** mean the record is acceptable as a fresh declaration. The regression
test `test_legacy_reaudit_is_separate_from_new_cookie_rejection` pins that
separation: a fresh `Domain=web.app` is still refused while the legacy row is
retained.

## What changes, attributed

| observation | source of the change |
|---|---|
| `Domain=web.app` rejected | `web.app` exists only in the upgraded catalog, PSL **PRIVATE** section, plain rule (`value=0`) |
| declaration becomes host-only in memory | `domain_name.domain` nil at `lib/http/cookie.rb:419`, so `@for_domain` is negated at `:420` |
| new cookie dropped entirely | `acceptable_from_uri?` fails via `DomainName#cookie_domain?` (`lib/http/cookie.rb:565`, `domain_name.rb:162`), and `parse` skips it (`lib/http/cookie.rb:323`) |
| host-only and below-suffix rows | no applicable rule changed; `domain` stays non-nil |
| `github.io` / `s3.amazonaws.com` rows | PRIVATE in **both** catalogs; classification unchanged |
| wildcard/exception rows | `-1`/`1` rule semantics unchanged in both catalogs |
| stored record still in jar | stores do not re-run acceptance on load (`yaml_saver.rb:43`, `cookiestxt_saver.rb:33`); only send-time matching changes |

## Upgrade guidance

1. Treat the gemspec `~> 0.5` as misleading: 0.6.x satisfies it
   (`Gem::Requirement.new("~> 0.5").satisfied_by?("0.6.20240107")` is true),
   so a data-only change can arrive without a major-version signal. Pin
   `domain_name` explicitly if data refreshes must be reviewed first.
2. Do not re-add stored cookies through a path that resets `for_domain` from
   the string alone. For legacy rows, re-audit against the new catalog and
   keep the narrowed behavior; quarantine any row whose reachable send set
   *grows*.
3. Add regression coverage for exactly two assertions: a fresh
   suffix-parent declaration is refused, and a stored record is not
   auto-migrated into a wider scope. `review/test_domain_upgrade_review.rb`
   is a portable starting point.
4. Keep the ICANN/PRIVATE distinction in the review record even though
   `domain_name` erases it. "Private suffix added" and "ICANN rule changed"
   have different trust implications for scraped multi-tenant hosts.

## Reproducibility and limits

- `review/output/upgrade-matrix.json` carries the full matrix, catalog diff,
  per-host deciding rules, and explicit `meta.network_used: false` /
  `meta.cookies_read_from_disk: false` markers.
- The baseline catalog is a reconstruction, not a historical artifact
  digest; the report claims only the modeled delta above.
- Only the portable HashStore is exercised (matches the prepared baseline;
  sqlite3 is not installed). MozillaStore is not covered here.
- No real PSL refresh, DNS lookup, or site traffic was performed.
