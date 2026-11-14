# Net::LDAP for Ruby

[![Gem Version](https://badge.fury.io/rb/net-ldap.svg?icon=si%3Arubygems)](https://badge.fury.io/rb/net-ldap)
[![Test Action Status](https://github.com/ruby-ldap/ruby-net-ldap/actions/workflows/test.yml/badge.svg)](https://github.com/ruby-ldap/ruby-net-ldap/actions/workflows/test.yml)

## Description

Net::LDAP for Ruby (also called net-ldap) implements client access for the
Lightweight Directory Access Protocol (LDAP), an IETF standard protocol for
accessing distributed directory services. Net::LDAP is written completely in
Ruby with no external dependencies. It supports most LDAP client features and a
subset of server features as well.

Net::LDAP has been tested against modern popular LDAP servers including
OpenLDAP and Active Directory. The current release is mostly compliant with
earlier versions of the IETF LDAP RFCs (2251–2256, 2829–2830, 3377, and 3771).
Our roadmap for Net::LDAP 1.0 is to gain full *client* compliance with
the most recent LDAP RFCs (4510–4519, plus portions of 4520–4532).

## Where

- [GitHub](https://github.com/ruby-ldap/ruby-net-ldap)
- [ruby-ldap@googlegroups.com](http://groups.google.com/group/ruby-ldap)

## Synopsis

See [Net::LDAP on rubydoc.info](https://www.rubydoc.info/gems/ruby-net-ldap/Net/LDAP) for documentation and usage samples.

## Requirements

Net::LDAP requires a Ruby 3.0.0 compatible interpreter or better.

## Install

Net::LDAP is a pure Ruby library. It does not require any external libraries.
You can install the RubyGems version of Net::LDAP available from the usual
sources.

```bash
gem install net-ldap
```

Simply require either `net-ldap` or `net/ldap`.

## Content Synchronization (RFC 4533)

`Net::LDAP#sync_refresh` runs one RFC 4533 `refreshOnly` content sync poll and
returns an atomic replacement for a locally held permission mirror. Entries are
correlated by their stable `entryUUID` (not their DN), and the change ledger is
keyed by UUID.

```ruby
# Persisted between polls: a UUID => Net::LDAP::Entry map and the last cookie.
state = load_checkpoint        # { entries: {...}, cookie: "..." } or nil
previous = state ? state[:entries] : {}
cookie   = state ? state[:cookie] : nil

result =
  ldap.sync_refresh(base: "ou=perms,dc=example,dc=org",
                    cookie: cookie,
                    previous_entries: previous)

replace_permissions(result.entries)        # swap the whole map atomically
save_checkpoint(entries: result.entries, cookie: result.cookie)

result.changelog # => { add: [...], modify: [...], present: [...], delete: [...] }
```

Two refresh shapes are handled and distinguished automatically:

- **Present phase** (`refreshDeletes=FALSE`): every surviving entry is named
  with `present` or carried as `add`/`modify`; entries never named are removed
  from the replacement.
- **Delete phase** (`refreshDeletes=TRUE`): only removed entries are named with
  `delete` (or a `syncIdSet`); every other previous entry is retained. A present
  phase followed by a delete phase is delimited by a `refreshPresent`
  Intermediate Response with `refreshDone=FALSE`.

### Checkpoint persistence

Persist the cookie **only together with** the fully materialized
`result.entries`, and only after `sync_refresh` returns. The returned cookie is
the one from the terminal Sync Done Control and is the sole valid checkpoint.
Cookies that arrive earlier (on Sync State Controls or Sync Info Messages) are
exposed for diagnostics via the consumer but must not be checkpointed: the
content they describe is not yet complete, so restarting from them can skip
unprocessed deletes.

### Why a failed refresh cannot continue from a half mirror

All messages are applied to private staging state; the caller's previous mirror
is never mutated. A replacement is published solely after a successful
SearchResultDone with a Sync Done Control. On a truncated stream, any
non-success result code (including `e-syncRefreshRequired`, raised as
`Net::LDAP::Sync::RefreshRequiredError`), or a contradictory protocol sequence,
a `Net::LDAP::Sync::Error` is raised and no result is available.

The half-applied staging data is unusable because present/delete semantics are
only defined relative to a *complete* refresh: in present mode an entry merely
not received yet would be indistinguishable from one that was deleted, and in
delete mode an unprocessed `delete` would leave a permission that should have
been revoked. Keep the previous mirror and checkpoint untouched, discard the
failed consumer, and retry the whole refresh (without a cookie for a full
reload, or with the cookie carried by `RefreshRequiredError` for an incremental
one).

## Extensions

This library focuses on the core LDAP RFCs referenced in the description.
However, we recognize there are commonly used extensions to the spec that are
useful. If there is another library which handles it, we list it here.

- [resolv-srv](https://rubygems.org/gems/resolv-srv): Support RFC2782 SRV record lookup and failover

## Develop

This task will run the test suite and the
[RuboCop](https://github.com/bbatsov/rubocop) static code analyzer.

```bash
rake rubotest
```

CI takes too long? If your local box supports
[Docker](https://www.docker.com/), you can also run integration tests locally.
Simply run:

```bash
script/ldap-docker
INTEGRATION=openldap rake test
```

Or, use [Docker Compose](https://docs.docker.com/compose/). See `docker-compose.yml` for available Ruby versions.

```bash
docker-compose run ci-4.0
```

**CAVEAT:** you need to add the following lines to `/etc/hosts`

```text
127.0.0.1 ldap.example.org
127.0.0.1 cert.mismatch.example.org
```

## Release

This section is for gem maintainers to cut a new version of the gem.

- Check out a new branch `release-VERSION`
- Update `lib/net/ldap/version.rb` to next version number `X.X.X` following [semver](http://semver.org/).
- Update `History.rdoc`. Get latest changes with `script/changelog`
- Open a pull request with these changes for review
- After merging, on the `master` branch, run `script/release`

## Contributors

See [Contributors.rdoc](Contributors.rdoc).

## License

See [License.rdoc](License.rdoc).
