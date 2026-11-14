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

### Active Directory ranged attributes

Active Directory splits large multi-valued attributes such as `member` into
ranges (`member;range=0-1499`, `member;range=1500-*`). `read_ranged_attribute`
reads every slice of one object and proves the result is complete before it
can be used as a permission snapshot.

```ruby
result = ldap.read_ranged_attribute(dn: group_dn, attribute: "member")

if result.replaceable?
  # Every range was contiguous, the terminal "*" range was seen, and the
  # object identity/version stayed stable. result.values is safe to apply.
  replace_permission_snapshot(group_dn, result.values)
elsif result.retryable?
  # Never resume from the last offset: retry the whole read from range 0.
  schedule_full_retry(group_dn, result.reason)
else
  alert(group_dn, result.reason)
end
```

`result.values` raises `Net::LDAP::IncompleteAttributeError` when the read is
incomplete; `result.partial_values` exists only for diagnostics. A complete
read with no values reports `complete? == true` and `empty? == true`, which is
deliberately different from an unfinished read.

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
