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

## Local filter evaluation

`Net::LDAP::Filter#evaluate` evaluates a filter against a directory entry
locally, without contacting a directory server. This is useful for previewing
which entries an authorization rule would select before the rule is published.

Local evaluation is deliberately three-valued, following the filter evaluation
rules in RFC 4511 section 4.5.1.7:

- `:match` - the filter is definitely true for the entry.
- `:no_match` - the filter is definitely false for the entry.
- `:undetermined` - the local schema cannot decide the assertion. This includes
  unknown attribute descriptions, unknown or inappropriate matching rules,
  unsupported extensible matching (such as `dnAttributes`), and invalid
  assertion values.

Only an explicit `Net::LDAP::Filter::Schema` supplies matching behavior; no
rule is inferred from an attribute name. Consequently, a filter such as
`(!(clearanceLevel=secret))` evaluates to `:undetermined` rather than
`:match` when `clearanceLevel` is not declared, and never silently authorizes
the entry. `Filter#authorized?` returns true only for `:match`.

```ruby
schema = Net::LDAP::Filter::Schema.new(
  {
    "objectClass" => { equality: :case_ignore, substring: :case_ignore },
    "uid"         => { equality: :case_ignore },
    "mail"        => { equality: :case_ignore, substring: :case_ignore },
    "gidNumber"   => { equality: :integer, ordering: :integer },
  },
  {
    # Extensible matching rules must be registered explicitly, along with the
    # attribute descriptions they may be applied to.
    "2.5.13.2" => { rule: :case_ignore, attributes: ["uid", "mail"] },
  }
)

filter = Net::LDAP::Filter.construct("(&(objectClass=person)(!(uid=nobody)))")
result = filter.evaluate(entry, schema: schema)

result.state        # => :match, :no_match, or :undetermined
result.matched?     # => true only for :match
result.reason       # => diagnostic text for an undetermined or false result
filter.authorized?(entry, schema: schema) # => true only for :match
```

Supported schema rule kinds are `:case_ignore`, `:case_exact`,
`:octet_string`, and `:integer`. Substring matching accepts the first three.
An attribute option such as `;lang-fr` must itself be declared; options are not
inherited from the base attribute type. The supported filter operations are
AND, OR, NOT, presence, equality, substring, greater-or-equal,
less-or-equal, binary equality, and registered extensible matches.

Undetermined results propagate through compound filters exactly as RFC 4511
requires, and never become authorization matches:

| Filter | Result | Why |
| --- | --- | --- |
| `(uid=alice)` | `:match` | declared attribute, declared equality rule |
| `(&(uid=alice)(missing=x))` | `:undetermined` | AND has no false child, but one child is undetermined |
| `(&(uid=alice)(sn=nobody))` | `:no_match` | AND has a definitely false child |
| `(|(uid=nobody)(missing=x))` | `:undetermined` | OR has no true child and one child is undetermined |
| OR: `(uid=alice)` plus `(missing=x)` | `:match` | OR has a definitely true child |
| `(!(missing=x))` | `:undetermined` | NOT preserves undetermined instead of becoming `:match` |
| `(uid:9.9.9:=alice)` | `:undetermined` | extensible rule is not registered |

Previewing a directory sample is a loop over entries:

```ruby
entries = Net::LDAP::Dataset.read_ldif(File.open("sample.ldif")).to_entries
rule = Net::LDAP::Filter.construct("(&(objectClass=person)(!(uid=nobody)))")

entries.each do |entry|
  puts "#{entry.dn}: #{rule.evaluate(entry, schema: schema).state}"
end
```

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
