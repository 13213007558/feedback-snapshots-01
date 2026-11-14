<p align="center">
    <a href="http://oauth.net/core/1.0/" target="_blank" rel="noopener">
      <img width="124px" src="https://github.com/oauth-xx/oauth-ruby/raw/main/docs/images/logo/Oauth_logo.svg?raw=true" alt="OAuth 1.0 Logo by Chris Messina, CC BY-SA 3.0, via Wikimedia Commons">
    </a>
    <a href="https://www.ruby-lang.org/" target="_blank" rel="noopener">
      <img width="124px" src="https://github.com/oauth-xx/oauth-ruby/raw/main/docs/images/logo/ruby-logo-198px.svg?raw=true" alt="Yukihiro Matsumoto, Ruby Visual Identity Team, CC BY-SA 2.5">
    </a>
</p>

# Ruby OAuth

OAuth 1.0 is an industry-standard protocol for authorization.

This is a RubyGem for implementing both OAuth 1.0 clients and servers in Ruby applications.
See the sibling `oauth2` gem for OAuth 2.0 implementations in Ruby.

* [OAuth 1.0 Spec][oauth1-spec]
* [oauth2 sibling gem][sibling-gem] for OAuth 2.0 implementations in Ruby.

[oauth1-spec]: http://oauth.net/core/1.0/
[sibling-gem]: https://github.com/oauth-xx/oauth-ruby

**New EOL Policy**

Versions 1.0.x will be EOL no later than April, 2025.
Versions 0.6.x will be EOL no later than April, 2024.
Versions 0.5.x will be EOL no later than April, 2023.

This will facilitate dropping support for old, dead, and crusty versions of Ruby.

Non-commercial support for the oldest version of Ruby (which itself is going EOL) will be dropped each year in April.

Please upgrade to version 1.0.  The only breaking change in 1.0 is dropping old Rubies.

## Status

<!--
Numbering rows and badges in each row as a visual "database" lookup,
    as the table is extremely dense, and it can be very difficult to find anything
Putting one on each row here, to document the emoji that should be used, and for ease of copy/paste.

row #s:
1️⃣
2️⃣
3️⃣
4️⃣
5️⃣
6️⃣
7️⃣

badge #s:
⛳️
🖇
🏘
🚎
🖐
🧮
📗

appended indicators:
♻️ - URL needs to be updated from SASS integration. Find / Replace is insufficient.
-->

|     | Project               | bundle add oauth                                                                                                                                                                                                                                                                                |
|:----|-----------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1️⃣ | name, license, docs   | [![RubyGems.org][⛳️name-img]][⛳️gem] [![License: MIT][🖇src-license-img]][🖇src-license] [![RubyDoc.info][🚎yard-img]][🚎yard]                                                                                                                                                                  |
| 2️⃣ | version & activity    | [![Gem Version][⛳️version-img]][⛳️gem] [![Total Downloads][🖇DL-total-img]][⛳️gem] [![Download Rank][🏘DL-rank-img]][⛳️gem] [![Source Code][🚎src-home-img]][🚎src-home] [![Open PRs][🖐prs-o-img]][🖐prs-o] [![Closed PRs][🧮prs-c-img]][🧮prs-c] <!--[![Next Version][📗next-img]][📗next]--> |
| 3️⃣ | maintenance & linting | [![Maintainability][⛳cclim-maint-img♻️]][⛳cclim-maint] [![Helpers][🖇triage-help-img]][🖇triage-help] [![Depfu][🏘depfu-img♻️]][🏘depfu♻️] [![Contributors][🚎contributors-img]][🚎contributors] [![Style][🖐style-wf-img]][🖐style-wf] [![Kloc Roll][🧮kloc-img]][🧮kloc]                      |
| 4️⃣ | testing               | [![Open Issues][⛳iss-o-img]][⛳iss-o] [![Closed Issues][🖇iss-c-img]][🖇iss-c] [![Supported][🏘sup-wf-img]][🏘sup-wf] [![Heads][🚎heads-wf-img]][🚎heads-wf] [![MacOS][🧮mac-wf-img]][🧮mac-wf] [![Windows][📗win-wf-img]][📗win-wf]                                                             |
| 5️⃣ | coverage & security   | [![CodeClimate][⛳cclim-cov-img♻️]][⛳cclim-cov] [![CodeCov][🖇codecov-img♻️]][🖇codecov] [![Coveralls][🏘coveralls-img]][🏘coveralls] [![Security Policy][🚎sec-pol-img]][🚎sec-pol] [![CodeQL][🖐codeQL-img]][🖐codeQL] [![Code Coverage][🧮cov-wf-img]][🧮cov-wf]                              |
| 6️⃣ | resources             | [![Discussion][⛳gh-discussions-img]][⛳gh-discussions] [![Get help on Codementor][🖇codementor-img]][🖇codementor] [![Chat][🏘chat-img]][🏘chat] [![Blog][🚎blog-img]][🚎blog] [![Blog][🖐wiki-img]][🖐wiki]                                                                                     |
| 7️⃣ | spread 💖             | [![Liberapay Patrons][⛳liberapay-img]][⛳liberapay] [![Sponsor Me][🖇sponsor-img]][🖇sponsor] [![Tweet @ Peter][🏘tweet-img]][🏘tweet] [🌏][aboutme] [👼][angelme] [💻][coderme]                                                                                                                 |

<!--
The link tokens in the following sections should be kept ordered by the row and badge numbering scheme
-->

<!-- 1️⃣ name, license, docs -->
[⛳️gem]: https://rubygems.org/gems/oauth
[⛳️name-img]: https://img.shields.io/badge/name-oauth-brightgreen.svg?style=flat
[🖇src-license]: https://opensource.org/licenses/MIT
[🖇src-license-img]: https://img.shields.io/badge/License-MIT-green.svg
[🚎yard]: https://www.rubydoc.info/github/oauth-xx/oauth-ruby
[🚎yard-img]: https://img.shields.io/badge/documentation-rubydoc-brightgreen.svg?style=flat

<!-- 2️⃣ version & activity -->
[⛳️version-img]: http://img.shields.io/gem/v/oauth.svg
[🖇DL-total-img]: https://img.shields.io/gem/dt/oauth.svg
[🏘DL-rank-img]: https://img.shields.io/gem/rt/oauth.svg
[🚎src-home]: https://github.com/oauth-xx/oauth-ruby
[🚎src-home-img]: https://img.shields.io/badge/source-github-brightgreen.svg?style=flat
[🖐prs-o]: https://github.com/oauth-xx/oauth-ruby/pulls
[🖐prs-o-img]: https://img.shields.io/github/issues-pr/oauth-xx/oauth-ruby
[🧮prs-c]: https://github.com/oauth-xx/oauth-ruby/pulls?q=is%3Apr+is%3Aclosed
[🧮prs-c-img]: https://img.shields.io/github/issues-pr-closed/oauth-xx/oauth-ruby
[📗next]: https://github.com/oauth-xx/oauth-ruby/milestone/1
[📗next-img]: https://img.shields.io/github/milestones/progress/oauth-xx/oauth-ruby/1?label=Next%20Version

<!-- 3️⃣ maintanence & linting -->
[⛳cclim-maint]: https://codeclimate.com/github/oauth-xx/oauth-ruby/maintainability
[⛳cclim-maint-img♻️]: https://api.codeclimate.com/v1/badges/3cf23270c21e8791d788/maintainability
[🖇triage-help]: https://www.codetriage.com/oauth-xx/oauth-ruby
[🖇triage-help-img]: https://www.codetriage.com/oauth-xx/oauth-ruby/badges/users.svg
[🏘depfu♻️]: https://depfu.com/github/oauth-xx/oauth-ruby?project_id=22868
[🏘depfu-img♻️]: https://badges.depfu.com/badges/d570491bac0ad3b0b65deb3c82028327/count.svg
[🚎contributors]: https://github.com/oauth-xx/oauth-ruby/graphs/contributors
[🚎contributors-img]: https://img.shields.io/github/contributors-anon/oauth-xx/oauth-ruby
[🖐style-wf]: https://github.com/oauth-xx/oauth-ruby/actions/workflows/style.yml
[🖐style-wf-img]: https://github.com/oauth-xx/oauth-ruby/actions/workflows/style.yml/badge.svg
[🧮kloc]: https://www.youtube.com/watch?v=dQw4w9WgXcQ
[🧮kloc-img]: https://img.shields.io/tokei/lines/github.com/oauth-xx/oauth-ruby

<!-- 4️⃣ testing -->
[⛳iss-o]: https://github.com/oauth-xx/oauth-ruby/issues
[⛳iss-o-img]: https://img.shields.io/github/issues-raw/oauth-xx/oauth-ruby
[🖇iss-c]: https://github.com/oauth-xx/oauth-ruby/issues?q=is%3Aissue+is%3Aclosed
[🖇iss-c-img]: https://img.shields.io/github/issues-closed-raw/oauth-xx/oauth-ruby
[🏘sup-wf]: https://github.com/oauth-xx/oauth-ruby/actions/workflows/supported.yml
[🏘sup-wf-img]: https://github.com/oauth-xx/oauth-ruby/actions/workflows/supported.yml/badge.svg
[🚎heads-wf]: https://github.com/oauth-xx/oauth-ruby/actions/workflows/heads.yml
[🚎heads-wf-img]: https://github.com/oauth-xx/oauth-ruby/actions/workflows/heads.yml/badge.svg
[🧮mac-wf]: https://github.com/oauth-xx/oauth-ruby/actions/workflows/macos.yml
[🧮mac-wf-img]: https://github.com/oauth-xx/oauth-ruby/actions/workflows/macos.yml/badge.svg
[📗win-wf]: https://github.com/oauth-xx/oauth-ruby/actions/workflows/windows.yml
[📗win-wf-img]: https://github.com/oauth-xx/oauth-ruby/actions/workflows/windows.yml/badge.svg

<!-- 5️⃣ coverage & security -->
[⛳cclim-cov]: https://codeclimate.com/github/oauth-xx/oauth-ruby/test_coverage
[⛳cclim-cov-img♻️]: https://api.codeclimate.com/v1/badges/3cf23270c21e8791d788/test_coverage
[🖇codecov-img♻️]: https://codecov.io/gh/oauth-xx/oauth-ruby/branch/main/graph/badge.svg?token=4ZNAWNxrf9
[🖇codecov]: https://codecov.io/gh/oauth-xx/oauth-ruby
[🏘coveralls]: https://coveralls.io/github/oauth-xx/oauth-ruby?branch=main
[🏘coveralls-img]: https://coveralls.io/repos/github/oauth-xx/oauth-ruby/badge.svg?branch=main
[🚎sec-pol]: https://github.com/oauth-xx/oauth-ruby/blob/main/SECURITY.md
[🚎sec-pol-img]: https://img.shields.io/badge/security-policy-brightgreen.svg?style=flat
[🖐codeQL]: https://github.com/oauth-xx/oauth-ruby/security/code-scanning
[🖐codeQL-img]: https://github.com/oauth-xx/oauth-ruby/actions/workflows/codeql-analysis.yml/badge.svg
[🧮cov-wf]: https://github.com/oauth-xx/oauth-ruby/actions/workflows/coverage.yml
[🧮cov-wf-img]: https://github.com/oauth-xx/oauth-ruby/actions/workflows/coverage.yml/badge.svg

<!-- 6️⃣ resources -->
[⛳gh-discussions]: https://github.com/oauth-xx/oauth-ruby/discussions
[⛳gh-discussions-img]: https://img.shields.io/github/discussions/oauth-xx/oauth-ruby
[🖇codementor]: https://www.codementor.io/peterboling?utm_source=github&utm_medium=button&utm_term=peterboling&utm_campaign=github
[🖇codementor-img]: https://cdn.codementor.io/badges/get_help_github.svg
[🏘chat]: https://gitter.im/oauth-xx/oauth-ruby
[🏘chat-img]: https://img.shields.io/gitter/room/oauth-xx/oauth-ruby.svg
[🚎blog]: http://www.railsbling.com/tags/oauth-ruby/
[🚎blog-img]: https://img.shields.io/badge/blog-railsbling-brightgreen.svg?style=flat
[🖐wiki]: https://github.com/oauth-xx/oauth-ruby/wiki
[🖐wiki-img]: https://img.shields.io/badge/wiki-examples-brightgreen.svg?style=flat

<!-- 7️⃣ spread 💖 -->
[⛳liberapay-img]: https://img.shields.io/liberapay/patrons/pboling.svg?logo=liberapay
[⛳liberapay]: https://liberapay.com/pboling/donate
[🖇sponsor-img]: https://img.shields.io/badge/sponsor-pboling.svg?style=social&logo=github
[🖇sponsor]: https://github.com/sponsors/pboling
[🏘tweet-img]: https://img.shields.io/twitter/follow/galtzo.svg?style=social&label=Follow
[🏘tweet]: http://twitter.com/galtzo

<!-- Maintainer Contact Links -->
[railsbling]: http://www.railsbling.com
[peterboling]: http://www.peterboling.com

## Installation

Install the gem and add to the application's Gemfile by executing:

    $ bundle add oauth

If bundler is not being used to manage dependencies, install the gem by executing:

    $ gem install oauth

## OAuth for Enterprise

Available as part of the Tidelift Subscription.

The maintainers of OAuth2 and thousands of other packages are working with Tidelift to deliver commercial support and maintenance for the open source packages you use to build your applications. Save time, reduce risk, and improve code health, while paying the maintainers of the exact packages you use. [Learn more.](https://tidelift.com/subscription/pkg/rubygems-oauth?utm_source=rubygems-oauth&utm_medium=referral&utm_campaign=enterprise)

## Security contact information [![Security Policy][🚎sec-pol-img]][🚎sec-pol]

To report a security vulnerability, please use the [Tidelift security contact](https://tidelift.com/security).
Tidelift will coordinate the fix and disclosure.

For more see [SECURITY.md][🚎sec-pol].

## Compatibility

Targeted ruby compatibility is non-EOL versions of Ruby, currently 2.7, 3.0, and
3.1. Ruby is limited to 2.7+ in the gemspec, and this will change with minor version bumps,
while the gem is still in 0.x, in accordance with the SemVer spec.

The `main` branch now targets 1.0.x releases, for Ruby >= 2.7.
See `v0.6-maintenance` (EOL April, 2024) branch for Ruby >= 2.4.
See `v0.5-maintenance` (EOL April, 2023) branch for Ruby >= 2.0.

NOTE: No further releases of version < 1.0.x are anticipated.

<details>
  <summary>Ruby Engine Compatibility Policy</summary>

This gem is tested against MRI, and to a lesser extent, against JRuby, and Truffleruby.
Each of those has varying versions that target a specific version of MRI Ruby.
This gem should work in the just-listed Ruby engines according to the targeted MRI compatibility in the table below.
If you would like to add support for additional engines,
first make sure Github Actions supports the engine,
then submit a PR to the correct maintenance branch as according to the table below.
</details>

<details>
  <summary>Ruby Version Compatibility Policy</summary>

If something doesn't work on one of these interpreters, it's a bug.

This library may inadvertently work (or seem to work) on other Ruby
implementations, however support will only be provided for the versions listed
above.

If you would like this library to support another Ruby version, you may
volunteer to be a maintainer. Being a maintainer entails making sure all tests
run and pass on that implementation. When something breaks on your
implementation, you will be responsible for providing patches in a timely
fashion. If critical issues for a particular implementation exist at the time
of a major release, support for that Ruby version may be dropped.
</details>

|     | Ruby OAuth Version | Maintenance Branch | EOL       | 🚂 Compatibility       | Official 💎          | Unofficial 💎                | Incidental 💎 |
|:----|--------------------|--------------------|-----------|------------------------|----------------------|------------------------------|---------------|
| 1️⃣ | 1.0.x              | `main`             |           | Rails 6, 7             | 2.7, 3.0, 3.1        | sorry, not sorry             | nope          |
| 2️⃣ | 0.6.x              | `v0.6-maintenance` | 04/2024   | Rails 5, 6, 7          | 2.7, 3.0, 3.1        | 2.5, 2.6                     | 2.4           |
| 3️⃣ | 0.5.x              | `v0.5-maintenance` | 04/2023   | Rails 2, 3, 4, 5, 6, 7 | 2.7, 3.0, 3.1        | 2.1, 2.2, 2.3, 2.4, 2.5, 2.6 | 2.0           |
| 4️⃣ | older              | N/A                | yesterday |                        | Best of luck to you! | Please upgrade!              | noop          |

NOTE: Once 1.0 is released, the 0.x series will only receive critical bug and security updates.
See [SECURITY.md][🚎sec-pol]

🚂 NOTE: See notes on Rails in next section.

## Basics

This is a ruby library which is intended to be used in creating Ruby Consumer
and Service Provider applications. It is NOT a Rails plugin, but could easily
be used for the foundation for such a Rails plugin.

This gem was originally extracted from @pelle's [oauth-plugin](https://github.com/pelle/oauth-plugin)
gem. After extraction that gem was made to depend on this gem.

Unfortunately, this gem does have some Rails related bits that are
**optional** to load. You don't need Rails! The Rails bits may be pulled out
into a separate gem with the release of version 1.0 of this gem.

## Usage

We need to specify the `oauth_callback` url explicitly, otherwise it defaults to
"oob" (Out of Band)

```ruby
callback_url = "http://127.0.0.1:3000/oauth/callback"
```

Create a new `OAuth::Consumer` instance by passing it a configuration hash:

```ruby
oauth_consumer = OAuth::Consumer.new("key", "secret", site: "https://agree2")
```

Start the process by requesting a token

```ruby
request_token = oauth_consumer.get_request_token(oauth_callback: callback_url)

session[:token] = request_token.token
session[:token_secret] = request_token.secret
redirect_to request_token.authorize_url(oauth_callback: callback_url)
```

When user returns create an access_token

```ruby
hash = { oauth_token: session[:token], oauth_token_secret: session[:token_secret] }
request_token = OAuth::RequestToken.from_hash(oauth_consumer, hash)
access_token = request_token.get_access_token
# For 3-legged authorization, flow oauth_verifier is passed as param in callback
# access_token = request_token.get_access_token(oauth_verifier: params[:oauth_verifier])
@photos = access_token.get("/photos.xml")
```

Now that you have an access token, you can use Typhoeus to interact with the
OAuth provider if you choose.

```ruby
require "typhoeus"
require "oauth/request_proxy/typhoeus_request"
oauth_params = { consumer: oauth_consumer, token: access_token }
hydra = Typhoeus::Hydra.new
req = Typhoeus::Request.new(uri, options) # :method needs to be specified in options
oauth_helper = OAuth::Client::Helper.new(req, oauth_params.merge(request_uri: uri))
req.options[:headers]["Authorization"] = oauth_helper.header # Signs the request
hydra.queue(req)
hydra.run
@response = req.response
```

## Verifying inbound requests: signature method policy

Every loaded signature extension registers itself in the global
`OAuth::Signature.available_methods` table. The global helper accepts *any*
registered method, so installing a new plugin (for example `PLAINTEXT`)
silently widens the methods every endpoint will accept. To pin a single
endpoint to an explicit, small set of methods, verify it through a
`OAuth::Signature::Verifier` backed by an `OAuth::Signature::Policy`.

```ruby
# This endpoint accepts HMAC-SHA1 only, no matter how many plugins are loaded.
verifier = OAuth::Signature.verifier("hmac-sha1")

verifier.verify(request) do |token, consumer_key, nonce, timestamp|
  secret = lookup_consumer_secret(consumer_key) # credential resolver
  [nil, secret]                                  # => [token_secret, consumer_secret]
end
```

Behavior guarantees:

* Method names are matched exactly (case-insensitively) against the allow list.
  Registering an extra plugin never expands what the verifier accepts.
* A request must carry exactly one `oauth_signature_method`; a duplicated
  parameter is rejected with `OAuth::AmbiguousSignatureMethod`.
* The credential resolver block is **not called** for a forbidden, ambiguous,
  or unimplemented method — the request fails first with
  `OAuth::UnauthorizedSignatureMethod`.
* The resolved credential must match the method family. An HMAC shared secret
  cannot be treated as an RSA key and vice versa; mismatches raise
  `OAuth::IncompatibleCredential`.
* `PLAINTEXT` is opt-in: it is only accepted when explicitly listed in the
  policy, for legacy/compatibility scenarios.
* A plugin that raises propagates its error; verification never falls back to
  another allowed method.

Two endpoints can therefore load the same plugin set but enforce different
policies:

```ruby
hmac_endpoint = OAuth::Signature.verifier("hmac-sha1")
rsa_endpoint  = OAuth::Signature.verifier("rsa-sha1")
```

### Migrating from the global verification API

The signing API is unchanged — keep using `OAuth::Signature.sign`. Only the
verification side gains the strict, policy-bound entry point.

```ruby
# Before: accepts any method present in the global registry
OAuth::Signature.verify(request, options) { |token, consumer_key, nonce, timestamp| ... }

# After: declare exactly which methods this endpoint accepts
verifier = OAuth::Signature.verifier("hmac-sha1", "rsa-sha1")
verifier.verify(request, options) { |token, consumer_key, nonce, timestamp| ... }
```

`OAuth::Signature.verify` still works for backward compatibility, but new code
should prefer an explicit policy so adding a plugin cannot change an endpoint's
accepted methods. The resolver block signature and the `options` hash
(`consumer`, `token`, `consumer_secret`, `token_secret`, `private_key`, …) are
identical between the two forms.

## More Information

* RubyDoc Documentation: [![RubyDoc.info](https://img.shields.io/badge/documentation-rubydoc-brightgreen.svg?style=flat)][documentation]
* Mailing List/Google Group: [![Mailing List](https://img.shields.io/badge/group-mailinglist-violet.svg?style=social&logo=google)][mailinglist]
* GitHub Discussions: [![Discussion](https://img.shields.io/badge/discussions-github-brightgreen.svg?style=flat)][gh_discussions]
* Live Chat on Gitter: [![Join the chat at https://gitter.im/oauth-xx/oauth-ruby](https://badges.gitter.im/Join%20Chat.svg)][chat]
* Maintainer's Blog: [![Blog](https://img.shields.io/badge/blog-railsbling-brightgreen.svg?style=flat)][blogpage]

## Contributing

See [CONTRIBUTING.md][contributing]

## Contributors

[![Contributors](https://contrib.rocks/image?repo=oauth-xx/oauth-ruby)][contributors]

Made with [contributors-img][contrib-rocks].

[contrib-rocks]: https://contrib.rocks

## Versioning

This library aims to adhere to [Semantic Versioning 2.0.0][semver]. Violations of this scheme should be reported as
bugs. Specifically, if a minor or patch version is released that breaks backward compatibility, a new version should be
immediately released that restores compatibility. Breaking changes to the public API will only be introduced with new
major versions.  Compatibility with a major and minor versions of Ruby will only be changed with a major version bump.

As a result of this policy, you can (and should) specify a dependency on this gem using
the [Pessimistic Version Constraint][pvc] with two digits of precision.

For example:

```ruby
spec.add_dependency "oauth", "~> 1.0"
```

## License

The gem is available as open source under the terms of
the [MIT License][license] [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)][license-ref].
See [LICENSE][license] for the [Copyright Notice][copyright-notice-explainer].

## Contact

OAuth Ruby has been created and maintained by a large number of talented
individuals. The current maintainer is Peter Boling ([@pboling][gh_sponsors]).

Comments are welcome. Contact the [OAuth Ruby mailing list (Google Group)][mailinglist] or [GitHub Discussions][gh_discussions].

[comment]: <> (Following links are used by README, CONTRIBUTING, Homepage)

[conduct]: https://github.com/oauth-xx/oauth-ruby/blob/main/CODE_OF_CONDUCT.md
[contributing]: https://github.com/oauth-xx/oauth-ruby/blob/main/CONTRIBUTING.md
[contributors]: https://github.com/oauth-xx/oauth-ruby/graphs/contributors
[mailinglist]: http://groups.google.com/group/oauth-ruby
[source]: https://github.com/oauth-xx/oauth-ruby/

[comment]: <> (Following links are used by README, Homepage)

[aboutme]: https://about.me/peter.boling
[actions]: https://github.com/oauth-xx/oauth-ruby/actions
[angelme]: https://angel.co/peter-boling
[blogpage]: http://www.railsbling.com/tags/oauth/
[chat]: https://gitter.im/oauth-xx/oauth-ruby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge
[climate_coverage]: https://codeclimate.com/github/oauth-xx/oauth-ruby/test_coverage
[climate_maintainability]: https://codeclimate.com/github/oauth-xx/oauth-ruby/maintainability
[code_triage]: https://www.codetriage.com/oauth-xx/oauth-ruby
[codecov_coverage]: https://codecov.io/gh/oauth-xx/oauth-ruby
[coderme]:http://coderwall.com/pboling
[depfu]: https://depfu.com/github/oauth-xx/oauth-ruby?project_id=22868
[documentation]: https://rubydoc.info/github/oauth-xx/oauth-ruby
[followme-img]: https://img.shields.io/twitter/follow/galtzo.svg?style=social&label=Follow
[gh_discussions]: https://github.com/oauth-xx/oauth-ruby/discussions
[gh_sponsors]: https://github.com/sponsors/pboling
[license]: https://github.com/oauth-xx/oauth-ruby/blob/main/LICENSE
[license-ref]: https://opensource.org/licenses/MIT
[liberapay_donate]: https://liberapay.com/pboling/donate
[pvc]: http://guides.rubygems.org/patterns/#pessimistic-version-constraint
[rubygems]: https://rubygems.org/gems/oauth
[security]: https://github.com/oauth-xx/oauth-ruby/blob/main/SECURITY.md
[semver]: http://semver.org/
[tweetme]: http://twitter.com/galtzo
