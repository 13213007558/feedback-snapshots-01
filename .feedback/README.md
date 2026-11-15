# Local preparation

Ruby 3.3.12. Gems are installed in this checkout; no application server or external database is required. The checked-in Gemfile selects runtime dependencies and the existing test runner only. TZ=UTC is required because the existing Apple certificate fixtures use a date parsed in the local timezone.

## Install

```sh
env TZ=UTC PATH=/opt/homebrew/opt/ruby@3.3/bin:/opt/homebrew/bin:/usr/bin:/bin BUNDLE_GEMFILE=.feedback/Gemfile BUNDLE_PATH=gems BUNDLE_APP_CONFIG=.feedback/bundle /opt/homebrew/opt/ruby@3.3/bin/bundle install --jobs 2
```

## Existing quick tests

```sh
env TZ=UTC PATH=/opt/homebrew/opt/ruby@3.3/bin:/opt/homebrew/bin:/usr/bin:/bin BUNDLE_GEMFILE=.feedback/Gemfile BUNDLE_PATH=gems BUNDLE_APP_CONFIG=.feedback/bundle /opt/homebrew/opt/ruby@3.3/bin/bundle exec rspec spec/webauthn spec/webauthn_spec.rb --format progress
```

Observed successful source baseline: 1.716 seconds (wall time, not a performance requirement).

Only preparation metadata was added. The application and existing tests remain at the recorded upstream commit.
