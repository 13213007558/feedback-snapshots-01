# Local preparation

Ruby 3.3.12. Gems are installed in this checkout; no application server or external database is required. The checked-in Gemfile selects runtime dependencies and the existing test runner only.

## Install

```sh
env PATH=/opt/homebrew/opt/ruby@3.3/bin:/opt/homebrew/bin:/usr/bin:/bin BUNDLE_GEMFILE=.feedback/Gemfile BUNDLE_PATH=gems BUNDLE_APP_CONFIG=.feedback/bundle /opt/homebrew/opt/ruby@3.3/bin/bundle install --jobs 2
```

## Existing quick tests

```sh
env PATH=/opt/homebrew/opt/ruby@3.3/bin:/opt/homebrew/bin:/usr/bin:/bin BUNDLE_GEMFILE=.feedback/Gemfile BUNDLE_PATH=gems BUNDLE_APP_CONFIG=.feedback/bundle /opt/homebrew/opt/ruby@3.3/bin/bundle exec ruby -Ilib:test -e 'Dir['"'"'test/**/*_test.rb'"'"'].sort.each { |f| require_relative f }'
```

Observed successful source baseline: 4.037 seconds (wall time, not a performance requirement).

Only preparation metadata was added. The application and existing tests remain at the recorded upstream commit.
