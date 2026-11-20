#!/bin/sh
set -eu
if [ -x /opt/homebrew/opt/ruby@3.3/bin/ruby ]; then
  PATH="/opt/homebrew/opt/ruby@3.3/bin:$PATH"
fi
export PATH
export BUNDLE_GEMFILE="$PWD/.feedback/Gemfile"
export BUNDLE_PATH="$PWD/.venv/gems"
export BUNDLE_IGNORE_CONFIG=1
export BUNDLE_GLOBAL_GEM_CACHE=true
if [ "$1" = install ]; then
  exec bundle install --jobs 2 --retry 1
fi
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY
export DB=sqlite
exec bundle exec "$@"
