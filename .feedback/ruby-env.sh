#!/bin/sh
set -eu
if [ -x /opt/homebrew/opt/ruby@3.3/bin/ruby ]; then
  PATH="/opt/homebrew/opt/ruby@3.3/bin:$PATH"
fi
export PATH
export BUNDLE_GEMFILE="$PWD/.feedback/Gemfile"
export BUNDLE_PATH="$PWD/.venv/gems"
export BUNDLE_IGNORE_CONFIG=1
export BUNDLE_GLOBAL_GEM_CACHE=false
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY
if [ "$1" = install ]; then
  bundle check >/dev/null 2>&1 && exit 0
  bundle install --local --jobs 1 --retry 0 && exit 0
  exec bundle install --jobs 2 --retry 1
fi
exec bundle exec "$@"
