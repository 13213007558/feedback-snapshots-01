#!/usr/bin/env bash
set -euo pipefail

lab_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$lab_dir/../.." && pwd)"

cd "$repo_root"
export BUNDLE_GEMFILE="$repo_root/.feedback/Gemfile"

exec bundle exec ruby "$lab_dir/harness.rb" "$@"
