# frozen_string_literal: true

# Standalone runner for test/current_attributes_test.rb. The locked local
# bundle omits Active Job/Railties/Redis, so instead of the full test helper
# this uses a minimal shim (shim/test/helper.rb) and the ActiveJob::Arguments
# shim. It runs the *real* test file unchanged, exercising both the legacy and
# the new allowlist behavior.

$LOAD_PATH.unshift File.expand_path("../../lib", __dir__)
$LOAD_PATH.unshift File.expand_path("shim", __dir__)

require "logger"
require "stringio"

gem_roots = (Gem.path + Gem.default_path + [
  "/opt/homebrew/lib/ruby/gems/#{RbConfig::CONFIG["ruby_version"]}",
  "/opt/homebrew/lib/ruby/gems/4.0.0"
]).uniq
gem_roots.each do |path|
  Dir.glob(File.join(path, "gems", "*", "lib")).each do |lib|
    next unless File.directory?(lib)
    # keep the locked minitest 5.x; skip a system-wide minitest 6.x copy
    next if lib.include?("/minitest-6")

    $LOAD_PATH.push(lib) unless $LOAD_PATH.include?(lib)
  end
end
Dir.glob("/opt/homebrew/lib/ruby/gems/*/gems/concurrent-ruby-*/lib/concurrent-ruby").each do |lib|
  $LOAD_PATH.push(lib) unless $LOAD_PATH.include?(lib)
end

require "active_support"
require "active_support/core_ext/string/inflections"
require "active_support/current_attributes"
require "active_job/arguments"

# test/current_attributes_test.rb expects Serializer at the top level.
Serializer = ActiveJob::Arguments

# test/current_attributes_test.rb does `require_relative "helper"`, which
# would resolve to the real test/helper.rb (Rails/Redis stack). Preload the
# minimal helper and mark that absolute path as already loaded so the
# require_relative becomes a no-op while the constant names stay identical.
require_relative "shim/test/helper"
$LOADED_FEATURES << File.expand_path("../../test/helper.rb", __dir__)

load File.expand_path("../../test/current_attributes_test.rb", __dir__)
