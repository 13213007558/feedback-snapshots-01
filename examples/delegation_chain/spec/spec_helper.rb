# frozen_string_literal: true

require 'rspec'

# Prefer the ruby-jwt source at the repository root; fall back to an installed gem.
repository_root = File.expand_path('../../..', __dir__)
repository_jwt_lib = File.join(repository_root, 'lib')
$LOAD_PATH.unshift(repository_jwt_lib) if File.directory?(repository_jwt_lib)
$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))

require 'jwt'
require 'act_chain'

RSpec.configure do |config|
  config.expect_with(:rspec) { |c| c.syntax = :expect }
end
