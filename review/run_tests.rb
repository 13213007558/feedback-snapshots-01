# frozen_string_literal: true

# Runs the review's regression tests using the workspace-local gems.
#
#   ruby review/run_tests.rb

require 'rubygems'
root = File.expand_path('..', __dir__)
gem_root = File.join(root, '.gems')
Gem.use_paths(gem_root, [gem_root])
$LOAD_PATH.unshift(File.join(root, 'lib'))
$LOAD_PATH.unshift(File.join(root, 'review'))

require 'test/unit'
require_relative 'test_domain_upgrade_review'
