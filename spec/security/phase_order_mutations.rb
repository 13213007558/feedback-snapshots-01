#!/usr/bin/env ruby
# Proves the phase-ordering specs detect security-semantic changes in the
# order of the request and callback phases. Each mutation below only moves
# existing lines; it adds no new logic. The script copies lib/ and the
# ordering spec into a temporary directory, applies one mutation at a time,
# runs the spec against the mutated copy, and reports which examples fail.
# It exits nonzero if a mutation survives.
#
# Run with: bundle exec ruby spec/security/phase_order_mutations.rb

require 'fileutils'
require 'open3'
require 'rbconfig'
require 'tmpdir'

ROOT = File.expand_path('../..', __dir__)
ORDERING_SPEC = File.join(ROOT, 'spec/omniauth/strategy/phase_order_spec.rb')
SPEC_HELPER = File.join(ROOT, 'spec/helper.rb')

MUTATIONS = {
  'request: store omniauth.params before running request_validation_phase' => {
    :file => 'lib/omniauth/strategy.rb',
    :edits => [
      [
        <<-'FROM',
      rejection = validation_rejection
      return rejection if rejection

      response = run_request_hooks
        FROM
        <<-'TO'
      session['omniauth.params'] = omniauth_params
      rejection = validation_rejection
      return rejection if rejection

      response = run_request_hooks
        TO
      ],
      [
        <<-'FROM',
    def run_request_hooks
      session['omniauth.params'] = omniauth_params
      run_hook(:before_request_phase)
        FROM
        <<-'TO'
    def run_request_hooks
      run_hook(:before_request_phase)
        TO
      ]
    ]
  },
  'test mode: write the mocked auth hash before the callback hook' => {
    :file => 'lib/omniauth/strategy/test_mode.rb',
    :edits => [
      [
        <<-'FROM',
        run_hook(:before_callback_phase)
        return failure_response if failure_dispatched?
        return fail!(mocked_auth) if failed

        env['omniauth.auth'] = mocked_auth
        call_app!
        FROM
        <<-'TO'
        env['omniauth.auth'] = mocked_auth unless failed
        run_hook(:before_callback_phase)
        failed ? fail!(mocked_auth) : call_app!
        TO
      ]
    ]
  }
}.freeze

def build_workspace(tmp)
  FileUtils.cp_r(File.join(ROOT, 'lib'), File.join(tmp, 'lib'))
  FileUtils.mkdir_p(File.join(tmp, 'spec/omniauth/strategy'))
  FileUtils.cp(SPEC_HELPER, File.join(tmp, 'spec/helper.rb'))
  FileUtils.cp(ORDERING_SPEC, File.join(tmp, 'spec/omniauth/strategy/phase_order_spec.rb'))
  # The full suite normally requires 100% coverage. These runs execute one
  # spec file, so don't let coverage decide the exit status.
  helper = File.read(File.join(tmp, 'spec/helper.rb')).sub("SimpleCov.start 'strict'", 'SimpleCov.start')
  File.write(File.join(tmp, 'spec/helper.rb'), helper)
  File.write(File.join(tmp, '.rspec'), "--format progress\n")
end

def run_spec(tmp)
  spec_path = File.join(tmp, 'spec/omniauth/strategy/phase_order_spec.rb')
  repo_lib = File.expand_path('lib', ROOT)
  load_path = $LOAD_PATH.reject { |path| File.expand_path(path) == repo_lib }
  env = ENV.to_h.reject { |key, _| key.start_with?('BUNDLE_', 'RUBY') }
  env['RUBYLIB'] = ([File.join(tmp, 'lib')] + load_path).join(File::PATH_SEPARATOR)
  Open3.capture2e(env, RbConfig.ruby,
                  '-e', 'require "rspec/core"; exit RSpec::Core::Runner.run([ARGV[0]])',
                  spec_path, :chdir => tmp)
end

# RSpec's failure summary lines start with "rspec /path/to/spec:LINE # name".
def failing_examples(out)
  out.gsub(/\e\[[0-9;]*m/, '').lines
     .grep(%r{^rspec \S+:\d+ # })
     .map { |line| line.strip.sub(%r{\A.*/phase_order_spec\.rb:}, 'phase_order_spec.rb:') }
end

def apply(tmp, mutation)
  path = File.join(tmp, mutation.fetch(:file))
  contents = File.read(path)
  mutated = mutation.fetch(:edits).inject(contents) do |text, (from, to)|
    replaced = text.sub(from, to)
    raise "mutation did not apply to #{mutation.fetch(:file)}" if replaced == text

    replaced
  end
  File.write(path, mutated)
end

Dir.mktmpdir('omniauth-phase-order') do |tmp|
  build_workspace(tmp)
  out, status = run_spec(tmp)
  abort("baseline ordering spec failed:\n#{out}") unless status.success?

  puts "baseline: #{out.lines.grep(/examples,/).first&.strip}"

  survived = []
  MUTATIONS.each do |name, mutation|
    apply(tmp, mutation)
    out, status = run_spec(tmp)
    File.write(File.join(tmp, mutation.fetch(:file)), File.read(File.join(ROOT, mutation.fetch(:file))))

    failures = failing_examples(out)
    puts
    puts "#{name}: #{status.success? ? 'SURVIVED' : "killed (#{failures.length} failing example(s))"}"
    failures.each { |line| puts "  #{line}" }
    survived << name if status.success?
  end

  abort("mutations survived: #{survived.join(', ')}") unless survived.empty?

  puts
  puts 'Both order-changing mutations were killed.'
end
