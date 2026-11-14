# frozen_string_literal: true

# Minimal reproduction for the security review of Strategy#call's fast
# passthrough path (lib/omniauth/strategy.rb). It is standalone: run it with
# Ruby from the repository root, without RSpec.
#
#   ruby script/verify_passthrough_security.rb
#
# For every request it compares the fast path (Strategy#call) against the
# forced full dispatch (dup.call!), then pins the security properties the
# fast path relies on: path lambdas are never run by the probe, a reused
# instance keeps no route cache across mounts or option changes, callback
# variants still enter the strategy, and no phase hook or omniauth.* env
# key reaches a request that only the app should see.
require 'stringio'
$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
require 'omniauth'

OmniAuth.config.logger = Logger.new(File::NULL)
OmniAuth.config.request_validation_phase = nil

def make_env(path_info, props = {})
  {
    'REQUEST_METHOD' => 'POST',
    'PATH_INFO' => path_info,
    'rack.session' => {},
    'rack.input' => StringIO.new('')
  }.merge(props)
end

class VerificationStrategy
  include OmniAuth::Strategy
  option :name, 'probe'

  def request_phase
    [200, {}, ['request phase']]
  end

  def callback_phase
    [200, {}, ['callback phase']]
  end
end

# An other_phase forces every request through dup.call!, because its mere
# presence switches dispatch_by_path? off. It only delegates to the app, so
# the response is what the plain full dispatch would produce.
class FullDispatchStrategy < VerificationStrategy
  def other_phase
    call_app!
  end
end

def downstream
  ->(env) { env['app.touched'] = true; [200, {}, ['app']] }
end

failures = []
check = lambda do |description, condition|
  puts "#{condition ? 'ok  ' : 'FAIL'} | #{description}"
  failures << description unless condition
end

# 1. Differential matrix: fast path and forced full dispatch must answer
#    identically and leave the same keys in env, across custom string paths,
#    path prefixes, mount points, request methods, and callback variants.
configs = [
  ['defaults', {}],
  ['string request_path', { request_path: '/login' }],
  ['string callback_path', { callback_path: '/login/done' }],
  ['both string paths', { request_path: '/login', callback_path: '/login/done' }],
  ['path_prefix /sso', { path_prefix: '/sso' }]
]
paths = ['/', '/trips/1', '/auth', '/auth/probe', '/auth/probe/', '/AUTH/Probe', '/auth//probe',
         '/auth/probe/callback', '/auth/probe/callback.json', '/auth/probe/callback/x', '/auth/probex',
         '/login', '/login/done', '/login/done.json', '/sso/probe', '/sso/probe/callback']
matrix = 0
configs.each do |label, options|
  ['', '/mounted'].each do |script_name|
    paths.each do |path|
      %w[GET POST OPTIONS].each do |method|
        matrix += 1
        fast_env = make_env(path.delete_prefix(script_name), 'SCRIPT_NAME' => script_name, 'REQUEST_METHOD' => method)
        full_env = make_env(path.delete_prefix(script_name), 'SCRIPT_NAME' => script_name, 'REQUEST_METHOD' => method)
        fast_status, _, fast_body = VerificationStrategy.new(downstream, options).call(fast_env)
        full_status, _, full_body = FullDispatchStrategy.new(downstream, options).call(full_env)
        watched = ->(env) { env.keys.select { |key| key.start_with?('omniauth') || key == 'app.touched' }.sort }
        identical = fast_status == full_status && fast_body == full_body && watched.call(fast_env) == watched.call(full_env)
        check.call("matrix #{label} #{script_name}#{path} #{method}", identical)
      end
    end
  end
end
puts "matrix: #{matrix} request configurations compared"

# 2. A path lambda disables the fast path, so the probe never runs it. The
#    remaining calls are the unchanged full-dispatch behavior, counted here
#    against the observed baseline rather than assumed to be a single call.
%i[request_path callback_path].each do |option|
  calls = 0
  path_lambda = ->(env) { calls += 1; env['PATH_INFO'] == '/x' }
  strategy = VerificationStrategy.new(downstream, option => path_lambda)
  probe_builds = 0
  strategy.singleton_class.send(:alias_method, :original_path_probe, :path_probe)
  strategy.singleton_class.send(:define_method, :path_probe) do |env|
    probe_builds += 1
    original_path_probe(env)
  end

  strategy.call(make_env('/trips/1', 'REQUEST_METHOD' => 'GET'))
  off_path_calls = calls
  strategy.call(make_env('/x', 'REQUEST_METHOD' => 'GET'))
  check.call("#{option} lambda: no path probe is built with a lambda option", probe_builds.zero?)
  check.call("#{option} lambda: calls come only from full dispatch, on both requests",
             off_path_calls.positive? && calls > off_path_calls)
end

# 3. One reused instance serves different mounts and option changes without
#    inheriting another request's route cache.
shared = VerificationStrategy.new(downstream)
shared.call(make_env('/trips/1', 'SCRIPT_NAME' => '/mount-a', 'REQUEST_METHOD' => 'GET'))
check.call('reused instance keeps no path memoization after passthrough',
           shared.instance_variables == %i[@app @env @options])
status, _, body = shared.call(make_env('/auth/probe', 'SCRIPT_NAME' => '/mount-b', 'REQUEST_METHOD' => 'POST'))
check.call('reused instance reaches the request phase under a new mount', [status, body] == [200, ['request phase']])
status, _, body = shared.call(make_env('/auth/probe/callback', 'SCRIPT_NAME' => '/mount-b'))
check.call('reused instance reaches the callback phase under a new mount', [status, body] == [200, ['callback phase']])
status, _, body = shared.call(make_env('/trips/2', 'SCRIPT_NAME' => '/mount-a', 'REQUEST_METHOD' => 'GET'))
check.call('reused instance still passes through back at the first mount', [status, body] == [200, ['app']])

movable = VerificationStrategy.new(downstream, request_path: '/login')
check.call('custom request_path routes before the option changes',
           movable.call(make_env('/login')) == [200, {}, ['request phase']])
movable.options[:request_path] = '/signin'
check.call('the old request path passes through after the option changes',
           movable.call(make_env('/login', 'REQUEST_METHOD' => 'GET')) == [200, {}, ['app']])
check.call('the new request path takes effect on the reused instance',
           movable.call(make_env('/signin')) == [200, {}, ['request phase']])

# 4. Hooks run only on the strategy's own paths; passthrough runs none, and
#    the callback variants are never mistaken for ordinary app paths.
hook_log = []
OmniAuth.config.request_validation_phase = ->(env) { hook_log << [:validation, env['PATH_INFO']] }
OmniAuth.config.before_request_phase = ->(env) { hook_log << [:before_request, env['PATH_INFO']] }
OmniAuth.config.after_request_phase = ->(env) { hook_log << [:after_request, env['PATH_INFO']] }
OmniAuth.config.before_callback_phase = ->(env) { hook_log << [:before_callback, env['PATH_INFO']] }
OmniAuth.config.before_options_phase = ->(env) { hook_log << [:before_options, env['PATH_INFO']] }
hooked = VerificationStrategy.new(downstream)
hooked.call(make_env('/trips/1', 'REQUEST_METHOD' => 'GET'))
check.call('no phase hook runs on a passthrough request', hook_log.empty?)
hooked.call(make_env('/auth/probe'))
check.call('request validation and request hooks run on the request path',
           hook_log == [[:validation, '/auth/probe'], [:before_request, '/auth/probe'],
                        [:after_request, '/auth/probe']])
hook_log.clear
hooked.call(make_env('/auth/probe/callback'))
check.call('the callback hook runs on the callback path',
           hook_log == [[:before_callback, '/auth/probe/callback']])
hook_log.clear
hooked.call(make_env('/auth/probe', 'REQUEST_METHOD' => 'OPTIONS'))
check.call('the options hook runs on an OPTIONS request to an auth path',
           hook_log == [[:before_options, '/auth/probe']])

%w[/auth/probe/callback /auth/probe/callback.json /AUTH/Probe/Callback].each do |path|
  check.call("callback variant #{path} enters the callback phase",
             VerificationStrategy.new(downstream).call(make_env(path)) == [200, {}, ['callback phase']])
end
seen = nil
VerificationStrategy.new(->(env) { seen = env; [200, {}, ['app']] }).call(make_env('/trips/1'))
check.call('the downstream app gets no omniauth.* key but keeps the session',
           seen.keys.none? { |key| key.start_with?('omniauth') } && seen['rack.session'] == {})

OmniAuth.config.request_validation_phase = nil
OmniAuth.config.before_request_phase = nil
OmniAuth.config.after_request_phase = nil
OmniAuth.config.before_callback_phase = nil
OmniAuth.config.before_options_phase = nil

if failures.empty?
  puts "\nPASSED: fast passthrough keeps the same security boundary as full dispatch (#{matrix} matrix cases)"
  exit 0
else
  puts "\nFAILED: #{failures.size} check(s): #{failures.join('; ')}"
  exit 1
end
