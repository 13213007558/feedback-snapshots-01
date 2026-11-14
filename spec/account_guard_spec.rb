# frozen_string_literal: true

require_relative 'spec_helper'

describe 'Rack::Attack.account_guard' do
  attr_reader :login_hits

  def app
    hits = @login_hits
    downstream = lambda do |env|
      req = Rack::Attack::Request.new(env)
      if req.path == '/login'
        hits << req.params['email']
        req.env['login.result'] == :failure ? [401, {}, ['Unauthorized']] : [200, {}, ['Welcome']]
      else
        [200, {}, ['Hello World']]
      end
    end

    Rack::Builder.new do
      use Rack::Lint
      use Rack::Attack
      use Rack::Lint
      run downstream
    end.to_app
  end

  before do
    @login_hits = []
    Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new
    Rack::Attack.account_guard(
      'credential-stuffing',
      maxretry: 3,
      findtime: 60,
      bantime: 300,
      classifier: ->(result) { result.status == 401 ? :failure : :success }
    ) do |request|
      request.post? && request.path == '/login' ? request.params['email'].to_s.downcase : nil
    end
  end

  def login(email, result = :failure, ip = '1.2.3.4')
    post '/login', { 'email' => email, 'password' => 'super-secret' },
         'REMOTE_ADDR' => ip, 'login.result' => result
  end

  def guard
    Rack::Attack.account_guards['credential-stuffing']
  end

  it 'does not count requests that never reach a failure response' do
    login('a@example.com', :success)
    _(last_response.status).must_equal 200
    _(guard.registry.failure_count('a@example.com')).must_equal 0
  end

  it 'accumulates failures from response classification, not on entry' do
    2.times { login('a@example.com', :failure) }
    _(last_response.status).must_equal 401
    _(guard.registry.failure_count('a@example.com')).must_equal 2
  end

  it 'bans on the request that reaches maxretry and blocks later ones before the app' do
    3.times { login('a@example.com', :failure) }
    # The third failure still completes downstream; the ban takes effect for
    # every subsequent request.
    _(last_response.status).must_equal 401
    _(guard.registry).must_be :banned?, 'a@example.com'

    hits_before = login_hits.dup
    login('a@example.com', :success)
    _(last_response.status).must_equal 429
    _(login_hits).must_equal hits_before, 'banned request must not reach the login handler'
  end

  it 'does not leak pending state after a normal request' do
    login('a@example.com', :failure)
    _(guard.registry.pending?('a@example.com', 'whatever')).must_equal false
  end

  it 'a success clears prior failures' do
    2.times { login('a@example.com', :failure) }
    login('a@example.com', :success)
    _(guard.registry.failure_count('a@example.com')).must_equal 0

    2.times { login('a@example.com', :failure) }
    _(last_response.status).must_equal 401, 'counter restarts from zero after success'
  end

  it 'classifier never sees the password or the response body' do
    seen = nil
    Rack::Attack.account_guards['credential-stuffing'].instance_variable_set(:@classifier,
                                                                             lambda { |result|
                                                                               seen = result
                                                                               :success
                                                                             })
    login('a@example.com', :success)
    _(seen).wont_respond_to :params
    _(seen).wont_respond_to :body
    _(seen.status).must_equal 200
    _(seen.path).must_equal '/login'
  end

  it 'still lets the downstream read the posted password after account extraction' do
    post '/login', { 'email' => 'a@example.com', 'password' => 'super-secret' },
         'REMOTE_ADDR' => '1.2.3.4', 'login.result' => :success
    _(last_response.status).must_equal 200
    _(login_hits).must_include 'a@example.com'
  end

  describe 'interleaved requests for the same account' do
    # Two in-flight logins for one account:
    #   request A starts, request B starts; B finishes first with a failure,
    #   then A finishes successfully. A's success must not erase B's failure
    #   because B started after A.
    it 'an earlier success cannot clear a failure that started after it' do
      account = 'race@example.com'
      registry = guard.registry

      a_id = registry.register(account)
      a_seen = registry.seen_seq(account)
      b_id = registry.register(account)
      b_seen = registry.seen_seq(account)

      registry.record_failure(account, b_id)
      _(registry.failure_count(account)).must_equal 1

      registry.record_success(account, a_id, a_seen)
      _(registry.failure_count(account)).must_equal 1, 'later failure survives the earlier success'
      _(registry.pending?(account, b_id)).must_equal false
      _(registry.pending?(account, a_id)).must_equal false
    end

    it 'demonstrates the ban threshold under controlled interleaving' do
      account = 'race@example.com'
      registry = guard.registry

      # A long-running successful request starts while no failure exists yet.
      success_id = registry.register(account)
      success_seen = registry.seen_seq(account)
      _(success_seen).must_equal 0

      # While it is in flight, three failures from other requests trip the
      # threshold: the account is banned even though a success is pending.
      3.times do
        id = registry.register(account)
        registry.record_failure(account, id)
      end
      _(registry).must_be :banned?, account

      # The late success only clears failures up to `success_seen` (none), so
      # it can neither erase the new failures nor lift the ban they caused.
      registry.record_success(account, success_id, success_seen)
      _(registry).must_be :banned?, account
      _(registry.failure_count(account)).must_equal 3
    end

    it 'runs the same race through real HTTP requests on two threads' do
      account = 'thread@example.com'
      registry = guard.registry
      entered = Queue.new
      failure_gate = Queue.new
      success_gate = Queue.new

      downstream = lambda do |env|
        req = Rack::Attack::Request.new(env)
        if req.path == '/login' && req.params['email'] == account
          role = req.env['role']
          entered << role
          (role == :failing ? failure_gate : success_gate).pop
          status = role == :failing ? 401 : 200
          [status, {}, [status == 401 ? 'Unauthorized' : 'Welcome']]
        else
          [200, {}, ['ok']]
        end
      end

      stack = Rack::Builder.new do
        use Rack::Attack
        run downstream
      end.to_app

      failing = Thread.new do
        stack.call(Rack::MockRequest.env_for('/login', method: 'POST',
                                             input: "email=#{account}&password=x",
                                             'role' => :failing))
      end
      succeeding = Thread.new do
        stack.call(Rack::MockRequest.env_for('/login', method: 'POST',
                                             input: "email=#{account}&password=y",
                                             'role' => :succeeding))
      end

      roles = [entered.pop, entered.pop].sort
      _(roles).must_equal [:failing, :succeeding]

      failure_gate << true # failing request (started first) finishes first
      failing.join
      _(registry.failure_count(account)).must_equal 1

      success_gate << true # succeeding request finishes afterwards
      succeeding.join

      _(registry.failure_count(account)).must_equal 1, 'success cannot erase the concurrent failure'
      _(registry).wont_be :banned?, account
      _(registry.pending?(account, 'anything')).must_equal false
    end
  end

  describe 'failure handling' do
    it 'aborts (does not count) and releases pending state when downstream raises' do
      raising = lambda { |_env| raise RuntimeError, 'downstream boom' }
      stack = Rack::Attack.new(raising)
      env = Rack::MockRequest.env_for('/login', method: 'POST',
                                        input: 'email=boom@example.com&password=z')
      assert_raises(RuntimeError) { stack.call(env) }
      registry = guard.registry
      _(registry.failure_count('boom@example.com')).must_equal 0
    end

    it 'accounts exactly once for a streaming body closed early' do
      streamed = [0]
      body = Class.new do
        def initialize(counter)
          @counter = counter
        end

        def each
          @counter[0] += 1
          yield 'chunk'
          raise 'client disconnected'
        end

        def close; end
      end.new(streamed)

      streaming_app = lambda { |_env| [401, { 'content-type' => 'text/plain' }, body] }
      stack = Rack::Attack.new(streaming_app)
      env = Rack::MockRequest.env_for('/login', method: 'POST',
                                        input: 'email=stream@example.com&password=z')
      _status, _headers, wrapped = stack.call(env)
      _(guard.registry.failure_count('stream@example.com')).must_equal 1

      assert_raises(RuntimeError) { wrapped.each { |_c| } }
      wrapped.close
      wrapped.close # double close must stay idempotent

      _(guard.registry.failure_count('stream@example.com')).must_equal 1
    end

    it 'keeps the recorded failure when nested middleware closes the body' do
      # Two Rack::Attack layers (as in the default spec app) each wrap the
      # body; closing the outer proxy must not undo the inner accounting.
      failing_app = lambda { |_env| [401, {}, ['Unauthorized']] }
      stack = Rack::Attack.new(Rack::Attack.new(failing_app))
      env = Rack::MockRequest.env_for('/login', method: 'POST',
                                        input: 'email=nested@example.com&password=z')
      status, _headers, body = stack.call(env)
      body.close
      _(status).must_equal 401
      _(guard.registry.failure_count('nested@example.com')).must_equal 1
    end

    it 'releases pending state and does not count when the classifier raises' do
      raising_guard = Rack::Attack::AccountGuard.new(
        'raising', maxretry: 2, findtime: 60, bantime: 60,
        classifier: ->(_result) { raise 'classifier boom' }
      ) { |_| 'raise@example.com' }

      ok_app = lambda { |_env| [200, {}, ['ok']] }
      request = Rack::Attack::Request.new(Rack::MockRequest.env_for('/'))
      assert_raises(RuntimeError) { raising_guard.wrap(request, ok_app) }
      _(raising_guard.registry.failure_count('raise@example.com')).must_equal 0
      _(raising_guard.registry.pending?('raise@example.com', 'x')).must_equal false
    end

    it 'does not count a response the classifier cannot categorize' do
      neutral_app = lambda { |_env| [503, {}, ['busy']] }
      neutral = Rack::Attack::AccountGuard.new(
        'neutral', maxretry: 1, findtime: 60, bantime: 60,
        classifier: ->(result) { result.status == 401 ? :failure : nil }
      ) { |_req| 'neutral@example.com' }
      request = Rack::Attack::Request.new(Rack::MockRequest.env_for('/'))
      status, _headers, body = neutral.wrap(request, neutral_app)
      body.close
      _(status).must_equal 503
      _(neutral.registry.failure_count('neutral@example.com')).must_equal 0
      _(neutral.registry.pending?('neutral@example.com', 'x')).must_equal false
    end
  end

  describe 'multiple account guards chained' do
    let(:unauthorized_classifier) { ->(result) { result.status == 401 ? :failure : :success } }

    it 'invokes the application exactly once and lets every guard account the response' do
      app_calls = 0
      counting_app = lambda do |_env|
        app_calls += 1
        [401, {}, ['Unauthorized']]
      end

      options = { maxretry: 5, findtime: 60, bantime: 60, classifier: unauthorized_classifier }
      Rack::Attack.account_guard('first', options) { |_| 'acct' }
      Rack::Attack.account_guard('second', options) { |_| 'acct' }

      stack = Rack::Attack.new(counting_app)
      env = Rack::MockRequest.env_for('/login', method: 'POST', input: 'email=a&password=p')
      status, _headers, body = stack.call(env)
      body.close

      _(status).must_equal 401
      _(app_calls).must_equal 1
      _(Rack::Attack.account_guards['first'].registry.failure_count('acct')).must_equal 1
      _(Rack::Attack.account_guards['second'].registry.failure_count('acct')).must_equal 1
    end

    it 'a banned guard short-circuits before the application runs' do
      # Isolate from the guard registered in the outer before-block.
      strict = Rack::Attack::AccountGuard.new(
        'strict', maxretry: 1, findtime: 60, bantime: 60,
        classifier: unauthorized_classifier
      ) { |_| 'acct' }
      Rack::Attack.configuration.account_guards.replace('strict' => strict)

      failing_app = lambda { |_env| [401, {}, ['no']] }
      login_env = -> do
        Rack::MockRequest.env_for('/login', method: 'POST', input: 'email=a&password=p')
      end
      _status, _h, body = Rack::Attack.new(failing_app).call(login_env.call)
      body.close
      _(strict.registry).must_be :banned?, 'acct'

      app_calls = 0
      counting_app = lambda do |_env|
        app_calls += 1
        [200, {}, ['ok']]
      end
      # A fresh env (as in real HTTP) so the middleware is not bypassed by the
      # previous request's 'rack.attack.called' marker.
      status, _headers, blocked_body = Rack::Attack.new(counting_app).call(login_env.call)
      blocked_body.close if blocked_body.respond_to?(:close)
      _(status).must_equal 429
      _(app_calls).must_equal 0
    end
  end

  describe 'with entry-time IP throttling enabled' do
    before do
      Rack::Attack.throttle('logins/ip', limit: 2, period: 60) { |req| req.post? && req.path == '/login' && req.ip }
    end

    it 'IP throttling blocks before the application and before account accounting' do
      login('ip@example.com', :failure, '9.9.9.9')
      login('ip@example.com', :failure, '9.9.9.9')
      login('ip@example.com', :failure, '9.9.9.9')

      _(last_response.status).must_equal 429
      _(login_hits.size).must_equal 2, 'third request never reached the handler'
      _(guard.registry.failure_count('ip@example.com')).must_equal 2
    end
  end
end
