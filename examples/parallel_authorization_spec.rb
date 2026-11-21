# frozen_string_literal: true

# Demonstrates Faraday parallel usage with a *pre-execution confirmation* step.
#
# The scenario mirrors a backend that schedules several parallel pulls, where an
# application's authorization can be revoked after the request was queued but
# before the adapter actually performs it. The in-memory parallel manager below:
#
#   1. collects every queued request (the adapter does not perform them yet);
#   2. runs a final authorization check for each request, immediately before the
#      adapter would execute it;
#   3. performs only the still-authorized requests, in parallel;
#   4. hands the requests whose authorization was revoked back to the caller
#      (both via an `on_revoked` callback and a `revoked_requests` list) and
#      leaves their Faraday::Response unfinished, so `on_complete` callbacks are
#      never fired and the revoked request is never reported as a success.
#
# Run it standalone (it needs no network):
#   rspec --options /dev/null -Ilib examples/parallel_authorization_spec.rb
require 'faraday'
require 'thread'

# In-memory registry of the applications currently allowed to call the backend.
# It is mutated while the batch is in flight to simulate an authorization that
# gets revoked between enqueueing and execution.
class AuthorizationRegistry
  def initialize(allowed_app_ids)
    @mutex = Mutex.new
    @allowed = allowed_app_ids.to_h { |id| [id, true] }
  end

  def revoke(app_id)
    @mutex.synchronize { @allowed.delete(app_id) }
  end

  def authorized?(app_id)
    @mutex.synchronize { @allowed.key?(app_id) }
  end
end

# The object returned to the caller when a queued request cannot be executed.
RevokedRequest = Struct.new(:app_id, :method, :url, keyword_init: true)

# A thread barrier: every thread signals {#ready}, then they all unblock
# together from {#wait_open}, guaranteeing the confirmed requests overlap.
class Gate
  def initialize(expected)
    @expected = expected
    @mutex = Mutex.new
    @condition = ConditionVariable.new
    @ready = 0
    @open = false
  end

  def ready
    @mutex.synchronize do
      @ready += 1
      @open = true if @ready >= @expected
      @condition.broadcast if @open
    end
  end

  def wait_open
    @mutex.synchronize do
      @condition.wait(@mutex) until @open
    end
  end
end

# A parallel manager that keeps everything in memory. It implements Faraday's
# modern parallel-manager contract (`#add` for the adapter, `#execute` for the
# connection) and adds the pre-execution authorization gate.
class InMemoryParallelManager
  # @param registry [AuthorizationRegistry] consulted at execution time.
  # @param on_revoked [#call, nil] optional handler that receives a
  #   RevokedRequest as soon as its authorization is found to be missing.
  def initialize(registry:, on_revoked: nil)
    @registry = registry
    @on_revoked = on_revoked
    @queued = []
    @revoked_requests = []
    @mutex = Mutex.new
    @max_active = 0
    @active = 0
  end

  # Requests that never reached the adapter because their authorization was
  # revoked. Handed back to the caller for its own processing.
  attr_reader :revoked_requests

  # Highest number of requests that were executing at the same time. Used in the
  # example to prove the authorized requests really did overlap.
  attr_reader :max_active

  # Called by the adapter while inside the `in_parallel` block. The request is
  # stored together with the work that *would* perform it; nothing runs yet.
  def add(env, perform)
    @queued << {
      app_id: env.request_headers['X-App-Id'],
      env: env,
      perform: perform
    }
  end

  # Called by Faraday::Connection#in_parallel with the request-building block.
  # The block is run first to collect the queued requests, then the batch is
  # confirmed and executed.
  def execute(&block)
    block.call
    run
  end

  # Executes every queued request. Each request is confirmed one last time, in
  # its own thread, immediately before the adapter would perform it.
  def run
    gate = Gate.new(@queued.size)
    threads = @queued.map do |job|
      Thread.new(job) do |queued_job|
        confirm_and_perform(queued_job, gate)
      end
    end
    threads.each(&:join)
    self
  end

  private

  def confirm_and_perform(job, gate)
    # Final confirmation, immediately before the adapter executes the request.
    unless @registry.authorized?(job[:app_id])
      reject(job)
      gate.ready # stay in step with the authorized threads
      gate.wait_open
      return
    end

    gate.ready
    gate.wait_open
    track_activity { job[:perform].call }
  end

  def reject(job)
    revoked = RevokedRequest.new(
      app_id: job[:app_id],
      method: job[:env][:method],
      url: job[:env][:url].to_s
    )
    @mutex.synchronize do
      @revoked_requests << revoked
      @on_revoked&.call(revoked)
    end
  end

  def track_activity
    @mutex.synchronize do
      @active += 1
      @max_active = [@max_active, @active].max
    end
    yield
  ensure
    @mutex.synchronize { @active -= 1 }
  end
end

# A parallel-capable adapter whose "network" is entirely in memory. Each
# response is rendered from a local stub store only when the parallel manager
# decides the request is allowed to execute.
class InMemoryAdapter < Faraday::Adapter
  self.supports_parallel = true

  def self.setup_parallel_manager(options = nil)
    InMemoryParallelManager.new(**(options || {}))
  end

  def initialize(app, stub_store, &configure)
    super(app)
    @stub_store = stub_store
    @executed_paths = []
    @executed_mutex = Mutex.new
    configure&.call(self)
  end

  # Paths the adapter actually performed, i.e. the requests that "went out".
  attr_reader :executed_paths

  def call(env)
    super
    manager = env.parallel_manager
    if manager
      # Parallel mode: hand the env and the deferred work to the manager. The
      # request is not performed here, so nothing leaves the process yet.
      manager.add(env, -> { perform(env) })
    else
      perform(env)
    end
    @app.call(env)
  end

  private

  def perform(env)
    @executed_mutex.synchronize { @executed_paths << env.url.path }
    status, headers, body = @stub_store.fetch(env.url.path).call
    # Simulate the adapter actually waiting on the network. Holding the GVL via
    # sleep makes the overlap between concurrent requests observable.
    sleep(0.05)
    save_response(env, status, body, headers)
    # In parallel mode Adapter#save_response leaves the response un-finished.
    # Completing it here fires the registered on_complete callbacks; a request
    # that is rejected before this point never reaches the line.
    env.response.finish(env) unless env.response.finished?
  end
end

RSpec.describe 'parallel requests with pre-execution authorization confirmation' do
  let(:registry) { AuthorizationRegistry.new(%w[app-1 app-2 app-3]) }

  let(:stub_store) do
    {
      '/pulls/app-1' => -> { [200, { 'Content-Type' => 'text/plain' }, 'payload-1'] },
      '/pulls/app-2' => -> { [200, { 'Content-Type' => 'text/plain' }, 'payload-2'] },
      '/pulls/app-3' => -> { [200, { 'Content-Type' => 'text/plain' }, 'payload-3'] }
    }
  end

  let(:adapter_holder) { {} }

  let(:connection) do
    Faraday.new('http://backend.internal') do |builder|
      builder.adapter(InMemoryAdapter, stub_store) do |adapter|
        adapter_holder[:instance] = adapter
      end
    end
  end

  let(:adapter) { adapter_holder[:instance] }

  it 'runs the two authorized requests in parallel and never performs the revoked one' do
    responses = {}
    completed_apps = []
    handled_revocations = []

    manager = InMemoryParallelManager.new(
      registry: registry,
      on_revoked: ->(revoked) { handled_revocations << revoked.app_id }
    )

    connection.in_parallel(manager) do
      %w[app-1 app-2 app-3].each do |app_id|
        response = connection.get("/pulls/#{app_id}") do |request|
          request.headers['X-App-Id'] = app_id
        end
        responses[app_id] = response

        # Registered for every queued request; it must only fire for the
        # requests that actually complete.
        response.on_complete { completed_apps << app_id }
      end

      # Authorization is revoked after enqueueing but before execution starts.
      registry.revoke('app-3')

      # While still inside the block nothing has been executed yet.
      expect(responses.values.map(&:finished?)).to all(be(false))
    end

    # The two still-authorized requests completed successfully and overlapped.
    expect(responses['app-1'].status).to eq(200)
    expect(responses['app-1'].body).to eq('payload-1')
    expect(responses['app-2'].status).to eq(200)
    expect(responses['app-2'].body).to eq('payload-2')
    expect(manager.max_active).to eq(2)

    # The revoked request never went out and was never reported as a success.
    expect(responses['app-3']).not_to be_finished
    expect(responses['app-3'].status).to be_nil
    expect(responses['app-3'].body).to be_nil
    expect(responses['app-3'].success?).to be(false)

    # Its completion callback was never invoked.
    expect(completed_apps).to match_array(%w[app-1 app-2])

    # The un-runnable request is handed back to the caller, both through the
    # callback and through the manager's list.
    expect(handled_revocations).to eq(['app-3'])
    expect(manager.revoked_requests.map(&:app_id)).to eq(['app-3'])
    expect(manager.revoked_requests.first).to have_attributes(
      method: :get,
      url: 'http://backend.internal/pulls/app-3'
    )

    # Only the two authorized requests were ever performed; the revoked one
    # never reached the adapter, so nothing left the process for it.
    expect(adapter.executed_paths).to match_array(%w[/pulls/app-1 /pulls/app-2])
  end

  it 'keeps a request un-finished even if its on_complete is registered later' do
    manager = InMemoryParallelManager.new(registry: registry)

    revoked_response = nil
    connection.in_parallel(manager) do
      revoked_response = connection.get('/pulls/app-3') do |request|
        request.headers['X-App-Id'] = 'app-3'
      end
      registry.revoke('app-3')
    end

    fired = false
    revoked_response.on_complete { fired = true }

    expect(revoked_response).not_to be_finished
    expect(fired).to be(false)
    expect(manager.revoked_requests.map(&:app_id)).to eq(['app-3'])
  end

  it 'still performs requests normally outside a parallel block' do
    response = connection.get('/pulls/app-1') do |request|
      request.headers['X-App-Id'] = 'app-1'
    end

    expect(response).to be_finished
    expect(response.status).to eq(200)
    expect(response.body).to eq('payload-1')
    expect(adapter.executed_paths).to eq(['/pulls/app-1'])
  end
end
