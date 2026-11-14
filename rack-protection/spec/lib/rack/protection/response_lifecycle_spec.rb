# frozen_string_literal: true

require 'stringio'

module ResponseLifecycleProbes
  class EnumerableBody
    attr_reader :each_calls, :call_calls, :close_calls

    def initialize(*chunks, close_error: nil, iteration_error: nil)
      @chunks = chunks
      @close_error = close_error
      @iteration_error = iteration_error
      @each_calls = 0
      @call_calls = 0
      @close_calls = 0
      @open = true
    end

    def each
      @each_calls += 1
      raise @iteration_error if @iteration_error

      @chunks.each { |chunk| yield chunk }
    end

    def close
      @close_calls += 1
      @open = false
      raise @close_error if @close_error
    end

    def open?
      @open
    end
  end

  class CallableBody
    attr_reader :each_calls, :call_calls, :close_calls

    def initialize(*chunks, close_error: nil, iteration_error: nil)
      @chunks = chunks
      @close_error = close_error
      @iteration_error = iteration_error
      @each_calls = 0
      @call_calls = 0
      @close_calls = 0
      @open = true
    end

    def call(stream)
      @call_calls += 1
      raise @iteration_error if @iteration_error

      stream << @chunks.join
    end

    def close
      @close_calls += 1
      @open = false
      raise @close_error if @close_error
    end

    def open?
      @open
    end
  end

  class JsonCsrfReportingByDefault < Rack::Protection::JsonCsrf
    default_reaction :report
  end

  class JsonCsrfWithReactions < Rack::Protection::JsonCsrf
    attr_reader :reaction_calls

    def explode(_env)
      @reaction_calls = reaction_calls.to_i + 1
      raise 'reaction failed'
    end

    def no_response(_env)
      @reaction_calls = reaction_calls.to_i + 1
      nil
    end

    def not_rack(_env)
      @reaction_calls = reaction_calls.to_i + 1
      'not a Rack response'
    end

    def malformed_response(_env)
      @reaction_calls = reaction_calls.to_i + 1
      [418, 'headers', ['teapot']]
    end

    def reuse_body(_env)
      @reaction_calls = reaction_calls.to_i + 1
      [200, { 'content-type' => 'application/json' }, @original_body]
    end

    def teapot(_env)
      @reaction_calls = reaction_calls.to_i + 1
      [418, { 'content-type' => 'text/plain' }, ['teapot']]
    end
  end
end

RSpec.describe 'response-dependent rejection lifecycle' do
  def request_env(extra = {})
    Rack::MockRequest.env_for(
      '/',
      {
        'HTTP_REFERER' => 'http://evil.example',
        'HTTP_HOST' => 'example.org'
      }.merge(extra)
    )
  end

  def json_app(body, headers = {})
    ->(_env) { [200, { 'content-type' => 'application/json' }.merge(headers), body] }
  end

  def call_json_csrf(body, options = {}, middleware_class = Rack::Protection::JsonCsrf)
    env = request_env
    middleware = middleware_class.new(json_app(body), { logging: false }.merge(options))
    [middleware.call(env), env]
  end

  describe 'deny mode' do
    it 'closes the replaced body once without iterating it' do
      body = ResponseLifecycleProbes::EnumerableBody.new('secret-business')
      response, = call_json_csrf(body)

      expect(response[0]).to eq(403)
      expect(response[2].join).to eq('Forbidden')
      expect(body.close_calls).to eq(1)
      expect(body.each_calls).to eq(0)
      expect(body.call_calls).to eq(0)
      expect(body).not_to be_open
    end

    it 'closes a callable body once without calling it' do
      body = ResponseLifecycleProbes::CallableBody.new('secret-business')
      response, = call_json_csrf(body)

      expect(response[0]).to eq(403)
      expect(response[2].join).to eq('Forbidden')
      expect(body.close_calls).to eq(1)
      expect(body.each_calls).to eq(0)
      expect(body.call_calls).to eq(0)
      expect(body).not_to be_open
    end

    it 'returns a custom Rack response without mixing in the original body' do
      body = ResponseLifecycleProbes::EnumerableBody.new('secret-business')
      response, = call_json_csrf(
        body,
        { reaction: :teapot },
        ResponseLifecycleProbes::JsonCsrfWithReactions
      )

      expect(response[0]).to eq(418)
      expect(response[2].join).to eq('teapot')
      expect(body.close_calls).to eq(1)
      expect(body.each_calls).to eq(0)
    end

    it 'falls back to the standard denial when a reaction returns nil' do
      body = ResponseLifecycleProbes::EnumerableBody.new('secret-business')
      middleware = ResponseLifecycleProbes::JsonCsrfWithReactions.new(
        json_app(body), logging: false, reaction: :no_response
      )

      response = middleware.call(request_env)

      expect(response[0]).to eq(403)
      expect(response[2].join).to eq('Forbidden')
      expect(middleware.reaction_calls).to eq(1)
      expect(body.close_calls).to eq(1)
      expect(body.each_calls).to eq(0)
    end

    it 'raises an explicit contract error when a reaction returns a non-Rack value' do
      body = ResponseLifecycleProbes::EnumerableBody.new('secret-business')
      middleware = ResponseLifecycleProbes::JsonCsrfWithReactions.new(
        json_app(body), logging: false, reaction: :not_rack
      )

      expect do
        middleware.call(request_env)
      end.to raise_error(Rack::Protection::Base::ResponseReactionError, /must return a Rack response triple/)

      expect(middleware.reaction_calls).to eq(1)
      expect(body.close_calls).to eq(1)
      expect(body.each_calls).to eq(0)
    end

    it 'raises an explicit contract error when a reaction returns a malformed triple' do
      body = ResponseLifecycleProbes::EnumerableBody.new('secret-business')
      middleware = ResponseLifecycleProbes::JsonCsrfWithReactions.new(
        json_app(body), logging: false, reaction: :malformed_response
      )

      expect do
        middleware.call(request_env)
      end.to raise_error(Rack::Protection::Base::ResponseReactionError, /must return a Rack response triple/)

      expect(middleware.reaction_calls).to eq(1)
      expect(body.close_calls).to eq(1)
      expect(body.each_calls).to eq(0)
    end

    it 'raises an explicit contract error when a reaction reuses the original body' do
      body = ResponseLifecycleProbes::EnumerableBody.new('secret-business')
      middleware = ResponseLifecycleProbes::JsonCsrfWithReactions.new(
        json_app(body), logging: false, reaction: :reuse_body
      )
      middleware.instance_variable_set(:@original_body, body)

      expect do
        middleware.call(request_env)
      end.to raise_error(Rack::Protection::Base::ResponseReactionError, /must not reuse the original body/)

      expect(middleware.reaction_calls).to eq(1)
      expect(body.close_calls).to eq(1)
      expect(body.each_calls).to eq(0)
    end
  end

  describe 'report mode' do
    it 'keeps the original response and records the finding without closing or iterating it' do
      body = ResponseLifecycleProbes::EnumerableBody.new('secret-business')
      response, env = call_json_csrf(body, reaction: :report)

      expect(response[0]).to eq(200)
      expect(response[2]).to be(body)
      expect(env['protection.failed']).to be(true)
      expect(body.close_calls).to eq(0)
      expect(body.each_calls).to eq(0)

      chunks = []
      response[2].each { |chunk| chunks << chunk }
      response[2].close

      expect(chunks.join).to eq('secret-business')
      expect(body.close_calls).to eq(1)
    end

    it 'keeps a callable body intact for the server to consume and close' do
      body = ResponseLifecycleProbes::CallableBody.new('secret-business')
      response, = call_json_csrf(body, reaction: :report)

      expect(response[0]).to eq(200)
      expect(response[2]).to be(body)
      expect(body.call_calls).to eq(0)
      expect(body.close_calls).to eq(0)

      output = StringIO.new
      response[2].call(output)
      response[2].close

      expect(output.string).to eq('secret-business')
      expect(body.call_calls).to eq(1)
      expect(body.close_calls).to eq(1)
    end
  end

  describe 'subclass default reaction' do
    it 'honors report when the subclass declares it as its default reaction' do
      body = ResponseLifecycleProbes::EnumerableBody.new('secret-business')
      middleware = ResponseLifecycleProbes::JsonCsrfReportingByDefault.new(
        json_app(body), logging: false
      )
      env = request_env

      response = middleware.call(env)

      expect(response[0]).to eq(200)
      expect(response[2]).to be(body)
      expect(env['protection.failed']).to be(true)
      expect(body.close_calls).to eq(0)
    end
  end

  describe 'failure paths' do
    it 'fails closed when the rejection decision raises, closing the body once' do
      body = ResponseLifecycleProbes::EnumerableBody.new('secret-business')
      response, = call_json_csrf(body, allow_if: ->(_env) { raise 'decision failed' })

      expect(response[0]).to eq(403)
      expect(response[2].join).to eq('Forbidden')
      expect(body.close_calls).to eq(1)
      expect(body.each_calls).to eq(0)
    end

    it 'fails closed when instrumentation raises' do
      instrumenter = Object.new
      def instrumenter.instrument(*)
        raise 'instrumentation failed'
      end

      body = ResponseLifecycleProbes::EnumerableBody.new('secret-business')
      response, = call_json_csrf(body, instrumenter: instrumenter)

      expect(response[0]).to eq(403)
      expect(body.close_calls).to eq(1)
      expect(body.each_calls).to eq(0)
    end

    it 'fails closed when a reaction raises, closing the body once' do
      body = ResponseLifecycleProbes::EnumerableBody.new('secret-business')
      middleware = ResponseLifecycleProbes::JsonCsrfWithReactions.new(
        json_app(body), logging: false, reaction: :explode
      )

      response = middleware.call(request_env)

      expect(response[0]).to eq(403)
      expect(response[2].join).to eq('Forbidden')
      expect(middleware.reaction_calls).to eq(1)
      expect(body.close_calls).to eq(1)
      expect(body.each_calls).to eq(0)
    end

    it 'stays fail-closed when the decision and the body close both raise' do
      body = ResponseLifecycleProbes::EnumerableBody.new(
        'secret-business',
        close_error: RuntimeError.new('close failed')
      )
      response, = call_json_csrf(body, allow_if: ->(_env) { raise 'decision failed' })

      expect(response[0]).to eq(403)
      expect(response[2].join).to eq('Forbidden')
      expect(body.close_calls).to eq(1)
      expect(body.each_calls).to eq(0)
    end

    it 'does not retry or pass through when closing the replaced body raises' do
      body = ResponseLifecycleProbes::EnumerableBody.new('secret-business', close_error: RuntimeError.new('close failed'))
      response, = call_json_csrf(body)

      expect(response[0]).to eq(403)
      expect(response[2].join).to eq('Forbidden')
      expect(body.close_calls).to eq(1)
      expect(body.each_calls).to eq(0)
    end

    it 'keeps a streaming body reversible in report mode even when it raises during consumption' do
      body = ResponseLifecycleProbes::CallableBody.new(
        'secret-business',
        iteration_error: RuntimeError.new('stream failed')
      )
      response, env = call_json_csrf(body, reaction: :report)

      expect(response[0]).to eq(200)
      expect(response[2]).to be(body)
      expect(env['protection.failed']).to be(true)
      expect(body.call_calls).to eq(0)
      expect(body.close_calls).to eq(0)

      output = StringIO.new
      expect { response[2].call(output) }.to raise_error('stream failed')
      response[2].close

      expect(body.call_calls).to eq(1)
      expect(body.close_calls).to eq(1)
    end

    it 'does not retry or pass through when closing a custom reaction body raises' do
      body = ResponseLifecycleProbes::EnumerableBody.new('secret-business', close_error: RuntimeError.new('close failed'))
      response, = call_json_csrf(
        body,
        { reaction: :teapot },
        ResponseLifecycleProbes::JsonCsrfWithReactions
      )

      expect(response[0]).to eq(418)
      expect(response[2].join).to eq('teapot')
      expect(body.close_calls).to eq(1)
      expect(body.each_calls).to eq(0)
    end

    it 'fails closed and closes the body when the report reaction raises' do
      logging_base = Class.new(Rack::Protection::JsonCsrf) do
        def report(_env)
          raise 'recording failed'
        end
      end

      body = ResponseLifecycleProbes::EnumerableBody.new('secret-business')
      middleware = logging_base.new(json_app(body), logging: false, reaction: :report)

      response = middleware.call(request_env)

      expect(response[0]).to eq(403)
      expect(body.close_calls).to eq(1)
      expect(body.each_calls).to eq(0)
    end

    it 'keeps report mode from turning a logging failure into a denial' do
      logger = Object.new
      def logger.warn(*)
        raise 'log sink failed'
      end

      body = ResponseLifecycleProbes::EnumerableBody.new('secret-business')
      response, env = call_json_csrf(body, reaction: :report, logging: true, logger: logger)

      expect(response[0]).to eq(200)
      expect(response[2]).to be(body)
      expect(env['protection.failed']).to be(true)
      expect(body.close_calls).to eq(0)
    end
  end

  describe 'notification' do
    it 'instruments and warns once for a denial' do
      instrumenter = Object.new
      instrumenter.instance_variable_set(:@calls, 0)
      def instrumenter.calls
        @calls
      end
      def instrumenter.instrument(*)
        @calls += 1
      end

      io = StringIO.new
      body = ResponseLifecycleProbes::EnumerableBody.new('secret-business')
      response, = call_json_csrf(body, logging: true, logger: Logger.new(io), instrumenter: instrumenter)

      expect(response[0]).to eq(403)
      expect(instrumenter.calls).to eq(1)
      expect(io.string.scan(/attack prevented/).length).to eq(1)
    end

    it 'reports once and does not also warn about prevention' do
      io = StringIO.new
      body = ResponseLifecycleProbes::EnumerableBody.new('secret-business')
      response, = call_json_csrf(body, reaction: :report, logging: true, logger: Logger.new(io))

      expect(response[0]).to eq(200)
      expect(io.string.scan(/attack reported/).length).to eq(1)
      expect(io.string.scan(/attack prevented/).length).to eq(0)
    end
  end
end
