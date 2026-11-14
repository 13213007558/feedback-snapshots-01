# frozen_string_literal: true

require 'helper'

# Structured, property-style tests for the request-phase -> session ->
# callback chain that carries omniauth.params:
#
#   request.params (real Rack parameter parsing)
#     -> Strategy#omniauth_params (protocol-only params removed, deep-copied)
#     -> session['omniauth.params'] (saved, then marshaled by a real session)
#     -> env['omniauth.params'] on the callback (and removed from the session)
#
# The inputs are generated, not hand-picked, with bounded size so a run is
# deterministic and fast, and every failure shrinks to a small query string.
# The point is the boundary: business params must survive intact, while the
# authenticity token (the only parameter that exists solely for protocol
# validation) must never reach the callback, at any nesting level.
module ParamPersistenceExamples
  # Characters that are legal inside a Rack parameter key or value without
  # percent-encoding, deliberately excluding '&', '=' and the brackets that
  # drive nesting, which the generator emits structurally instead.
  SAFE_CHARS = ['a', 'b', 'z', '0', '9', '-', '_', '.', ' ', 'é', '中'].freeze
  SENSITIVE_KEYS = %w[password password_confirmation token api_key secret authorization].freeze
  BUSINESS_KEYS = %w[scope plan login locale origin invite return_to state nonce].freeze
  KEY_POOL = (BUSINESS_KEYS + SENSITIVE_KEYS + ['authenticity_token', 'profile', 'filters', 'x']).freeze

  # A bounded query tree: a Hash of at most MAX_KEYS keys whose values are
  # scalars, Arrays of at most MAX_ARRAY scalars/hashes, or nested Hashes up
  # to MAX_DEPTH. Depth and width caps make generation total and keep every
  # example well within Rack's parser limits and a cookie session's size cap.
  MAX_DEPTH = 3
  MAX_KEYS = 3
  MAX_ARRAY = 2
  MAX_EXAMPLES = Integer(ENV.fetch('PARAM_SPEC_EXAMPLES', '70'))

  class Gen
    attr_reader :seed

    def initialize(seed)
      @seed = seed
      @rng = Random.new(seed)
      @counter = 0
    end

    def integer(max)
      @rng.rand(max)
    end

    def pick(values)
      values.fetch(integer(values.length))
    end

    # Unique within one generated tree, so a well-formed tree never reuses a
    # key at the same level and can't trigger Rack's type-collision parser
    # errors. Collisions are generated separately, on purpose, by the
    # adversarial examples.
    def key
      @counter += 1
      base = KEY_POOL.fetch(@counter % KEY_POOL.length)
      "#{base}_#{@counter}"
    end

    def scalar_value
      case integer(6)
      when 0 then ''
      when 1 then pick(SAFE_CHARS) * (integer(3) + 1)
      when 2 then integer(1000).to_s
      when 3 then pick(SENSITIVE_KEYS) # a value that merely looks sensitive
      when 4 then "value#{integer(50)}"
      else (+'bad').force_encoding(Encoding::UTF_8)
      end
    end

    def array(depth)
      Array.new(integer(MAX_ARRAY) + 1) do
        depth >= MAX_DEPTH ? scalar_value : pick([scalar_value, hash(depth)])
      end
    end

    def hash(depth)
      count = integer(MAX_KEYS) + 1
      count.times.each_with_object({}) do |_, tree|
        tree[key] = depth >= MAX_DEPTH ? scalar_value : pick([scalar_value, array(depth + 1), hash(depth + 1)])
      end
    end

    def tree
      hash(1)
    end
  end

  # Renders a tree as a real application/x-www-form-urlencoded query string.
  # Hash nesting becomes a[b]=..., Arrays use empty brackets a[]=..., and
  # every leaf is percent-encoded so binary bytes and reserved characters
  # travel exactly as a client would send them.
  module Render
    module_function

    def call(tree)
      pairs = []
      append(tree, +'', pairs)
      pairs.join('&')
    end

    def append(value, prefix, pairs)
      case value
      when Hash
        value.each do |key, nested|
          nested_prefix = prefix.empty? ? escape(key) : "#{prefix}[#{escape(key)}]"
          append(nested, nested_prefix, pairs)
        end
      when Array
        value.each do |nested|
          append(nested, "#{prefix}[]", pairs)
        end
      else
        pairs << "#{prefix}=#{escape(value)}"
      end
    end

    def escape(value)
      URI.encode_www_form_component(value.to_s, Encoding::UTF_8)
    end
  end

  # Shrinks a failing query string toward a small one while keeping it a
  # failure. It first drops pairs, then trims each pair's nesting path, then
  # shortens the leaf text, returning the smallest string that still violates
  # the property. A hand-written shrinker (rather than random re-generation)
  # makes the reported counterexample stable across runs and easy to read.
  # Returns nil when the starting input already satisfies the property, so a
  # caller can tell "no counterexample" apart from "the smallest input is the
  # starting one".
  module Shrinker
    module_function

    def find(initial_query)
      return nil if yield(initial_query)

      current = initial_query
      loop do
        smaller = candidates(current).detect { |candidate| !yield(candidate) }
        return current unless smaller

        current = smaller
      end
    end

    def candidates(query)
      pairs = query.split('&')
      drops = pairs.each_index.map { |index| pairs.reject.with_index { |_, i| i == index }.join('&') }
      trims = pairs.filter_map do |pair|
        head, value = pair.split('=', 2)
        segments = head.split(/\[|\]\[?/).reject(&:empty?)
        next if segments.length <= 1

        flattened = "#{segments.first}=#{value}"
        (pairs - [pair] + [flattened]).join('&')
      end
      short_values = pairs.filter_map do |pair|
        head, value = pair.split('=', 2)
        next if value.nil? || value.length <= 1

        shortened = (pairs - [pair] + ["#{head}=#{value[0...(value.length / 2)]}"]).join('&')
        shortened
      end
      (drops + trims + short_values).uniq.reject(&:empty?)
    end
  end

  # What the contract says the saved params must equal: the real parsed
  # params, with the authenticity token removed at every level, but with every
  # business and merely-sensitive parameter kept verbatim. Computed from the
  # parser output rather than reimplemented, so it tests the boundary instead
  # of duplicating the parser.
  module Expected
    module_function

    def without_authenticity(value)
      case value
      when Hash
        value.each_with_object(value.class.new) do |(key, nested), result|
          next if key == 'authenticity_token'

          result[key] = without_authenticity(nested)
        end
      when Array
        value.map { |nested| without_authenticity(nested) }
      else
        value
      end
    end
  end

  # A strategy that records the params and the request object, and a callback
  # app that echoes the restored params back through the env.
  class CapturingStrategy
    include OmniAuth::Strategy

    option :name, 'test'
    attr_reader :captured_request_params

    def request_phase
      @captured_request_params = request.params
      [200, {}, ['request']]
    end

    def callback_phase
      call_app!
    end
  end

  # Deliberately reproduces the pre-fix save boundary: a shallow reject with
  # no deep copy and no nested-token removal. It exists to prove the property
  # tests actually fail when an isolation measure is removed, instead of
  # passing vacuously.
  class UnsafeStrategy < CapturingStrategy
    def omniauth_params
      request.params.reject { |key, _| key.eql?('authenticity_token') }
    end

    # Mutates the strategy's own memoized request params during the request
    # phase, after the boundary was saved: code a real app runs at this point
    # (a hook, the strategy's request_phase) has exactly this handle.
    def request_phase
      request.params.each_value do |value|
        value['MUTATED'] = true if value.is_a?(Hash)
        value << 'MUTATED' if value.is_a?(Array)
      end
      super
    end
  end

  # Removes only the deep-copy measure: the token filter stays, but the saved
  # hash keeps sharing its nested containers with request.params.
  class SharedCopyStrategy < CapturingStrategy
    def omniauth_params
      request.params.each_with_object(request.params.class.new) do |(key, nested), sanitized|
        next if key.eql?('authenticity_token')

        sanitized[key] = nested
      end
    end

    def request_phase
      request.params.each_value do |value|
        value['MUTATED'] = true if value.is_a?(Hash)
        value << 'MUTATED' if value.is_a?(Array)
      end
      super
    end
  end

  # Removes only the nested-token measure: the deep copy stays, so only the
  # top-level authenticity token is dropped.
  class TopLevelOnlyStrategy < CapturingStrategy
    def omniauth_params
      OmniAuth::Utils.deep_dup(request.params.reject { |key, _| key.eql?('authenticity_token') })
    end
  end

  def new_strategy(app = callback_app, **options)
    CapturingStrategy.new(app, **options)
  end

  def run_cycle_with(strategy_class, query)
    session = {}
    strategy = strategy_class.new(callback_app)
    strategy.call(request_env(query, session))
    saved = session['omniauth.params']
    status, _, body = strategy.call(callback_env(session))
    {
      :status => status,
      :session => session,
      :saved => saved,
      :restored => Marshal.load(body.join),
      :request_params => strategy.captured_request_params
    }
  end

  # Marshal, rather than JSON, so a value holding invalid UTF-8 bytes can be
  # observed exactly: JSON refuses to generate one, and replacing the bytes
  # would hide whether the boundary preserves the original payload.
  def callback_app
    lambda { |env| [200, {'Content-Type' => 'application/octet-stream'}, [Marshal.dump(env['omniauth.params'] || {})]] }
  end

  def request_env(query, session)
    Rack::MockRequest.env_for(
      "http://app.example/auth/test?#{query}",
      :method => 'POST',
      'rack.input' => StringIO.new(''),
      'rack.session' => session
    )
  end

  def callback_env(session, cookie = nil)
    Rack::MockRequest.env_for(
      'http://app.example/auth/test/callback',
      'rack.session' => session,
      'HTTP_COOKIE' => cookie
    )
  end

  def parsed_params(query)
    Rack::Request.new(request_env(query, {})).params
  end

  # Runs the full request -> session -> callback cycle against a fresh
  # strategy and session, returning the observed artifacts.
  def run_cycle(query)
    session = {}
    strategy = new_strategy
    strategy.call(request_env(query, session))
    saved = session['omniauth.params']
    status, _, body = strategy.call(callback_env(session))
    restored = Marshal.load(body.join)
    {
      :status => status,
      :session => session,
      :saved => saved,
      :restored => restored,
      :request_params => strategy.captured_request_params
    }
  end

  # A real cookie-session stack, exercising marshaling and a separate request,
  # the way production carries the params between the two phases.
  def run_cookie_cycle(query)
    app = callback_app
    stack = Rack::Builder.new do
      use Rack::Session::Cookie, :secret => SecureRandom.hex(32)
      use CapturingStrategy
      run app
    end.to_app

    request = stack.call(request_env(query, {}))
    cookie_header = request[1]['set-cookie']
    raise "no session cookie for query of #{query.length} bytes (over the session size cap?)" unless cookie_header

    cookie = cookie_header.split(';').first
    status, headers, body = stack.call(callback_env({}, cookie))
    { :status => status, :headers => headers, :restored => Marshal.load(body.join) }
  end

  def each_seed
    (1..MAX_EXAMPLES).each do |index|
      # A fixed base keeps the suite reproducible; different examples still
      # cover independent shapes because each ParamPersistenceExamples::Gen stream advances on its own.
      yield index, ParamPersistenceExamples::Gen.new(9000 + index * 7)
    end
  end
end

describe OmniAuth::Strategy, 'omniauth.params persistence' do
  include ParamPersistenceExamples

  around do |example|
    validation_phase = OmniAuth.config.request_validation_phase
    OmniAuth.config.request_validation_phase = nil
    example.run
  ensure
    OmniAuth.config.request_validation_phase = validation_phase
  end

  describe 'round trip through real parsing and the session' do
    it 'keeps every business and sensitive-looking param and drops only the authenticity token' do
      failures = []
      each_seed do |index, gen|
        query = ParamPersistenceExamples::Render.call(gen.tree)
        result = run_cycle(query)
        expected = ParamPersistenceExamples::Expected.without_authenticity(parsed_params(query))

        unless result[:status] == 200 && result[:restored] == expected
          failures << [index, query]
        end
      end

      expect(failures).to be_empty, -> {
        index, query = failures.first
        shrunk = ParamPersistenceExamples::Shrinker.find(query) do |candidate|
          outcome = run_cycle(candidate)
          outcome[:status] == 200 && outcome[:restored] == ParamPersistenceExamples::Expected.without_authenticity(parsed_params(candidate))
        end
        "example #{index} violated the contract\nfull query: #{query}\nshrunk:    #{shrunk}"
      }
    end

    it 'preserves params through a real cookie-session marshal boundary' do
      each_seed do |_index, gen|
        query = ParamPersistenceExamples::Render.call(gen.tree)
        result = run_cookie_cycle(query)
        expected = ParamPersistenceExamples::Expected.without_authenticity(parsed_params(query))

        expect(result[:status]).to eq(200)
        expect(result[:restored]).to eq(expected)
      end
    end
  end

  describe 'isolation of the saved copy from request.params' do
    it 'deep-copies nested hashes and arrays so mutation after the boundary cannot reach them' do
      each_seed do |_index, gen|
        query = ParamPersistenceExamples::Render.call(gen.tree)
        result = run_request_phase_with(ParamPersistenceExamples::CapturingStrategy, query)

        # A second request builds a fresh parser output; mutating it must not
        # touch the first request's saved params, and mutating the saved copy
        # must not be visible through the request's still-live params.
        follow_up = run_request_phase_with(ParamPersistenceExamples::CapturingStrategy, query)
        inject_everywhere(follow_up[:request_params], 'MUTATED')
        expect(contains_key?(result[:saved], 'MUTATED')).to be(false)

        inject_everywhere(result[:saved], 'MUTATED')
        expect(contains_key?(follow_up[:request_params], 'MUTATED')).to be(false)
      end
    end

    it 'is proven meaningful by a strategy that mutates its own request params' do
      query = 'profile[name]=ana&tags[]=a'

      shared = run_request_phase_with(ParamPersistenceExamples::SharedCopyStrategy, query)
      expect(contains_key?(shared[:saved], 'MUTATED')).to be(true)

      fixed = run_request_phase_with(ParamPersistenceExamples::CapturingStrategy, query)
      expect(contains_key?(fixed[:saved], 'MUTATED')).to be(false)
    end

    it 'does not let one sign-in observe or mutate another sign-in nested object' do
      session = {}
      first = new_strategy
      first.call(request_env('profile[name]=ana&tags[]=a', session))
      first_saved = session['omniauth.params']

      second = new_strategy
      second.call(request_env('profile[name]=leo&tags[]=b', session))

      expect(first_saved).to eq('profile' => {'name' => 'ana'}, 'tags' => ['a'])
      expect(session['omniauth.params']).to eq('profile' => {'name' => 'leo'}, 'tags' => ['b'])
      expect(first_saved).not_to equal(session['omniauth.params'])
      expect(first_saved['profile']).not_to equal(session['omniauth.params']['profile'])
    end
  end

  describe 'protocol-only parameters' do
    it 'removes the authenticity token as a scalar, array, hash and nested value' do
      queries = [
        'authenticity_token=sec&b=2',
        'authenticity_token[]=sec&authenticity_token[]=ret&b=2',
        'form[authenticity_token]=sec&form[keep]=1',
        'form[deep][authenticity_token]=sec&form[deep][keep]=1',
        'authenticity_token=sec&authenticity_token=ret&b=2',
        'rows[][authenticity_token]=sec&rows[][keep]=1'
      ]
      queries.each do |query|
        result = run_cycle(query)
        expect(contains_key?(result[:restored], 'authenticity_token'))
          .to be(false), "expected no authenticity token for #{query}, got #{result[:restored].inspect}"
        expect(result[:restored]['b']).to eq('2') if query.include?('b=2')
      end
    end

    it 'keeps a business parameter whose name merely contains the protocol name' do
      result = run_cycle('x_authenticity_token=keep&authenticity_token=drop')
      expect(result[:restored]).to eq('x_authenticity_token' => 'keep')
    end
  end

  describe 'parser-rejected inputs leave no half-saved params' do
    it 'stores nothing when Rack raises on type collisions or excessive depth' do
      collision = 'a=1&a[b]=2&good=1'
      deep = 'x' + '[x]' * 40 + '=1&good=1'

      [collision, deep].each do |query|
        session = {}
        status, = new_strategy.call(request_env(query, session))

        expect(status).to eq(302)
        expect(session).not_to have_key('omniauth.params')
        expect(session.keys.grep(/omniauth/)).to be_empty
      end
    end

    it 'leaves a previously stored sign-in untouched when a later request fails to parse' do
      session = {}
      new_strategy.call(request_env('legit=1', session))
      expect(session['omniauth.params']).to eq('legit' => '1')

      new_strategy.call(request_env('a=1&a[b]=2', session))
      expect(session['omniauth.params']).to eq('legit' => '1')
    end

    it 'removes the params from the session even when the callback app raises' do
      session = {'omniauth.params' => {'legit' => '1'}}
      boom = lambda { |_env| raise RuntimeError, 'downstream failure' }

      expect { new_strategy(boom).call(callback_env(session)) }.to raise_error(RuntimeError)
      expect(session).not_to have_key('omniauth.params')
    end
  end

  describe 'encoding and sensitive values' do
    it 'round-trips invalid byte sequences without raising and keeps them as values' do
      session = {}
      status, = new_strategy.call(request_env('a=%ff&b=%fe%ff', session))
      expect(status).to eq(200)
      expect(session['omniauth.params'].keys).to contain_exactly('a', 'b')

      # A real cookie session must accept the binary payload; the callback
      # restores it without a marshaling or encoding error.
      result = run_cookie_cycle('a=%ff&b=2')
      expect(result[:status]).to eq(200)
      expect(result[:restored]).to eq('a' => "\xFF", 'b' => '2')
    end

    it 'treats sensitive-looking business params as data to retain, not protocol secrets to strip' do
      query = 'password=hunter2&api_key=k&user[secret]=s&authenticity_token=drop&plan=pro'
      result = run_cycle(query)

      expect(result[:restored]).to eq(
        'password' => 'hunter2',
        'api_key' => 'k',
        'user' => {'secret' => 's'},
        'plan' => 'pro'
      )
    end

    it 'keeps empty, repeated and bracket-shaped business values intact' do
      query = 'a=&b=1&b=2&tags[]=x&tags[]=y&nested[k]=v'
      result = run_cycle(query)

      expect(result[:restored]).to eq(
        'a' => '',
        'b' => '2',
        'tags' => ['x', 'y'],
        'nested' => {'k' => 'v'}
      )
    end
  end

  describe 'shrinker' do
    it 'reports no counterexample for an input the fixed boundary already sanitizes' do
      big = 'good=1&form[authenticity_token]=sec&form[keep]=1&z[y][w]=v&tags[]=t'
      shrunk = ParamPersistenceExamples::Shrinker.find(big) do |candidate|
        !contains_key?(run_cycle(candidate)[:restored], 'authenticity_token')
      end

      expect(shrunk).to be_nil
    end

    it 'shrinks a contaminated input against the removed-isolation strategy' do
      big = 'good=1&form[authenticity_token]=sec&form[keep]=1&z[y][w]=v&tags[]=t'

      shrunk = ParamPersistenceExamples::Shrinker.find(big) do |candidate|
        result = run_cycle_with(ParamPersistenceExamples::UnsafeStrategy, candidate)
        !contains_key?(result[:restored], 'authenticity_token')
      end

      expect(shrunk).not_to be_nil
      expect(shrunk.length).to be < big.length
      expect(contains_key?(run_cycle_with(ParamPersistenceExamples::UnsafeStrategy, shrunk)[:restored], 'authenticity_token'))
        .to be(true)
    end
  end

  # Runs only the request phase, leaving the saved params in the session, so
  # the window between saving and the callback can be probed directly.
  def run_request_phase_with(strategy_class, query)
    session = {}
    strategy = strategy_class.new(callback_app)
    strategy.call(request_env(query, session))
    { :session => session, :saved => session['omniauth.params'], :request_params => strategy.captured_request_params }
  end

  describe 'when an isolation measure is deliberately removed' do
    it 'the deep-copy property catches a strategy that shares nested objects' do
      query = 'profile[name]=ana&tags[]=a'

      shared = run_request_phase_with(ParamPersistenceExamples::SharedCopyStrategy, query)
      expect(contains_key?(shared[:saved], 'MUTATED')).to be(true)

      fixed = run_request_phase_with(ParamPersistenceExamples::CapturingStrategy, query)
      expect(contains_key?(fixed[:saved], 'MUTATED')).to be(false)
      expect(fixed[:saved]).to eq('profile' => {'name' => 'ana'}, 'tags' => ['a'])
    end

    it 'the nested-token property catches a strategy that only filters the top level' do
      query = 'form[authenticity_token]=sec&form[keep]=1'
      weak = run_cycle_with(ParamPersistenceExamples::TopLevelOnlyStrategy, query)
      fixed = run_cycle(query)

      expect(contains_key?(weak[:restored], 'authenticity_token')).to be(true)
      expect(contains_key?(fixed[:restored], 'authenticity_token')).to be(false)
      expect(fixed[:restored]).to eq('form' => {'keep' => '1'})
    end

    it 'the original pre-fix boundary fails both properties at once' do
      query = 'form[authenticity_token]=sec&profile[name]=ana'
      legacy = run_request_phase_with(ParamPersistenceExamples::UnsafeStrategy, query)

      expect(contains_key?(legacy[:saved], 'authenticity_token')).to be(true)
      expect(contains_key?(legacy[:saved], 'MUTATED')).to be(true)
    end
  end

  def inject_everywhere(value, marker)
    case value
    when Hash
      value[marker] = true
      value.each_value { |nested| inject_everywhere(nested, marker) }
    when Array
      value.each { |nested| inject_everywhere(nested, marker) }
    end
  end

  def contains_key?(value, key)
    case value
    when Hash
      value.key?(key) || value.values.any? { |nested| contains_key?(nested, key) }
    when Array
      value.any? { |nested| contains_key?(nested, key) }
    else
      false
    end
  end
end
