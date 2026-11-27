# frozen_string_literal: true

# Acceptance for `version ... vary: true`: an API whose resource changes
# representation across a version migration answers every response -- the
# representations, a failed negotiation and the fallback another version
# answers -- with a Vary naming the negotiation inputs, so a shared cache
# keys what it stores on them. The cache below is a stand-in shared cache
# (RFC 9111): it replays a stored response to a request whose Vary-listed
# header values match, and refuses what Cache-Control keeps out of shared
# caches.
describe 'Vary on the responses of a versioned API' do
  # In-memory shared cache: stores GET responses by path plus the values of
  # the request headers each stored response's Vary listed.
  class InMemorySharedCache
    Entry = Data.define(:path, :vary, :request_values, :response)

    def initialize(app)
      @app = app
      @entries = []
    end

    def call(env)
      request = Rack::Request.new(env)
      return @app.call(env) unless request.get?

      entry = @entries.find do |candidate|
        candidate.path == request.path_info && candidate.request_values == vary_values(env, candidate.vary)
      end
      return respond_with(entry.response, 'hit') if entry

      response = buffered(@app.call(env))
      store(request.path_info, env, response) if storable?(response[1])
      respond_with(response, 'miss')
    end

    private

    # Bodies the app hands out may be one-shot, so a response is buffered
    # once and the buffer is what gets stored and answered with.
    def buffered(response)
      status, headers, body = response
      parts = []
      body.each { |part| parts << part }
      body.close if body.respond_to?(:close)
      [status, headers, parts]
    end

    def store(path, env, response)
      status, headers, parts = response
      vary = (headers['vary'] || headers['Vary']).split(',').map(&:strip)
      @entries << Entry.new(path, vary, vary_values(env, vary), [status, headers, parts])
    end

    def storable?(headers)
      vary = headers['vary'] || headers['Vary']
      return false unless vary

      cache_control = headers['cache-control'] || ''
      !cache_control.match?(/no-store|private/)
    end

    def vary_values(env, vary)
      vary.to_h { |name| [name, env["HTTP_#{name.tr('-', '_').upcase}"]] }
    end

    def respond_with(response, cache)
      status, headers, body = response
      [status, headers.merge('x-cache' => cache), body]
    end
  end

  subject do
    Class.new(Grape::API) do
      version 'v2', using: :header, vendor: 'acme', vary: true
      format :json

      get 'thing' do
        { representation: 'v2' }
      end

      version 'v1', using: :header, vendor: 'acme', vary: true do
        get 'thing' do
          { representation: 'v1-legacy' }
        end
      end

      get 'custom' do
        header 'Vary', 'X-Custom'
        header 'Cache-Control', 'private, no-store'
        { representation: 'custom' }
      end
    end
  end

  def app
    InMemorySharedCache.new(subject)
  end

  def get_with_accept(path, accept)
    get path, {}, { 'HTTP_ACCEPT' => accept }
    [last_response.status, last_response.headers, last_response.body]
  end

  it 'serves each representation from the shared cache for its own Accept, in reverse order' do
    status, headers, body = get_with_accept('/thing', 'application/vnd.acme-v2+json')
    expect([status, headers['vary'], headers['x-cache'], body]).to eq([200, 'Accept', 'miss', '{"representation":"v2"}'])

    status, headers, body = get_with_accept('/thing', 'application/vnd.acme-v1+json')
    expect([status, headers['vary'], headers['x-cache'], body]).to eq([200, 'Accept', 'miss', '{"representation":"v1-legacy"}'])

    status, headers, body = get_with_accept('/thing', 'application/vnd.acme-v1+json')
    expect([status, headers['vary'], headers['x-cache'], body]).to eq([200, 'Accept', 'hit', '{"representation":"v1-legacy"}'])

    status, headers, body = get_with_accept('/thing', 'application/vnd.acme-v2+json')
    expect([status, headers['vary'], headers['x-cache'], body]).to eq([200, 'Accept', 'hit', '{"representation":"v2"}'])
  end

  it 'lists the negotiation input on the 404 a failed negotiation cascades into' do
    status, headers, body = get_with_accept('/thing', 'application/vnd.acme-v3+json')
    expect([status, headers['vary'], body]).to eq([404, 'Accept', '404 Not Found'])
  end

  it 'keeps the Vary and Cache-Control an app set, and out of the shared cache' do
    status, headers, body = get_with_accept('/custom', 'application/vnd.acme-v2+json')
    expect([status, headers['vary'], headers['cache-control'], headers['x-cache'], body])
      .to eq([200, 'X-Custom, Accept', 'private, no-store', 'miss', '{"representation":"custom"}'])

    _, headers, = get_with_accept('/custom', 'application/vnd.acme-v2+json')
    expect(headers['x-cache']).to eq('miss')
  end
end
