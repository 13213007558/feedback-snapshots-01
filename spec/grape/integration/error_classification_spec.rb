# frozen_string_literal: true

# Acceptance for the layered error contract of a public "issue details" API:
# customer service maps every failure to a stable business classification and
# a sanitized body, while the internal stage detail stays on the rack env for
# on-call to check separately. Only rack-test drives the requests.
describe 'Public issue details error contract' do
  let(:api_class) do
    Class.new(Grape::API) do
      format :json

      # Business classification -> [status, public message]. The only vocabulary
      # a client may ever see; backend detail never joins it.
      classifications = {
        'issue_not_found' => [404, 'Issue not found'],
        'issue_archived' => [410, 'Issue no longer available'],
        'lookup_unavailable' => [503, 'Issue details temporarily unavailable']
      }

      backend_timeout = Class.new(StandardError)
      stale_record = Class.new(StandardError)
      issue_archived = Class.new(StandardError)
      sensitive_lookup = Class.new(StandardError)

      helpers do
        define_method(:public_error!) do |code|
          status, message = classifications.fetch(code)
          error!({ code:, message: }, status)
        end
      end

      # Layer 2: a raised backend exception is reclassified and sanitized.
      rescue_from backend_timeout do
        public_error!('lookup_unavailable')
      end

      # Layer 3: this handler reclassifies by raising an error that has its own
      # registered handler; the middleware redispatches to it once.
      rescue_from stale_record do
        raise issue_archived
      end

      rescue_from issue_archived do
        public_error!('issue_archived')
      end

      # Layer 4: the rescue handler itself fails with an unregistered error.
      rescue_from sensitive_lookup do
        raise NoMethodError, "redaction failed for tenant token 'sekret'"
      end

      # Layer 1: an explicit error! with the public classification.
      get('/issues/missing') { public_error!('issue_not_found') }
      get('/issues/slow') { raise backend_timeout, 'pg query 14.2s against shard 7' }
      get('/issues/stale') { raise stale_record, 'replica lag 32s behind primary' }
      get('/issues/redaction-broken') { raise sensitive_lookup, "row owned by tenant 'acme-internal'" }
    end
  end

  # Exceptions Grape publishes on the rack env for the on-call side. Never
  # part of a client response.
  let(:internal_events) { [] }

  let(:app) do
    api = api_class
    events = internal_events
    lambda do |env|
      api.call(env).tap do
        events << env[Grape::Env::RACK_EXCEPTION] if env.key?(Grape::Env::RACK_EXCEPTION)
      end
    end
  end

  let(:parsed_body) { Grape::Json.load(last_response.body) }

  describe 'explicit error!' do
    before { get '/issues/missing' }

    it 'answers the classified status and sanitized body' do
      expect(last_response.status).to eq(404)
      expect(parsed_body).to eq('code' => 'issue_not_found', 'message' => 'Issue not found')
    end

    it 'publishes no internal event' do
      expect(internal_events).to be_empty
    end
  end

  describe 'raised exception reclassified by rescue_from' do
    before { get '/issues/slow' }

    it 'answers the mapped classification' do
      expect(last_response.status).to eq(503)
      expect(parsed_body).to eq('code' => 'lookup_unavailable', 'message' => 'Issue details temporarily unavailable')
    end

    it 'keeps the backend detail out of the response' do
      expect(last_response.body).not_to include('shard')
    end
  end

  describe 'rescue handler redispatch' do
    before { get '/issues/stale' }

    it 'answers with the reclassified mapping of the redispatched handler' do
      expect(last_response.status).to eq(410)
      expect(parsed_body).to eq('code' => 'issue_archived', 'message' => 'Issue no longer available')
    end
  end

  describe 'rescue handler itself failing' do
    before { get '/issues/redaction-broken' }

    # The conversion happens in Grape::Middleware::Error#redispatch: the
    # handler-raised error matches no registered rescue_from and is not a
    # Grape exception, so the safe default renders the framework's generic
    # InternalServerError. The client gets that stable 500, never a
    # classification derived from either failure.
    it 'answers the stable framework 500' do
      expect(last_response.status).to eq(500)
      expect(parsed_body).to eq('error' => 'Internal Server Error')
    end

    it 'leaks neither the lookup detail nor the handler failure' do
      expect(last_response.body).not_to include('acme-internal')
      expect(last_response.body).not_to include('sekret')
    end

    # The one item allowed only in internal events: the handler-raised
    # exception itself, on env['rack.exception'] for on-call to reconcile.
    it 'publishes the handler failure only as an internal event' do
      expect(internal_events.length).to eq(1)
      expect(internal_events.first).to be_a(NoMethodError)
      expect(internal_events.first.message).to include('sekret')
    end
  end

  describe 'final media type' do
    it 'renders every layer as the negotiated media type' do
      %w[missing slow stale redaction-broken].each do |id|
        get "/issues/#{id}"
        expect(last_response.content_type).to eq('application/json')
      end
    end

    it 'limits client-visible keys to the public vocabulary' do
      %w[missing slow stale redaction-broken].each do |id|
        get "/issues/#{id}"
        expect(parsed_body.keys).to all(satisfy { |key| %w[code message error].include?(key) })
      end
    end
  end
end
