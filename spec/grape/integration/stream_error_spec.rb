# frozen_string_literal: true

describe 'streaming download errors' do
  include Rack::Test::Methods

  # A download body that fails either before its first byte or after it, and
  # records when it was closed relative to the response the caller observed.
  class DownloadBody
    def initialize(failure_point, events)
      @failure_point = failure_point
      @events = events
    end

    def each
      raise 'SECRET internal handle before first byte' if @failure_point == :before

      yield 'first-chunk-'
      raise 'SECRET internal handle after first byte' if @failure_point == :after

      yield 'second-chunk'
    end

    def close
      @events << :body_closed
    end
  end

  let(:events) { [] }
  let(:errors) { StringIO.new }

  let(:app) do
    recorded = events
    Class.new(Grape::API) do
      format :json
      # Unified public classification: every failed download answers the same
      # public error, regardless of the underlying exception.
      rescue_from :all do |_error|
        error!({ error: 'download_failed' }, 500)
      end

      get('/fail-before') { stream DownloadBody.new(:before, recorded) }
      get('/fail-after') { stream DownloadBody.new(:after, recorded) }
      get('/ok') { stream DownloadBody.new(nil, recorded) }
    end
  end

  def request(path)
    get path, {}, Rack::RACK_ERRORS => errors
  end

  describe 'a failure before the first byte' do
    it 'renders a normal error response and returns the body before the request ends' do
      request('/fail-before')

      expect(last_response.status).to eq(500)
      expect(last_response.content_type).to include('application/json')
      expect(JSON.parse(last_response.body)).to eq('error' => 'download_failed')
      # The failure's internal state never reaches the response or the log.
      expect(last_response.body).not_to include('SECRET')
      expect(errors.string).not_to include('SECRET')
      # The body was closed by the time the request finished, exactly once.
      expect(events).to eq(%i[body_closed])
    end
  end

  describe 'a failure after the first byte' do
    it 'ends the committed stream safely, keeps the sent bytes, and returns the body' do
      request('/fail-after')

      # The status and headers were already sent: the caller keeps the 200 and
      # the partial body, with the stream ended rather than an exception raised.
      expect(last_response.status).to eq(200)
      expect(last_response.body).to eq('first-chunk-')
      expect(last_response.body).not_to include('SECRET')
      # The abort is logged by class name only and the body is given back.
      expect(errors.string).to include('Grape stream aborted after the response was committed: RuntimeError')
      expect(errors.string).not_to include('SECRET')
      expect(last_request.env[Grape::Env::RACK_EXCEPTION]).to be_a(RuntimeError)
      expect(events).to eq(%i[body_closed])
    end
  end

  describe 'a successful download' do
    it 'streams every chunk and closes the body' do
      request('/ok')

      expect(last_response.status).to eq(200)
      expect(last_response.body).to eq('first-chunk-second-chunk')
      expect(events).to eq(%i[body_closed])
    end
  end
end
