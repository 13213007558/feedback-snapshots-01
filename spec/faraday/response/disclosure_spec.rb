# frozen_string_literal: true

require 'stringio'
require 'logger'

RSpec.describe 'Faraday disclosure policy' do
  let(:log) { StringIO.new }
  let(:logger) { Logger.new(log) }
  let(:logger_options) { { headers: true, bodies: true, errors: true } }
  let(:policy) { { request: %i[method url_path], error: %i[message response_body] } }

  let(:query_marker) { 'SYNTHETIC-QUERY-MARKER' }
  let(:auth_marker) { 'SYNTHETIC-AUTH-MARKER' }
  let(:request_body_marker) { 'SYNTHETIC-REQUEST-BODY-MARKER' }
  let(:response_body_marker) { 'SYNTHETIC-RESPONSE-BODY-MARKER' }
  let(:response_header_marker) { 'SYNTHETIC-RESPONSE-HEADER-MARKER' }
  let(:middleware_marker) { 'SYNTHETIC-MIDDLEWARE-MARKER' }

  let(:conn) do
    Faraday.new(disclosure: policy) do |b|
      b.response :logger, logger, logger_options
      b.response :raise_error
      b.adapter :test do |stub|
        stub.post('/success') do
          [200, { 'X-Reply' => response_header_marker }, response_body_marker]
        end
        stub.post('/server-error') do
          [500, { 'X-Reason' => response_header_marker }, response_body_marker]
        end
        stub.post('/boom') { raise Faraday::ConnectionFailed, middleware_marker }
      end
    end
  end

  before do
    logger.level = Logger::DEBUG
  end

  def perform(path)
    conn.post("#{path}?token=#{query_marker}") do |req|
      req.headers['Authorization'] = "Bearer #{auth_marker}"
      req.body = request_body_marker
    end
  end

  describe 'a successful request' do
    it 'logs only the selected request attributes and keeps the response available' do
      response = perform('/success')

      expect(log.string).to include('request: POST /success')
      expect(log.string).not_to include(query_marker)
      expect(log.string).not_to include(auth_marker)
      expect(log.string).not_to include(request_body_marker)
      expect(log.string).to include('response: Status 200')

      expect(response.status).to eq(200)
      expect(response.body).to eq(response_body_marker)
      expect(response.headers['X-Reply']).to eq(response_header_marker)
      expect(response.env.request_headers['Authorization']).to eq("Bearer #{auth_marker}")
      expect(response.env.url.query).to eq("token=#{query_marker}")
    end
  end

  describe 'a server error raised by RaiseError' do
    it 'keeps the error class and status while limiting the attached response details' do
      expect { perform('/server-error') }.to raise_error(Faraday::ServerError) do |error|
        expect(error.response_status).to eq(500)
        expect(error.response_body).to eq(response_body_marker)
        expect(error.response_headers).to be_nil
        expect(error.response.keys).to contain_exactly(:status, :body, :request)
        expect(error.response[:request].keys).to contain_exactly(:method, :url_path)
        expect(error.response[:request][:url_path]).to eq('/server-error')
        expect(error.message).to eq('the server responded with status 500 for POST /server-error')
        expect(error.message).not_to include(query_marker)
        expect(error.inspect).not_to include(query_marker)
        expect(error.inspect).not_to include(auth_marker)
        expect(error.inspect).not_to include(request_body_marker)
      end

      expect(log.string).to include('error: Faraday::ServerError (status 500)')
      expect(log.string).to include(response_body_marker)
      expect(log.string).not_to include(response_header_marker)
      expect(log.string).not_to include(query_marker)
      expect(log.string).not_to include(auth_marker)
      expect(log.string).not_to include(request_body_marker)
    end

    context 'when the error policy selects the response headers instead' do
      let(:policy) { { request: %i[method], error: %i[response_headers] } }

      it 'discloses headers and omits the body' do
        expect { perform('/server-error') }.to raise_error(Faraday::ServerError) do |error|
          expect(error.response_status).to eq(500)
          expect(error.response_headers['X-Reason']).to eq(response_header_marker)
          expect(error.response_body).to be_nil
          expect(error.response.keys).to contain_exactly(:status, :headers, :request)
        end

        expect(log.string).to include(response_header_marker)
        expect(log.string).not_to include(response_body_marker)
      end
    end
  end

  describe 'an error raised by a request middleware' do
    context 'when the error policy discloses nothing' do
      let(:policy) { { request: %i[method url_path], error: [] } }

      it 'logs only the error class while the raised object stays consumable' do
        expect { perform('/boom') }.to raise_error(Faraday::ConnectionFailed) do |error|
          # The message the application raised stays consumable; the shared
          # log is what the policy narrows.
          expect(error.message).to eq(middleware_marker)
          expect(error.response_status).to be_nil
        end

        expect(log.string).to include('error: Faraday::ConnectionFailed')
        expect(log.string).not_to include(middleware_marker)
        expect(log.string).not_to include(query_marker)
        expect(log.string).not_to include(auth_marker)
      end
    end

    context 'when the error policy selects the message' do
      let(:policy) { { request: %i[method], error: %i[message] } }

      it 'logs the message' do
        expect { perform('/boom') }.to raise_error(Faraday::ConnectionFailed)
        expect(log.string).to include(middleware_marker)
      end
    end
  end

  describe 'query strings' do
    context 'when only the path is selected' do
      it 'does not log or attach the query string' do
        perform('/success')
        expect(log.string).not_to include(query_marker)

        expect { perform('/server-error') }.to raise_error(Faraday::ServerError) do |error|
          expect(error.response[:request][:url_path]).to eq('/server-error')
          expect(error.message).not_to include(query_marker)
        end
      end
    end

    context 'when params are selected' do
      let(:policy) { { request: %i[method params], error: [] } }

      it 'discloses the decoded params without the path' do
        expect { perform('/server-error') }.to raise_error(Faraday::ServerError) do |error|
          expect(error.response[:request]).to eq(method: :post, params: { 'token' => query_marker })
          expect(error.message).to eq('the server responded with status 500 for POST')
        end
      end
    end
  end

  describe 'request attribute selection' do
    let(:policy) { { request: %i[method url url_path params headers body], error: [] } }

    it 'attaches every selected attribute to the error' do
      expect { perform('/server-error') }.to raise_error(Faraday::ServerError) do |error|
        request = error.response[:request]
        expect(request[:method]).to eq(:post)
        expect(request[:url].to_s).to include("token=#{query_marker}")
        expect(request[:url_path]).to eq('/server-error')
        expect(request[:params]).to eq('token' => query_marker)
        expect(request[:headers]['Authorization']).to eq("Bearer #{auth_marker}")
        expect(request[:body]).to eq(request_body_marker)
      end

      expect(log.string).to include("request: POST http:/server-error?token=#{query_marker}")
      expect(log.string).to include(auth_marker)
      expect(log.string).to include(request_body_marker)
      expect(log.string).not_to include(response_body_marker)
    end
  end

  describe 'a request-level policy' do
    it 'overrides the connection policy for that request only' do
      response = conn.post("/success?token=#{query_marker}") do |req|
        req.options.disclosure = { request: %i[method], error: [] }
      end
      expect(response.status).to eq(200)
      expect(log.string).to include("request: POST\n")
      expect(log.string).not_to include('/success')

      log.truncate(0)
      log.rewind
      perform('/success')

      expect(log.string).to include('request: POST /success')
      expect(response.body).to eq(response_body_marker)
    end
  end

  describe 'a middleware failing with a response env' do
    let(:policy) { { request: %i[method url_path], error: %i[response_body] } }
    let(:middleware_class) do
      Class.new(Faraday::Middleware) do
        def on_complete(env)
          raise Faraday::ParsingError.new(RuntimeError.new('bad body'), env) if env.status == 200
        end
      end
    end
    let(:conn) do
      Faraday.new(disclosure: policy) do |b|
        b.use middleware_class
        b.adapter :test do |stub|
          stub.post('/success') { [200, { 'X-Reply' => response_header_marker }, response_body_marker] }
        end
      end
    end

    it 'projects the response attached to the error without touching the returned one' do
      expect { perform('/success') }.to raise_error(Faraday::ParsingError) do |error|
        expect(error.response_status).to eq(200)
        expect(error.response_body).to eq(response_body_marker)
        expect(error.response_headers).to eq({})
        expect(error.response.env.request_headers).to be_nil
        expect(error.response.env.url.to_s).to eq('/success')
        expect(error.response.env.request_body).to be_nil
      end
    end
  end

  describe 'a formatter with the historical signature' do
    let(:policy) { { request: %i[method], error: [] } }
    let(:formatter_class) do
      Class.new(Faraday::Logging::Formatter) do
        def request(_env)
          info('custom request')
        end

        def response(_env)
          info('custom response')
        end

        def exception(exc)
          info("custom exception: #{exc.class}")
        end
      end
    end
    let(:conn) do
      Faraday.new(disclosure: policy) do |b|
        b.response :logger, logger, { errors: true, formatter: formatter_class }
        b.adapter :test do |stub|
          stub.post('/boom') { raise Faraday::ConnectionFailed, middleware_marker }
        end
      end
    end

    it 'still receives a single argument' do
      expect { perform('/boom') }.to raise_error(Faraday::ConnectionFailed)

      expect(log.string).to include('custom exception: Faraday::ConnectionFailed')
      expect(log.string).not_to include(middleware_marker)
    end
  end

  describe 'compatibility' do
    context 'without a policy' do
      let(:conn) do
        Faraday.new do |b|
          b.response :logger, logger, logger_options
          b.adapter :test do |stub|
            stub.post('/success') { [200, {}, response_body_marker] }
          end
        end
      end

      it 'keeps the historical request line' do
        perform('/success')

        expect(log.string).to include("request: POST http:/success?token=#{query_marker}")
        expect(log.string).to include(auth_marker) if logger_options[:headers]
      end
    end

    context 'with a strict policy' do
      let(:policy) { true }
      let(:conn) do
        Faraday.new(disclosure: policy) do |b|
          b.response :logger, logger, logger_options
          b.response :raise_error
          b.adapter :test do |stub|
            stub.post('/server-error') { [500, { 'X-Reason' => response_header_marker }, response_body_marker] }
          end
        end
      end

      it 'discloses nothing beyond the class and status' do
        expect { perform('/server-error') }.to raise_error(Faraday::ServerError) do |error|
          expect(error.response_status).to eq(500)
          expect(error.response_body).to be_nil
          expect(error.response).to eq(status: 500)
        end

        expect(log.string).to include('error: Faraday::ServerError (status 500)')
        expect(log.string).not_to include(response_body_marker)
        expect(log.string).not_to include(query_marker)
      end
    end

    context 'with include_request: false and a policy' do
      let(:policy) { { request: %i[method url_path], error: %i[response_body] } }
      let(:conn) do
        Faraday.new(disclosure: policy) do |b|
          b.response :raise_error, include_request: false
          b.adapter :test do |stub|
            stub.post('/server-error') { [500, {}, response_body_marker] }
          end
        end
      end

      it 'keeps the stricter legacy marker authoritative' do
        expect { perform('/server-error') }.to raise_error(Faraday::ServerError) do |error|
          expect(error.response_status).to eq(500)
          expect(error.response_body).to eq(response_body_marker)
          expect(error.response[:request]).to be_nil
          expect(error.message).to include('method and url are not available')
        end
      end
    end
  end
end
