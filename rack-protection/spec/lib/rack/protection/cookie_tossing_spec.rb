# frozen_string_literal: true

require 'rack/mock'
require 'timeout'

RSpec.describe Rack::Protection::CookieTossing do
  it_behaves_like 'any rack application'

  class CookieTossingCloseableBody
    def initialize(*chunks)
      @chunks = chunks
      @closed = false
    end

    def each(&block)
      @chunks.each(&block)
    end

    def close
      @closed = true
    end

    def closed?
      @closed
    end
  end

  def call_app(app, host:, path:, cookie: nil)
    env = Rack::MockRequest.env_for("http://#{host}#{path}")
    env['HTTP_COOKIE'] = cookie if cookie
    app.call(env)
  end

  def response_cookies(response)
    Array(response[1]['set-cookie'])
  end

  def cookie_values(response, attribute)
    response_cookies(response).map { |cookie| cookie[/; #{attribute}=([^;]*)/, 1] }
  end

  def cookie_names(response)
    response_cookies(response).map { |cookie| cookie.split('=', 2).first }
  end

  def pausable_app(pause_path)
    entered = Queue.new
    release = Queue.new
    app = lambda do |env|
      if env['PATH_INFO'] == pause_path
        entered << true
        release.pop
      end
      [200, { 'content-type' => 'text/plain' }, ['ok']]
    end
    [app, entered, release]
  end

  def pop_with_timeout(queue, seconds = 5)
    Timeout.timeout(seconds) { queue.pop }
  end

  context 'with default reaction' do
    before(:each) do
      mock_app do
        use Rack::Protection::CookieTossing
        run DummyApp
      end
    end

    it 'accepts requests with a single session cookie' do
      get '/', {}, 'HTTP_COOKIE' => 'rack.session=SESSION_TOKEN'
      expect(last_response).to be_ok
    end

    it 'denies requests with duplicate session cookies' do
      get '/', {}, 'HTTP_COOKIE' => 'rack.session=EVIL_SESSION_TOKEN; rack.session=SESSION_TOKEN'
      expect(last_response).not_to be_ok
    end

    it 'denies requests with sneaky encoded session cookies' do
      get '/', {}, 'HTTP_COOKIE' => 'rack.session=EVIL_SESSION_TOKEN; rack.%73ession=SESSION_TOKEN'
      expect(last_response).not_to be_ok
    end

    it 'adds the correct Set-Cookie header' do
      get '/some/path', {}, 'HTTP_COOKIE' => 'rack.%73ession=EVIL_SESSION_TOKEN; rack.session=EVIL_SESSION_TOKEN; rack.session=SESSION_TOKEN'

      # Rack no longer URI encodes the % in the cookie in Rack 3.1+
      # https://github.com/sinatra/sinatra/issues/2017
      cookie_key = if Rack::RELEASE < "3.1"
        "rack.%2573ession"
      else
        "rack.%73ession"
      end

      expected_header = <<-END.chomp.split("\n")
#{cookie_key}=; domain=example.org; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT
#{cookie_key}=; domain=example.org; path=/some; expires=Thu, 01 Jan 1970 00:00:00 GMT
#{cookie_key}=; domain=example.org; path=/some/path; expires=Thu, 01 Jan 1970 00:00:00 GMT
rack.session=; domain=example.org; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT
rack.session=; domain=example.org; path=/some; expires=Thu, 01 Jan 1970 00:00:00 GMT
rack.session=; domain=example.org; path=/some/path; expires=Thu, 01 Jan 1970 00:00:00 GMT
      END
      expect(last_response.headers['Set-Cookie']).to eq(expected_header)
    end
  end

  context 'with redirect reaction' do
    before(:each) do
      mock_app do
        use Rack::Protection::CookieTossing, reaction: :redirect
        run DummyApp
      end
    end

    it 'redirects requests with duplicate session cookies' do
      get '/', {}, 'HTTP_COOKIE' => 'rack.session=EVIL_SESSION_TOKEN; rack.session=SESSION_TOKEN'
      expect(last_response).to be_redirect
      expect(last_response.location).to eq('/')
    end

    it 'redirects requests with sneaky encoded session cookies' do
      get '/path', {}, 'HTTP_COOKIE' => 'rack.%73ession=EVIL_SESSION_TOKEN; rack.session=SESSION_TOKEN'
      expect(last_response).to be_redirect
      expect(last_response.location).to eq('/path')
    end
  end

  context 'with custom session key' do
    it 'denies requests with duplicate session cookies' do
      mock_app do
        use Rack::Protection::CookieTossing, session_key: '_session'
        run DummyApp
      end

      get '/', {}, 'HTTP_COOKIE' => '_session=EVIL_SESSION_TOKEN; _session=SESSION_TOKEN'
      expect(last_response).not_to be_ok
    end
  end

  context 'when one middleware instance handles multiple requests' do
    it 'does not carry a rejection from one request into the next' do
      app = described_class.new(DummyApp)

      attack = call_app(app, host: 'a.example.org', path: '/a/secret',
                             cookie: 'rack.session=EVIL; rack.session=GOOD')
      normal = call_app(app, host: 'b.example.org', path: '/b/other',
                             cookie: 'theme=light; theme=dark')

      expect(attack[0]).to eq(403)
      expect(normal[0]).to eq(200)
      expect(response_cookies(normal)).to be_empty
    end

    it 'does not carry a redirect from one request into the next' do
      app = described_class.new(DummyApp, reaction: :redirect)

      attack = call_app(app, host: 'a.example.org', path: '/a',
                             cookie: 'rack.session=EVIL; rack.session=GOOD')
      normal = call_app(app, host: 'b.example.org', path: '/b',
                             cookie: 'rack.session=GOOD')

      expect(attack[0]).to eq(302)
      expect(cookie_names(attack).uniq).to eq(['rack.session'])
      expect(cookie_values(attack, 'domain').uniq).to eq(['a.example.org'])
      expect(normal[0]).to eq(200)
      expect(response_cookies(normal)).to be_empty
    end

    it 'deletes only names, domains, and paths belonging to the rejected request' do
      app = described_class.new(DummyApp)

      attack = call_app(app, host: 'a.example.org', path: '/a/secret',
                             cookie: 'rack.session=EVIL; rack.session=GOOD')

      expect(cookie_names(attack).uniq).to eq(['rack.session'])
      expect(cookie_values(attack, 'domain').uniq).to eq(['a.example.org'])
      expect(cookie_values(attack, 'path')).to eq(['/', '/a', '/a/secret'])
    end

    it 'does not treat repeated ordinary cookies as a session cookie attack' do
      app = described_class.new(DummyApp)

      response = call_app(app, host: 'a.example.org', path: '/',
                               cookie: 'theme=light; theme=dark; lang=en; lang=fr')

      expect(response[0]).to eq(200)
      expect(response_cookies(response)).to be_empty
    end

    it 'keeps detection and cleanup isolated when responses interleave' do
      pausable, entered, release = pausable_app('/a/deep')
      app = described_class.new(pausable, reaction: :report)

      attack = Thread.new do
        call_app(app, host: 'a.example.org', path: '/a/deep',
                       cookie: 'rack.session=EVIL; rack.session=GOOD')
      end

      begin
        expect(pop_with_timeout(entered)).to be(true)

        normal = call_app(app, host: 'b.example.org', path: '/b/other',
                               cookie: 'rack.%73ession=EVIL2')

        expect(normal[0]).to eq(200)
        expect(cookie_names(normal).uniq).to eq(['rack.%73ession'])
        expect(cookie_values(normal, 'domain').uniq).to eq(['b.example.org'])
        expect(cookie_values(normal, 'path')).to eq(['/', '/b', '/b/other'])
      ensure
        release << true
      end

      attack_response = attack.value

      expect(attack_response[0]).to eq(200)
      expect(cookie_names(attack_response).uniq).to eq(['rack.session'])
      expect(cookie_values(attack_response, 'domain').uniq).to eq(['a.example.org'])
      expect(cookie_values(attack_response, 'path')).to eq(['/', '/a', '/a/deep'])
    end

    it 'does not add cleanup cookies to a request that was already accepted' do
      pausable, entered, release = pausable_app('/normal')
      app = described_class.new(pausable)

      accepted = Thread.new do
        call_app(app, host: 'normal.example.org', path: '/normal',
                       cookie: 'theme=light; theme=dark')
      end

      begin
        expect(pop_with_timeout(entered)).to be(true)

        attack = call_app(app, host: 'evil.example.org', path: '/evil',
                               cookie: 'rack.session=EVIL; rack.session=GOOD')

        expect(attack[0]).to eq(403)
        expect(cookie_values(attack, 'domain').uniq).to eq(['evil.example.org'])
      ensure
        release << true
      end

      normal = accepted.value

      expect(normal[0]).to eq(200)
      expect(response_cookies(normal)).to be_empty
    end

    it 'isolates cleanup when a rejected request is paused mid-response' do
      cleanup_entered = Queue.new
      cleanup_release = Queue.new

      klass = Class.new(described_class) do
        define_method(:remove_bad_cookies) do |request, response|
          if request.path == '/a'
            cleanup_entered << true
            cleanup_release.pop
          end
          super(request, response)
        end
      end

      app = klass.new(DummyApp)

      attack = Thread.new do
        call_app(app, host: 'a.example.org', path: '/a',
                       cookie: 'rack.session=EVIL; rack.session=GOOD')
      end

      begin
        expect(pop_with_timeout(cleanup_entered)).to be(true)

        normal = call_app(app, host: 'b.example.org', path: '/b',
                               cookie: 'theme=light; theme=dark')

        expect(normal[0]).to eq(200)
        expect(response_cookies(normal)).to be_empty
      ensure
        cleanup_release << true
      end

      attack_response = attack.value

      expect(attack_response[0]).to eq(403)
      expect(cookie_names(attack_response).uniq).to eq(['rack.session'])
      expect(cookie_values(attack_response, 'domain').uniq).to eq(['a.example.org'])
      expect(cookie_values(attack_response, 'path')).to eq(['/', '/a'])
    end

    it 'leaves the original application body intact and closable' do
      body = CookieTossingCloseableBody.new('ok')
      app = described_class.new(->(_env) { [200, { 'content-type' => 'text/plain' }, body] },
                                reaction: :report)

      response = call_app(app, host: 'a.example.org', path: '/',
                               cookie: 'rack.session=EVIL; rack.session=GOOD')

      expect(response[2]).to be(body)
      expect(body).not_to be_closed

      response[2].close
      expect(body).to be_closed
    end
  end
end
