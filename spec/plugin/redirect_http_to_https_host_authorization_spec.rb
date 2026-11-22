require_relative "../spec_helper"

describe "redirect_http_to_https plugin with host_authorization" do
  before do
    app(:bare) do
      plugin :host_authorization, %w'www.example.com app.example.com', :check_forwarded=>true
      plugin :redirect_http_to_https, :host=>'www.example.com'

      route do |r|
        r.get 'healthz' do
          'ok'
        end

        check_host_authorization!
        r.redirect_http_to_https

        r.get 'business' do
          'business'
        end

        'root'
      end
    end
  end

  it "redirects requests for registered hosts to the configured deployment host" do
    s, h, b = req('/business', 'HTTP_HOST'=>'www.example.com')
    s.must_equal 301
    h[RodaResponseHeaders::LOCATION].must_equal 'https://www.example.com/business'
    b.must_be_empty

    s, h, = req('/business', 'HTTP_HOST'=>'app.example.com', 'QUERY_STRING'=>'foo=bar')
    s.must_equal 301
    h[RodaResponseHeaders::LOCATION].must_equal 'https://www.example.com/business?foo=bar'
  end

  it "redirects internal proxy requests using the configured host, not proxy headers" do
    s, h, = req('/business', 'HTTP_HOST'=>'10.0.0.1:8080', 'HTTP_X_FORWARDED_HOST'=>'www.example.com')
    s.must_equal 301
    h[RodaResponseHeaders::LOCATION].must_equal 'https://www.example.com/business'

    s, h, = req('/business', 'HTTP_HOST'=>'internal.proxy:8080', 'HTTP_X_FORWARDED_HOST'=>'attacker.example.net, app.example.com')
    s.must_equal 301
    h[RodaResponseHeaders::LOCATION].must_equal 'https://www.example.com/business'
  end

  it "rejects plain requests without recognized site ownership instead of redirecting" do
    s, h, b = req('/business', 'HTTP_HOST'=>'evil.example.net')
    s.must_equal 403
    h[RodaResponseHeaders::LOCATION].must_be_nil
    b.must_be_empty

    status('/business', 'HTTP_HOST'=>'evil.example.net', 'HTTP_X_FORWARDED_HOST'=>'also-evil.example.net').must_equal 403
    status('/business', 'HTTP_HOST'=>'internal.proxy:8080', 'HTTP_X_FORWARDED_HOST'=>'www.example.com, attacker.example.net').must_equal 403
  end

  it "does not redirect HTTPS requests for authorized hosts, avoiding redirect loops" do
    s, h, b = req('/business', 'HTTP_HOST'=>'www.example.com', 'HTTPS'=>'on')
    s.must_equal 200
    h[RodaResponseHeaders::LOCATION].must_be_nil
    b.must_equal ['business']

    body('/business', 'HTTP_HOST'=>'app.example.com', 'HTTPS'=>'on').must_equal 'business'
    body('/', 'HTTP_HOST'=>'www.example.com', 'HTTPS'=>'on').must_equal 'root'
  end

  it "uses 307 for non-GET redirects to the configured host" do
    s, h, = req('/business', 'HTTP_HOST'=>'app.example.com', 'REQUEST_METHOD'=>'POST')
    s.must_equal 307
    h[RodaResponseHeaders::LOCATION].must_equal 'https://www.example.com/business'
  end

  it "serves the reserved business path without affecting host policy on other routes" do
    body('/healthz').must_equal 'ok'
    body('/healthz', 'HTTP_HOST'=>'evil.example.net').must_equal 'ok'
    body('/healthz', 'HTTP_HOST'=>'10.0.0.1:8080').must_equal 'ok'

    status('/', 'HTTP_HOST'=>'evil.example.net').must_equal 403
    s, h, = req('/', 'HTTP_HOST'=>'app.example.com')
    s.must_equal 301
    h[RodaResponseHeaders::LOCATION].must_equal 'https://www.example.com/'
  end
end
