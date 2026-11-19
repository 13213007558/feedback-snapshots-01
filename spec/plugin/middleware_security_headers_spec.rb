require_relative "../spec_helper"

# Outermost rack middleware that owns the default security headers for the
# whole stack.  It must fill in defaults only when neither the Roda
# middleware nor the downstream application set the header explicitly.
class SecurityHeadersTestMiddleware
  DEFAULT_SECURITY_HEADERS = {
    'x-content-type-options' => 'nosniff',
    'x-frame-options' => 'SAMEORIGIN',
    'referrer-policy' => 'strict-origin-when-cross-origin'
  }.freeze

  def initialize(app)
    @app = app
  end

  def call(env)
    status, headers, body = @app.call(env)
    DEFAULT_SECURITY_HEADERS.each do |name, value|
      headers[name] = value unless headers.key?(name)
    end
    [status, headers, body]
  end
end

describe "security response headers with Roda app used as rack middleware" do
  before do
    mid = app(:bare) do
      plugin :middleware, :next_if_not_found=>true
      plugin :error_handler do |_error|
        response['x-roda-path'] = 'error'
        response['referrer-policy'] = 'no-referrer'
        'error!'
      end

      route do |r|
        r.is 'halt' do
          response['x-roda-path'] = 'halted'
          response['x-frame-options'] = 'DENY'
          response.write 'halted'
          r.halt
        end

        r.is 'error' do
          raise 'middleware failure'
        end
      end
    end

    app(:bare) do
      use SecurityHeadersTestMiddleware
      use mid

      route do |r|
        r.is 'downstream' do
          response['x-roda-path'] = 'downstream'
          response['x-frame-options'] = 'DENY'
          'downstream'
        end

        r.is 'plain' do
          'plain'
        end
      end
    end
  end

  # Assert the final rack response contains the given security header exactly
  # once (regardless of key casing) with the expected value.  Catches missing
  # defaults, headers written twice, and overridden explicit values.
  def assert_security_header(headers, name, value)
    entries = headers.select{|k, _| k.downcase == name}
    entries.size.must_equal 1
    entries.values.first.must_equal value
  end

  it "keeps explicit values and fills remaining defaults when the middleware halts early" do
    status('/halt').must_equal 200
    body('/halt').must_equal 'halted'
    headers = req('/halt')[1]
    header('x-roda-path', '/halt').must_equal 'halted'
    assert_security_header headers, 'x-frame-options', 'DENY'
    assert_security_header headers, 'x-content-type-options', 'nosniff'
    assert_security_header headers, 'referrer-policy', 'strict-origin-when-cross-origin'
  end

  it "applies default security headers to error handler responses" do
    status('/error').must_equal 500
    body('/error').must_equal 'error!'
    headers = req('/error')[1]
    header('x-roda-path', '/error').must_equal 'error'
    assert_security_header headers, 'referrer-policy', 'no-referrer'
    assert_security_header headers, 'x-frame-options', 'SAMEORIGIN'
    assert_security_header headers, 'x-content-type-options', 'nosniff'
  end

  it "does not override explicit downstream security headers when forwarding" do
    status('/downstream').must_equal 200
    body('/downstream').must_equal 'downstream'
    headers = req('/downstream')[1]
    header('x-roda-path', '/downstream').must_equal 'downstream'
    assert_security_header headers, 'x-frame-options', 'DENY'
    assert_security_header headers, 'x-content-type-options', 'nosniff'
    assert_security_header headers, 'referrer-policy', 'strict-origin-when-cross-origin'
  end

  it "applies all default security headers when no layer sets them" do
    status('/plain').must_equal 200
    headers = req('/plain')[1]
    assert_security_header headers, 'x-frame-options', 'SAMEORIGIN'
    assert_security_header headers, 'x-content-type-options', 'nosniff'
    assert_security_header headers, 'referrer-policy', 'strict-origin-when-cross-origin'
  end

  it "applies default security headers to unmatched requests forwarded through the stack" do
    status('/unknown').must_equal 404
    headers = req('/unknown')[1]
    assert_security_header headers, 'x-frame-options', 'SAMEORIGIN'
    assert_security_header headers, 'x-content-type-options', 'nosniff'
    assert_security_header headers, 'referrer-policy', 'strict-origin-when-cross-origin'
  end
end
