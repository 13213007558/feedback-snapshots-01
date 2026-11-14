# frozen_string_literal: true

require_relative 'helper'
require 'base64'

separate_testing do
  require_relative '../lib/rack/message_signatures/verifier'
  require_relative '../lib/rack/mock_request'
  require_relative '../lib/rack/lint'
end

describe Rack::MessageSignatures::Verifier do
  BODY = '{"hello":"world"}'
  KEY = "app-shared-secret"
  NOW = 1_618_884_500

  # Independent RFC 9421 Appendix B.2.5 test vector. The shared secret and
  # signature value are taken from the RFC, while the signature base is
  # assembled here without using the middleware.
  RFC_KEY = "uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ=="
  RFC_SIGNATURE_INPUT = 'sig-b25=("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"'
  RFC_SIGNATURE = "sig-b25=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:"

  class OneShotStream
    def initialize(data)
      @io = StringIO.new(data.b)
      @reads = 0
      @exhausted = false
    end

    attr_reader :reads

    def read(*arguments)
      raise IOError, "stream consumed more than once" if @exhausted
      @reads += 1
      result = @io.read(*arguments)
      @exhausted = true if result.nil?
      result
    end

    def gets
      @io.gets
    end

    def each(&block)
      @io.each(&block)
    end

    def close
      @io.close
    end
  end

  def b64(value)
    [value].pack("m0")
  end

  def hmac(key, base)
    b64(OpenSSL::HMAC.digest("SHA256", key, base))
  end

  def signature_base(lines, params)
    lines.join("\n") + "\n\"@signature-params\": " + params
  end

  def digest_line(body = BODY, algorithm = "sha-256")
    digest = algorithm == "sha-256" ? Digest::SHA256.digest(body) : Digest::SHA512.digest(body)
    "\"content-digest\": #{algorithm}=:#{b64(digest)}:"
  end

  def component_line(component)
    case component
    when "@method" then '"@method": POST'
    when "@authority" then '"@authority": example.com'
    when "@path" then '"@path": /foo'
    when "@query" then '"@query": ?param=Value&Pet=dog'
    when "@scheme" then '"@scheme": http'
    when "@target-uri" then '"@target-uri": http://example.com/foo?param=Value&Pet=dog'
    when "content-digest" then digest_line
    when "content-type" then '"content-type": application/json'
    else raise "unsupported test component #{component}"
    end
  end

  def signature(components, params, key: KEY)
    base = signature_base(components.map { |component| component_line(component) }, params)
    hmac(key, base)
  end

  def params(components, extra = "")
    '("' + components.join('" "') + '")' + extra
  end

  def env_for(uri = "http://example.com/foo?param=Value&Pet=dog", body: BODY, headers: {})
    Rack::MockRequest.env_for(uri,
      method: "POST",
      input: body,
      "HTTP_HOST" => URI.parse(uri).host,
      "CONTENT_TYPE" => "application/json",
      **headers)
  end

  def signed_env(components:, params:, signature_value: signature(components, params),
                 uri: "http://example.com/foo?param=Value&Pet=dog", body: BODY, headers: {})
    env = env_for(uri, body: body, headers: headers)
    env["HTTP_CONTENT_DIGEST"] ||= "sha-256=:#{b64(Digest::SHA256.digest(body))}:"
    env["HTTP_SIGNATURE_INPUT"] = "sig1=" + params
    env["HTTP_SIGNATURE"] = "sig1=:#{signature_value}:"
    env
  end

  def env_with_signed_fields(field_lines, params, components: nil, headers: {}, body: BODY)
    env = env_for(body: body, headers: headers)
    env["HTTP_CONTENT_DIGEST"] ||= "sha-256=:#{b64(Digest::SHA256.digest(body))}:"
    base = signature_base(field_lines, params)
    env["HTTP_SIGNATURE_INPUT"] = "sig1=" + params
    env["HTTP_SIGNATURE"] = "sig1=:#{hmac(KEY, base)}:"
    env
  end

  def make_app(required_components: %w[@method @authority @path @query content-digest], now: NOW, **options)
    @calls = 0
    app = lambda do |env|
      @calls += 1
      [200, { "content-type" => "text/plain" }, ["ok"]]
    end
    Rack::MessageSignatures::Verifier.new(app,
      key: KEY,
      required_components: required_components,
      clock: -> { now },
      clock_skew: 0,
      max_age: 300,
      **options)
  end

  def default_components
    %w[@method @authority @path @query content-digest]
  end

  def default_params(extra = ';created=1618884500;keyid="app-key"')
    params(default_components, extra)
  end

  it "verifies the independent RFC 9421 HMAC-SHA256 vector" do
    base = [
      '"date": Tue, 20 Apr 2021 02:07:55 GMT',
      '"@authority": example.com',
      '"content-type": application/json',
    ].join("\n") + "\n" + '"@signature-params": ("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"'
    hmac(Base64.strict_decode64(RFC_KEY), base).must_equal "pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8="

    @calls = 0
    app = lambda do |_env|
      @calls += 1
      [200, { "content-type" => "text/plain" }, ["ok"]]
    end
    verifier = Rack::MessageSignatures::Verifier.new(app,
      key: Base64.strict_decode64(RFC_KEY),
      required_components: %w[date @authority content-type],
      clock: -> { 1_618_884_473 },
      clock_skew: 0,
      max_age: 60)

    env = env_for("http://example.com/foo", body: BODY)
    env["HTTP_DATE"] = "Tue, 20 Apr 2021 02:07:55 GMT"
    env["CONTENT_TYPE"] = "application/json"
    env["HTTP_SIGNATURE_INPUT"] = RFC_SIGNATURE_INPUT
    env["HTTP_SIGNATURE"] = RFC_SIGNATURE

    response = verifier.call(env)
    response[0].must_equal 200
    response[2].must_equal ["ok"]
    @calls.must_equal 1
    env[Rack::MessageSignatures::Verifier::ENV_VERIFIED]["key_id"].must_equal "test-shared-secret"
  end

  it "verifies a hard-coded vector generated outside the middleware" do
    verifier = make_app

    # Signature base (generated with OpenSSL outside this middleware):
    # "@method": POST
    # "@authority": example.com
    # "@path": /foo
    # "@query": ?param=Value&Pet=dog
    # "content-digest": sha-256=:k6I5cakU5erL8KjSUVTNownDwccvu5kU1Hxg88toFYg=:
    # "@signature-params": ("@method" "@authority" "@path" "@query" "content-digest");created=1618884500;keyid="app-key"
    env = signed_env(components: default_components, params: default_params,
      signature_value: "evl2MD+6E1Yj8QfkHQ0c+wlhmZNA2OAxi6F4tPM0+wA=")
    response = verifier.call(env)
    response[0].must_equal 200
    @calls.must_equal 1
  end

  it "accepts an independently constructed signature and exposes verified metadata" do
    verifier = make_app
    env = signed_env(components: default_components, params: default_params)

    response = verifier.call(env)
    response[0].must_equal 200
    response[2].close if response[2].respond_to?(:close)
    @calls.must_equal 1

    info = env[Rack::MessageSignatures::Verifier::ENV_VERIFIED]
    info["label"].must_equal "sig1"
    info["components"].must_equal default_components
    info["created"].must_equal 1_618_884_500
  end

  it "rejects when a required component is absent from Signature-Input" do
    components = %w[@method @authority @path @query]
    signature_value = signature(components, params(components, ';created=1618884500;keyid="app-key"'))
    verifier = make_app
    env = signed_env(components: components, params: params(components, ';created=1618884500;keyid="app-key"'), signature_value: signature_value)

    response = verifier.call(env)
    response[0].must_equal 401
    @calls.must_equal 0
  end

  it "rejects a signature that covers only a subset of the configured components" do
    components = %w[@method @authority @path @query content-digest]
    signature_value = signature(components, params(components, ';created=1618884500;keyid="app-key"'))
    verifier = make_app(required_components: %w[@method @authority @path @query content-digest @scheme])
    env = signed_env(components: components, params: params(components, ';created=1618884500;keyid="app-key"'), signature_value: signature_value)

    response = verifier.call(env)
    response[0].must_equal 401
    @calls.must_equal 0
  end

  it "rejects a tampered body when Content-Digest is covered" do
    verifier = make_app
    env = signed_env(components: default_components, params: default_params)
    env["rack.input"] = StringIO.new('{"hello":"tampered"}')

    response = verifier.call(env)
    response[0].must_equal 401
    @calls.must_equal 0
  end

  it "verifies a one-shot request stream and rewinds it for the application" do
    received = nil
    @calls = 0
    app = lambda do |env|
      @calls += 1
      received = env["rack.input"].read
      [200, { "content-type" => "text/plain" }, ["ok"]]
    end
    verifier = Rack::MessageSignatures::Verifier.new(app,
      key: KEY,
      required_components: default_components,
      clock: -> { NOW },
      clock_skew: 0,
      max_age: 300)

    env = signed_env(components: default_components, params: default_params)
    stream = OneShotStream.new(BODY)
    env["rack.input"] = stream
    env.delete("CONTENT_LENGTH")

    response = verifier.call(env)
    response[0].must_equal 200
    @calls.must_equal 1
    received.must_equal BODY
    env["rack.input"].must_be_kind_of StringIO
    stream.reads.must_be :>=, 1
  end

  it "keeps the buffered stream readable after the application returns" do
    @calls = 0
    app = lambda do |env|
      @calls += 1
      [200, { "content-type" => "text/plain" }, [env["rack.input"].read]]
    end
    verifier = Rack::MessageSignatures::Verifier.new(app,
      key: KEY,
      required_components: default_components,
      clock: -> { NOW },
      clock_skew: 0,
      max_age: 300)

    env = signed_env(components: default_components, params: default_params)
    env["rack.input"] = OneShotStream.new(BODY)
    env.delete("CONTENT_LENGTH")

    response = verifier.call(env)
    response[0].must_equal 200
    body = +""
    response[2].each { |chunk| body << chunk }
    body.must_equal BODY
  end

  it "rejects when Content-Digest is present but not covered" do
    components = %w[@method @authority @path @query]
    verifier = make_app(required_components: components)
    env = signed_env(components: components, params: params(components, ';created=1618884500;keyid="app-key"'))
    env["HTTP_CONTENT_DIGEST"] = "sha-256=:#{b64(Digest::SHA256.digest(BODY))}:"

    response = verifier.call(env)
    response[0].must_equal 401
    @calls.must_equal 0
  end

  it "rejects a signature that does not bind the method" do
    tampered = env_for
    tampered[Rack::REQUEST_METHOD] = "PUT"
    tampered["HTTP_SIGNATURE_INPUT"] = "sig1=" + default_params
    tampered["HTTP_SIGNATURE"] = "sig1=:#{signature(default_components, default_params)}:"

    response = make_app.call(tampered)
    response[0].must_equal 401
    @calls.must_equal 0
  end

  it "rejects a signature that does not bind the target" do
    tampered = env_for("http://example.com/other?param=Value&Pet=dog")
    tampered["HTTP_SIGNATURE_INPUT"] = "sig1=" + default_params
    tampered["HTTP_SIGNATURE"] = "sig1=:#{signature(default_components, default_params)}:"

    response = make_app.call(tampered)
    response[0].must_equal 401
    @calls.must_equal 0
  end

  it "accepts a signature that also binds the authority and scheme" do
    components = %w[@method @scheme @authority @path @query content-digest]
    extra = ';created=1618884500;keyid="app-key"'
    verifier = make_app(required_components: components)
    env = signed_env(components: components, params: params(components, extra))

    response = verifier.call(env)
    response[0].must_equal 200
    @calls.must_equal 1
  end

  it "does not let Forwarded headers change the signed authority" do
    components = %w[@method @authority @path @query content-digest]
    extra = ';created=1618884500;keyid="app-key"'
    env = signed_env(components: components, params: params(components, extra))
    env["HTTP_FORWARDED"] = "host=evil.example;proto=https"
    env["HTTP_X_FORWARDED_HOST"] = "evil.example"

    response = make_app.call(env)
    response[0].must_equal 200
    @calls.must_equal 1
  end

  it "derives @target-uri from the Rack env and rejects a different forwarded target" do
    components = %w[@method @target-uri content-digest]
    extra = ';created=1618884500;keyid="app-key"'
    verifier = make_app(required_components: components)
    env = signed_env(components: components, params: params(components, extra))
    env["HTTP_FORWARDED"] = "host=evil.example;proto=https"

    response = verifier.call(env)
    response[0].must_equal 200
    @calls.must_equal 1

    env = signed_env(components: components, params: params(components, extra))
    env["HTTP_FORWARDED"] = "host=evil.example;proto=https"
    env["HTTP_HOST"] = "evil.example"

    response = make_app(required_components: components).call(env)
    response[0].must_equal 401
  end

  it "rejects signatures outside the policy time window" do
    components = default_components
    old_params = params(components, ';created=1618884000;keyid="app-key"')
    verifier = make_app
    env = signed_env(components: components, params: old_params)

    response = verifier.call(env)
    response[0].must_equal 401
    @calls.must_equal 0
  end

  it "rejects signatures created in the future" do
    components = default_components
    future_params = params(components, ';created=1618885000;keyid="app-key"')
    verifier = make_app
    env = signed_env(components: components, params: future_params)

    response = verifier.call(env)
    response[0].must_equal 401
    @calls.must_equal 0
  end

  it "rejects signatures whose expires time has passed" do
    components = default_components
    expired_params = params(components, ';created=1618884400;expires=1618884401;keyid="app-key"')
    verifier = make_app
    env = signed_env(components: components, params: expired_params)

    response = verifier.call(env)
    response[0].must_equal 401
    @calls.must_equal 0
  end

  it "accepts a signature with a future expires value" do
    components = default_components
    live_params = params(components, ';created=1618884500;expires=1618884600;keyid="app-key"')
    verifier = make_app
    env = signed_env(components: components, params: live_params)

    response = verifier.call(env)
    response[0].must_equal 200
    @calls.must_equal 1
  end

  it "rejects an unsupported signature algorithm" do
    components = default_components
    params = params(components, ';created=1618884500;keyid="app-key";alg="rsa-pss-sha512"')
    verifier = make_app
    env = signed_env(components: components, params: params)

    response = verifier.call(env)
    response[0].must_equal 401
    @calls.must_equal 0
  end

  it "rejects a different key identifier when one is configured" do
    components = default_components
    params = params(components, ';created=1618884500;keyid="other-key"')
    verifier = make_app(key_id: "app-key")
    env = signed_env(components: components, params: params)

    response = verifier.call(env)
    response[0].must_equal 401
    @calls.must_equal 0
  end

  it "rejects multiple signatures without an explicit label" do
    components = default_components
    params = params(components, ';created=1618884500;keyid="app-key"')
    env = signed_env(components: components, params: params)
    env["HTTP_SIGNATURE_INPUT"] = "sig1=#{params}, sig2=#{params}"
    env["HTTP_SIGNATURE"] = "sig1=:#{signature(components, params)}:, sig2=:#{signature(components, params)}:"

    response = make_app.call(env)
    response[0].must_equal 400
    @calls.must_equal 0
  end

  it "selects an explicit label among multiple signatures" do
    components = default_components
    params = params(components, ';created=1618884500;keyid="app-key"')
    env = signed_env(components: components, params: params)
    env["HTTP_SIGNATURE_INPUT"] = "other=#{params}, sig1=#{params}"
    env["HTTP_SIGNATURE"] = "other=:#{signature(components, params)}:, sig1=:#{signature(components, params)}:"

    response = make_app(label: "sig1").call(env)
    response[0].must_equal 200
    @calls.must_equal 1
  end

  it "rejects a mismatched Signature-Input and Signature label set" do
    components = default_components
    params = params(components, ';created=1618884500;keyid="app-key"')
    env = signed_env(components: components, params: params)
    env["HTTP_SIGNATURE"] = "other=:#{signature(components, params)}:"

    response = make_app.call(env)
    response[0].must_equal 401
    @calls.must_equal 0
  end

  it "rejects a malformed Signature-Input field" do
    env = env_for
    env["HTTP_SIGNATURE_INPUT"] = 'sig1=("date" "@authority"'
    env["HTTP_SIGNATURE"] = "sig1=:#{b64("x")}:"

    response = make_app.call(env)
    response[0].must_equal 401
    @calls.must_equal 0
  end

  it "rejects duplicate labels in Signature-Input" do
    components = default_components
    params = params(components, ';created=1618884500;keyid="app-key"')
    env = signed_env(components: components, params: params)
    env["HTTP_SIGNATURE_INPUT"] = "sig1=#{params}, sig1=#{params}"

    response = make_app.call(env)
    response[0].must_equal 401
    @calls.must_equal 0
  end

  it "rejects unsupported component parameters" do
    components = default_components
    tampered_params = '("@method" "@authority" "@path" "@query" "content-digest";tr);created=1618884500;keyid="app-key"'
    env = signed_env(components: components, params: tampered_params)

    response = make_app.call(env)
    response[0].must_equal 401
    @calls.must_equal 0
  end

  it "rejects unsupported derived components" do
    components = default_components
    tampered_params = '("@method" "@authority" "@path" "@query" "@status");created=1618884500;keyid="app-key"'
    env = signed_env(components: components, params: tampered_params)

    response = make_app.call(env)
    response[0].must_equal 401
    @calls.must_equal 0
  end

  it "rejects requests where a required field is missing" do
    components = default_components
    params = params(components, ';created=1618884500;keyid="app-key"')
    env = signed_env(components: components, params: params)
    env.delete("HTTP_HOST")
    env.delete("SERVER_NAME")

    response = make_app.call(env)
    response[0].must_equal 400
    @calls.must_equal 0
  end

  it "rejects an ambiguous field that Rack has already combined" do
    components = default_components
    params = params(components, ';created=1618884500;keyid="app-key"')
    env = signed_env(components: components, params: params)
    env["HTTP_CONTENT_DIGEST"] = "sha-256=:#{b64(Digest::SHA256.digest(BODY))}:, sha-256=:#{b64(Digest::SHA256.digest(BODY))}:"
    env["HTTP_SIGNATURE_INPUT"] = "sig1=" + params + ", sig1=" + params

    response = make_app.call(env)
    response[0].must_equal 401
    @calls.must_equal 0
  end

  it "rejects a header value containing a newline instead of guessing" do
    components = default_components + %w[content-type]
    params = params(components, ';created=1618884500;keyid="app-key"')
    env = signed_env(components: components, params: params)
    env["CONTENT_TYPE"] = "application/json\napplication/json"

    response = make_app.call(env)
    response[0].must_equal 400
    @calls.must_equal 0
  end

  it "rejects an array-valued host rather than joining it" do
    components = default_components
    params = params(components, ';created=1618884500;keyid="app-key"')
    env = signed_env(components: components, params: params)
    env["HTTP_HOST"] = ["example.com", "evil.example"]

    response = make_app.call(env)
    response[0].must_equal 400
    @calls.must_equal 0
  end

  it "rejects a request body that exceeds the configured limit" do
    components = default_components
    verifier = make_app(max_body_bytes: 4)
    env = signed_env(components: components, params: default_params)

    response = verifier.call(env)
    response[0].must_equal 413
    @calls.must_equal 0
  end

  it "rejects an unsupported Content-Digest algorithm" do
    body = BODY
    line = '"content-digest": sha=:' + b64(Digest::SHA256.digest(body)) + ':'
    components = default_components
    params = params(components, ';created=1618884500;keyid="app-key"')
    base = signature_base([
      component_line("@method"), component_line("@authority"), component_line("@path"),
      component_line("@query"), line.to_s
    ], params)
    env = signed_env(components: components, params: params, signature_value: hmac(KEY, base))
    env["HTTP_CONTENT_DIGEST"] = "sha=:#{b64(Digest::SHA256.digest(body))}:"

    response = make_app.call(env)
    response[0].must_equal 401
    @calls.must_equal 0
  end

  it "accepts sha-512 Content-Digest when enabled by policy" do
    components = default_components
    params = params(components, ';created=1618884500;keyid="app-key"')
    base = signature_base([
      component_line("@method"), component_line("@authority"), component_line("@path"),
      component_line("@query"), digest_line(BODY, "sha-512")
    ], params)
    env = signed_env(components: components, params: params, signature_value: hmac(KEY, base))
    env["HTTP_CONTENT_DIGEST"] = "sha-512=:#{b64(Digest::SHA512.digest(BODY))}:"

    response = make_app(digest_algorithms: %w[sha-256 sha-512]).call(env)
    response[0].must_equal 200
    @calls.must_equal 1
  end

  it "rejects a request with no Signature-Input" do
    env = env_for

    response = make_app.call(env)
    response[0].must_equal 401
    @calls.must_equal 0
  end

  it "does not call the app when verification fails" do
    components = default_components
    env = signed_env(components: components, params: default_params)
    env["HTTP_SIGNATURE"] = "sig1=:#{b64("short")}:"

    response = make_app.call(env)
    response[0].must_equal 401
    @calls.must_equal 0
  end

  it "rejects a signature not tied to the configured key" do
    components = default_components
    params = params(components, ';created=1618884500;keyid="app-key"')
    env = signed_env(components: components, params: params, signature_value: signature(components, params, key: "wrong-secret"))

    response = make_app.call(env)
    response[0].must_equal 401
    @calls.must_equal 0
  end

  it "supports a key resolver" do
    keys = { "app-key" => KEY }
    verifier = make_app(key: ->(keyid) { keys[keyid] })
    env = signed_env(components: default_components, params: default_params)

    response = verifier.call(env)
    response[0].must_equal 200
    @calls.must_equal 1
  end

  it "supports a hash of keys" do
    verifier = make_app(key: { "app-key" => KEY })
    env = signed_env(components: default_components, params: default_params)

    response = verifier.call(env)
    response[0].must_equal 200
    @calls.must_equal 1
  end

  it "rejects a signature from an unknown key identifier" do
    verifier = make_app(key: { "other" => KEY })
    env = signed_env(components: default_components, params: default_params)

    response = verifier.call(env)
    response[0].must_equal 401
    @calls.must_equal 0
  end

  it "rejects a non-HMAC signature field value" do
    env = signed_env(components: default_components, params: default_params)
    env["HTTP_SIGNATURE"] = "sig1=abc"

    response = make_app.call(env)
    response[0].must_equal 401
    @calls.must_equal 0
  end

  it "requires a created timestamp by default" do
    components = default_components
    params = params(components, ';keyid="app-key"')
    env = signed_env(components: components, params: params)

    response = make_app.call(env)
    response[0].must_equal 401
    @calls.must_equal 0
  end

  it "can require expires and keyid explicitly" do
    components = default_components
    params = params(components, ';created=1618884500;expires=1618884600')
    env = signed_env(components: components, params: params)

    response = make_app(require_expires: true, require_keyid: true).call(env)
    response[0].must_equal 401
    @calls.must_equal 0
  end

  it "rejects an invalid constructor configuration" do
    app = lambda { |_env| [200, {}, []] }

    lambda {
      Rack::MessageSignatures::Verifier.new(app, key: KEY, required_components: [])
    }.must_raise ArgumentError

    lambda {
      Rack::MessageSignatures::Verifier.new(app, key: KEY, required_components: %w[@status])
    }.must_raise ArgumentError

    lambda {
      Rack::MessageSignatures::Verifier.new(app, key: KEY, required_components: %w[@method], algorithms: %w[rsa-v1_5-sha256])
    }.must_raise ArgumentError

    lambda {
      Rack::MessageSignatures::Verifier.new(app, key: KEY, required_components: %w[@method], max_age: -1)
    }.must_raise ArgumentError
  end


  it "binds the default policy to method, target, and content digest" do
    @calls = 0
    app = lambda { |_env| @calls += 1; [200, {}, []] }
    verifier = Rack::MessageSignatures::Verifier.new(app,
      key: KEY,
      clock: -> { NOW },
      clock_skew: 0)

    env = signed_env(components: default_components, params: default_params)
    response = verifier.call(env)
    response[0].must_equal 200
    @calls.must_equal 1
  end

  it "rejects a default-policy request without a Content-Digest binding" do
    components = %w[@method @authority @path @query]
    @calls = 0
    app = lambda { |_env| @calls += 1; [200, {}, []] }
    verifier = Rack::MessageSignatures::Verifier.new(app,
      key: KEY,
      clock: -> { NOW },
      clock_skew: 0)

    env = signed_env(components: components, params: params(components, ';created=1618884500;keyid="app-key"'))
    response = verifier.call(env)
    response[0].must_equal 401
    @calls.must_equal 0
  end

  it "rejects a covered field that is absent from the request" do
    components = default_components + %w[digest]
    extra = ';created=1618884500;keyid="app-key"'
    base = signature_base((default_components + %w[digest]).map { |component|
      component == "digest" ? '"digest": sha-256=:AAAA:' : component_line(component)
    }, params(components, extra))
    space_env = signed_env(components: default_components, params: params(components, extra))
    space_env["HTTP_SIGNATURE_INPUT"] = "sig1=" + params(components, extra)
    space_env["HTTP_SIGNATURE"] = "sig1=:#{hmac(KEY, base)}:"
    space_env.delete("HTTP_DIGEST")

    response = make_app(required_components: %w[@method @authority @path @query content-digest]).call(space_env)
    response[0].must_equal 401
    @calls.must_equal 0
  end

  it "rejects @request-target at configuration time because Rack cannot preserve it" do
    lambda {
      Rack::MessageSignatures::Verifier.new(lambda { |_env| [200, {}, []] },
        key: KEY,
        required_components: %w[@method @request-target])
    }.must_raise ArgumentError
  end

  it "rejects @request-target from a signature at verification time" do
    components = %w[@method @authority @path @query content-digest]
    extra = ';created=1618884500;keyid="app-key"'
    env = signed_env(components: components, params: params(components, extra))
    env["HTTP_SIGNATURE_INPUT"] = 'sig1=("@method" "@request-target");created=1618884500;keyid="app-key"'

    response = make_app.call(env)
    response[0].must_equal 401
    @calls.must_equal 0
  end

  it "rejects a tampered body from a one-shot stream without calling the app" do
    verifier = make_app
    env = signed_env(components: default_components, params: default_params)
    env["rack.input"] = OneShotStream.new('{"hello":"tampered"}')

    response = verifier.call(env)
    response[0].must_equal 401
    @calls.must_equal 0
  end

  it "canonicalizes optional whitespace in the received Signature-Input" do
    spaced_params = '("@method"  "@authority" "@path" "@query" "content-digest" );created=1618884500;keyid="app-key"'
    verifier = make_app

    env = signed_env(components: default_components, params: spaced_params,
      signature_value: "evl2MD+6E1Yj8QfkHQ0c+wlhmZNA2OAxi6F4tPM0+wA=")
    response = verifier.call(env)
    response[0].must_equal 200
    @calls.must_equal 1
  end

  it "produces a Rack::Lint-compliant request and response" do
    @calls = 0
    inner = lambda do |env|
      @calls += 1
      body = env["rack.input"].read
      [200, { "content-type" => "text/plain" }, [body]]
    end
    app = Rack::Lint.new(Rack::MessageSignatures::Verifier.new(Rack::Lint.new(inner),
      key: KEY,
      required_components: default_components,
      clock: -> { NOW },
      clock_skew: 0))

    env = signed_env(components: default_components, params: default_params)
    response = app.call(env)
    response[0].must_equal 200
    chunks = []
    response[2].each { |chunk| chunks << chunk }
    chunks.join.must_equal BODY
    @calls.must_equal 1
  end

  it "rejects Cookie as a covered component because Rack cannot preserve its lines" do
    components = default_components + %w[cookie]
    extra = ';created=1618884500;keyid="app-key"'
    params = params(components, extra)
    lines = components.map do |component|
      component == "cookie" ? '"cookie": a=1; b=2' : component_line(component)
    end
    env = env_with_signed_fields(lines, params, headers: { "HTTP_COOKIE" => "a=1; b=2" })

    response = make_app(required_components: %w[@method @authority @path @query content-digest]).call(env)
    response[0].must_equal 401
    @calls.must_equal 0
  end

  it "rejects Cookie at configuration time" do
    lambda {
      Rack::MessageSignatures::Verifier.new(lambda { |_env| [200, {}, []] },
        key: KEY,
        required_components: %w[@method cookie])
    }.must_raise ArgumentError
  end

  it "does not intercept exceptions raised by the application" do
    app = lambda { |_env| raise Rack::MessageSignatures::Verifier::Rejection.new(418, "app error") }
    verifier = Rack::MessageSignatures::Verifier.new(app,
      key: KEY,
      required_components: default_components,
      clock: -> { NOW },
      clock_skew: 0)

    lambda {
      verifier.call(signed_env(components: default_components, params: default_params))
    }.must_raise Rack::MessageSignatures::Verifier::Rejection
  end

  it "binds a covered Content-Length to a verified body digest" do
    components = default_components + %w[content-length]
    extra = ';created=1618884500;keyid="app-key"'
    params = params(components, extra)
    lines = components.map do |component|
      component == "content-length" ? '"content-length": ' + BODY.bytesize.to_s : component_line(component)
    end
    env = env_with_signed_fields(lines, params)

    response = make_app(required_components: components).call(env)
    response[0].must_equal 200
    @calls.must_equal 1
  end

  it "rejects a covered Content-Length without a body digest binding" do
    components = %w[@method @authority @path @query content-length]
    extra = ';created=1618884500;keyid="app-key"'
    params = params(components, extra)
    lines = components.map do |component|
      component == "content-length" ? '"content-length": ' + BODY.bytesize.to_s : component_line(component)
    end
    env = env_with_signed_fields(lines, params)
    env.delete("HTTP_CONTENT_DIGEST")

    response = make_app(required_components: components).call(env)
    response[0].must_equal 401
    @calls.must_equal 0
  end

  it "rejects a covered Date field that is absent from the Rack env" do
    components = %w[@method @authority @path @query content-digest date]
    extra = ';created=1618884500;keyid="app-key"'
    params = params(components, extra)
    lines = components.map do |component|
      component == "date" ? '"date": Tue, 20 Apr 2021 02:07:55 GMT' : component_line(component)
    end
    env = env_with_signed_fields(lines, params)

    response = make_app(required_components: components).call(env)
    response[0].must_equal 401
    @calls.must_equal 0
  end

  it "accepts a covered Date field when present" do
    components = %w[@method @authority @path @query content-digest date]
    extra = ';created=1618884500;keyid="app-key"'
    params = params(components, extra)
    lines = components.map do |component|
      component == "date" ? '"date": Tue, 20 Apr 2021 02:07:55 GMT' : component_line(component)
    end
    env = env_with_signed_fields(lines, params, headers: { "HTTP_DATE" => "Tue, 20 Apr 2021 02:07:55 GMT" })

    response = make_app(required_components: components).call(env)
    response[0].must_equal 200
    @calls.must_equal 1
  end

  it "reports failures through on_failure without invoking the app" do
    reasons = []
    verifier = make_app(on_failure: ->(_env, reason, status) { reasons << [reason, status] })
    env = signed_env(components: default_components, params: default_params)
    env["HTTP_SIGNATURE"] = "sig1=:#{b64("bad")}:"

    response = verifier.call(env)
    response[0].must_equal 401
    response[1]["cache-control"].must_equal "no-store"
    @calls.must_equal 0
    reasons.size.must_equal 1
    reasons.first[1].must_equal 401
  end
end
