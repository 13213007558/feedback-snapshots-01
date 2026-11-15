# frozen_string_literal: true
require "spec_helper"
require "rack/mock"

module SecureHeaders
  describe NonceCacheMiddleware do
    CSP_HEADER = ContentSecurityPolicyConfig::HEADER_NAME
    SECRET = "test-secret-do-not-use-in-prod".freeze

    # In-memory Rack app rendering an HTML page with a CSP nonce. The page
    # content is versioned; in :pinned mode the app declares the content
    # version as its nonce token and ETag before rendering, exactly like an
    # app that knows the digest of what it is about to render.
    def build_app(content_version: "v1", use_nonce: true, extra_headers: {}, set_validators: true)
      lambda do |env|
        request = Rack::Request.new(env)
        token = Digest::SHA256.hexdigest("page-template:#{content_version}")
        env[NonceCacheMiddleware::TOKEN_KEY] = token if use_nonce

        nonce = SecureHeaders.content_security_policy_script_nonce(request) if use_nonce
        body = %(<html><head><script nonce="#{nonce}">console.log("#{content_version}")</script></head><body>Hello #{content_version}</body></html>)

        headers = { "content-type" => "text/html" }.merge(extra_headers)
        headers["etag"] = %("#{token}") if set_validators
        [200, headers, [body]]
      end
    end

    def build_stack(app, **options)
      NonceCacheMiddleware.new(
        Middleware.new(
          Rack::ConditionalGet.new(
            Rack::ETag.new(app))),
        **options)
    end

    def body_nonce(response)
      response.body[/<script nonce="([^"]+)"/, 1]
    end

    def header_nonce(response, header = CSP_HEADER)
      response.headers[header][/'nonce-([^']+)'/, 1]
    end

    before(:each) do
      reset_config
      Configuration.default do |config|
        config.csp = {
          default_src: %w('self'),
          script_src: %w('self'),
        }
      end
    end

    context "configuration validation" do
      it "rejects an unknown mode" do
        expect { NonceCacheMiddleware.new(build_app, mode: :sometimes) }.to raise_error(ArgumentError, /mode/)
      end

      it "requires a secret in :pinned mode" do
        expect { NonceCacheMiddleware.new(build_app, mode: :pinned) }.to raise_error(ArgumentError, /secret/)
      end
    end

    context "no_store mode (default): nonce'd pages must never be reused" do
      let(:stack) { build_stack(build_app(extra_headers: { "cache-control" => "public, max-age=3600" })) }
      let(:request) { Rack::MockRequest.new(stack) }

      it "first read: strips validators and forces private, no-store even when upstream set caching headers" do
        response = request.get("https://example.org/")

        expect(response.status).to eq(200)
        expect(response.headers["Cache-Control"]).to eq("private, no-store")
        expect(response.headers["ETag"]).to be_nil
        expect(header_nonce(response)).to eq(body_nonce(response))
      end

      it "HEAD: applies the same restrictions as GET" do
        response = request.head("https://example.org/")

        expect(response.headers["Cache-Control"]).to eq("private, no-store")
        expect(response.headers["ETag"]).to be_nil
        expect(header_nonce(response)).not_to be_nil
      end

      it "generates a fresh random nonce per request" do
        first = request.get("https://example.org/")
        second = request.get("https://example.org/")
        expect(header_nonce(first)).not_to eq(header_nonce(second))
      end

      it "leaves responses without a nonce untouched" do
        stack = build_stack(build_app(use_nonce: false, extra_headers: { "cache-control" => "public, max-age=60" }))
        response = Rack::MockRequest.new(stack).get("https://example.org/")

        expect(response.headers["Cache-Control"]).to eq("public, max-age=60")
        expect(response.headers["ETag"]).not_to be_nil
      end

      it "raises when a 304 would pair a fresh nonce with a cached body" do
        not_modified_app = lambda do |env|
          SecureHeaders.content_security_policy_script_nonce(Rack::Request.new(env))
          [304, {}, []]
        end
        stack = NonceCacheMiddleware.new(Middleware.new(not_modified_app))

        expect { Rack::MockRequest.new(stack).get("https://example.org/") }.to raise_error(NonceCacheError, /304/)
      end

      it "raises when the CSP header contains a nonce secure_headers did not generate" do
        foreign_app = lambda do |_env|
          [200, { CSP_HEADER => "default-src 'self'; script-src 'nonce-foreign'" }, ["<html></html>"]]
        end
        stack = NonceCacheMiddleware.new(Middleware.new(foreign_app))

        # SecureHeaders::Middleware overwrites the upstream CSP, so simulate
        # an opt-out request where the upstream header survives.
        allow(SecureHeaders).to receive(:header_hash_for).and_return({})
        expect { Rack::MockRequest.new(stack).get("https://example.org/") }.to raise_error(NonceCacheError, /did not generate/)
      end

      it "raises when the CSP header nonce differs from the request nonce" do
        mismatched_app = lambda do |env|
          SecureHeaders.content_security_policy_script_nonce(Rack::Request.new(env))
          [200, { CSP_HEADER => "default-src 'self'; script-src 'nonce-other'" }, ["<html></html>"]]
        end
        allow(SecureHeaders).to receive(:header_hash_for).and_return({})
        stack = NonceCacheMiddleware.new(Middleware.new(mismatched_app))

        expect { Rack::MockRequest.new(stack).get("https://example.org/") }.to raise_error(NonceCacheError, /differs/)
      end
    end

    context "pinned mode: deterministic nonce bound to the body token" do
      let(:stack) do
        build_stack(
          build_app(extra_headers: { "cache-control" => "public, max-age=60, must-revalidate" }),
          mode: :pinned,
          secret: SECRET,
          enforce_token_etag_match: true)
      end
      let(:request) { Rack::MockRequest.new(stack) }

      it "round trip: first read, conditional hit, and read after a config change all keep header/body nonces matched" do
        # 1. First read: full response. The client stores body + ETag.
        first = request.get("https://example.org/")
        expect(first.status).to eq(200)
        expect(first.headers["Cache-Control"]).to eq("public, max-age=60, must-revalidate")
        etag = first.headers["ETag"]
        expect(etag).not_to be_nil
        cached_body_nonce = body_nonce(first)
        expect(header_nonce(first)).to eq(cached_body_nonce)

        # 2. Conditional hit: the client revalidates with If-None-Match and
        #    receives a 304. The client keeps the ORIGINAL cached body, so
        #    the CSP header on the 304 must carry that body's nonce.
        second = request.get("https://example.org/", "HTTP_IF_NONE_MATCH" => etag)
        expect(second.status).to eq(304)
        expect(second.body).to eq("")
        expect(header_nonce(second)).to eq(cached_body_nonce)

        # 3. HEAD: headers must match what a GET would produce for the same
        #    body.
        head = request.head("https://example.org/")
        expect(head.status).to eq(200)
        expect(header_nonce(head)).to eq(cached_body_nonce)

        # 4. Config change (e.g. a new script-src host is deployed): the CSP
        #    directives change but the body does not, so the ETag is
        #    unchanged and the derived nonce still matches the cached body.
        reset_config
        Configuration.default do |config|
          config.csp = {
            default_src: %w('self'),
            script_src: %w('self' https://cdn.example.com),
          }
        end
        after_change = request.get("https://example.org/", "HTTP_IF_NONE_MATCH" => etag)
        expect(after_change.status).to eq(304)
        expect(after_change.headers[CSP_HEADER]).to include("cdn.example.com")
        expect(header_nonce(after_change)).to eq(cached_body_nonce)
      end

      it "derives a new nonce when the body changes, and the client sees a matching pair" do
        first = request.get("https://example.org/")
        old_etag = first.headers["ETag"]

        changed_stack = build_stack(
          build_app(content_version: "v2"),
          mode: :pinned,
          secret: SECRET,
          enforce_token_etag_match: true)
        changed = Rack::MockRequest.new(changed_stack).get("https://example.org/", "HTTP_IF_NONE_MATCH" => old_etag)

        expect(changed.status).to eq(200)
        expect(changed.headers["ETag"]).not_to eq(old_etag)
        expect(header_nonce(changed)).not_to eq(header_nonce(first))
        expect(header_nonce(changed)).to eq(body_nonce(changed))
      end

      it "accepts a token supplied via the :token callback" do
        callback_app = lambda do |env|
          nonce = SecureHeaders.content_security_policy_script_nonce(Rack::Request.new(env))
          [200, { "etag" => %("static-token") }, [%(<script nonce="#{nonce}"></script>)]]
        end
        stack = build_stack(callback_app, mode: :pinned, secret: SECRET, token: ->(_req) { "static-token" })

        response = Rack::MockRequest.new(stack).get("https://example.org/")
        expect(header_nonce(response)).to eq(body_nonce(response))
        expect(header_nonce(response)).to eq(NonceCacheMiddleware.derive_nonce(SECRET, "static-token"))
      end

      it "raises at render time when the nonce is used before a token was provided" do
        tokenless_app = lambda do |env|
          SecureHeaders.content_security_policy_script_nonce(Rack::Request.new(env))
          [200, {}, ["<html></html>"]]
        end
        stack = build_stack(tokenless_app, mode: :pinned, secret: SECRET)

        expect { Rack::MockRequest.new(stack).get("https://example.org/") }.to raise_error(NonceCacheError, /TOKEN_KEY|token/)
      end

      it "raises when the response has no ETag" do
        stack = build_stack(build_app(set_validators: false), mode: :pinned, secret: SECRET)
        expect { Rack::MockRequest.new(stack).get("https://example.org/") }.to raise_error(NonceCacheError, /ETag/)
      end

      it "raises on a weak ETag" do
        weak_app = build_app
        weak_stack_app = lambda do |env|
          status, headers, body = weak_app.call(env)
          headers["etag"] = %(W/"#{env[NonceCacheMiddleware::TOKEN_KEY]}")
          [status, headers, body]
        end
        stack = build_stack(weak_stack_app, mode: :pinned, secret: SECRET)
        expect { Rack::MockRequest.new(stack).get("https://example.org/") }.to raise_error(NonceCacheError, /weak/i)
      end

      it "raises when Cache-Control: no-store contradicts pinned mode" do
        stack = build_stack(build_app(extra_headers: { "cache-control" => "no-store" }), mode: :pinned, secret: SECRET)
        expect { Rack::MockRequest.new(stack).get("https://example.org/") }.to raise_error(NonceCacheError, /no-store/)
      end

      it "raises when the token does not match the ETag and enforcement is on" do
        lying_app = lambda do |env|
          env[NonceCacheMiddleware::TOKEN_KEY] = "token-a"
          nonce = SecureHeaders.content_security_policy_script_nonce(Rack::Request.new(env))
          [200, { "etag" => %("different-etag") }, [%(<script nonce="#{nonce}"></script>)]]
        end
        stack = build_stack(lying_app, mode: :pinned, secret: SECRET, enforce_token_etag_match: true)
        expect { Rack::MockRequest.new(stack).get("https://example.org/") }.to raise_error(NonceCacheError, /does not match/)
      end

      it "leaves responses without a nonce untouched" do
        stack = build_stack(build_app(use_nonce: false, set_validators: false), mode: :pinned, secret: SECRET)
        response = Rack::MockRequest.new(stack).get("https://example.org/")
        expect(response.status).to eq(200)
        # the weak ETag comes from Rack::ETag below us, passed through untouched
        expect(response.headers["ETag"]).to start_with("W/")
      end
    end
  end
end
