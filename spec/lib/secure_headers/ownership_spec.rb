# frozen_string_literal: true
require "spec_helper"

module SecureHeaders
  describe "configuration ownership and isolation" do
    before(:each) do
      reset_config
    end

    let(:request) { Rack::Request.new("HTTP_X_FORWARDED_SSL" => "on") }

    describe "registered configuration immutability" do
      it "deep freezes the default config including nested CSP arrays, cookies and endpoints" do
        SecureHeaders::Configuration.default do |config|
          config.csp = { default_src: %w('self'), script_src: %w('self') }
          config.cookies = {
            httponly: { only: %w(_session) },
            secure: true,
            samesite: { lax: { except: %w(_guest) } },
          }
          config.reporting_endpoints = { "csp" => "https://example.com/reports" }
        end

        default_config = Configuration.send(:default_config)
        expect(Ownership.deep_frozen?(default_config)).to eq(true)
        expect(Ownership.deep_frozen?(default_config.csp)).to eq(true)
        expect(Ownership.deep_frozen?(default_config.cookies)).to eq(true)
        expect(Ownership.deep_frozen?(default_config.reporting_endpoints)).to eq(true)
        expect(default_config.csp.directive_value(:script_src)).to be_frozen
        expect(default_config.cookies[:samesite][:lax][:except]).to be_frozen
      end

      it "does not let callers mutate registered CSP source arrays after registration" do
        shared_sources = %w('self' https:)
        Configuration.default do |config|
          config.csp = { default_src: shared_sources, script_src: %w('self') }
        end

        shared_sources << "evil.example"

        registered = Configuration.send(:default_config).csp.directive_value(:default_src)
        expect(registered).to eq(%w('self' https:))
      end

      it "does not alias a CSP config object passed directly at registration" do
        external = ContentSecurityPolicyConfig.new(default_src: %w('self'), script_src: %w('self'))
        Configuration.default { |config| config.csp = external }

        external.update_directive(:script_src, %w(evil.example))

        registered = Configuration.send(:default_config).csp
        expect(registered).not_to be(external)
        expect(registered.directive_value(:script_src)).to eq(%w('self'))
      end

      it "deep copies cookie only/except conditions away from the caller hash" do
        only_cookies = %w(_session)
        caller_cookies = { httponly: { only: only_cookies }, secure: true, samesite: OPT_OUT }
        Configuration.default { |config| config.cookies = caller_cookies }

        only_cookies << "injected"
        caller_cookies[:httponly][:only] << "also-injected"

        registered = Configuration.send(:default_config).cookies
        expect(registered).not_to be(caller_cookies)
        expect(registered[:httponly][:only]).to eq(%w(_session))
      end

      it "deep copies reporting endpoints away from the caller hash" do
        endpoints = { "csp" => "https://example.com/reports" }
        Configuration.default do |config|
          config.csp = { default_src: %w('self'), script_src: %w('self') }
          config.reporting_endpoints = endpoints
        end

        endpoints["csp"] = "https://evil.example/reports"
        endpoints["extra"] = "https://evil.example/extra"

        registered = Configuration.send(:default_config).reporting_endpoints
        expect(registered).to eq("csp" => "https://example.com/reports")
      end

      it "raises FrozenError when the registered config is mutated in place" do
        Configuration.default do |config|
          config.csp = { default_src: %w('self'), script_src: %w('self') }
          config.cookies = { secure: true }
        end

        default_config = Configuration.send(:default_config)
        expect { default_config.csp.update_directive(:script_src, %w(evil)) }.to raise_error(FrozenError)
        expect { default_config.cookies[:secure] = false }.to raise_error(FrozenError)
        expect { default_config.reporting_endpoints = {} }.to raise_error(FrozenError)
      end
    end

    describe "OPT_OUT identity" do
      it "keeps the OPT_OUT singleton through registration and dup" do
        Configuration.default do |config|
          config.csp = OPT_OUT
          config.csp_report_only = OPT_OUT
          config.cookies = OPT_OUT
          config.reporting_endpoints = OPT_OUT
        end

        default_config = Configuration.send(:default_config)
        expect(default_config.csp).to be(OPT_OUT)
        expect(default_config.csp_report_only).to be(OPT_OUT)
        expect(default_config.cookies).to be(OPT_OUT)
        expect(default_config.reporting_endpoints).to be(OPT_OUT)

        copy = default_config.dup
        expect(copy.csp).to be(OPT_OUT)
        expect(copy.csp_report_only).to be(OPT_OUT)
        expect(copy.cookies).to be(OPT_OUT)
        expect(copy.reporting_endpoints).to be(OPT_OUT)
      end

      it "never freezes the OPT_OUT singleton" do
        Configuration.default { |config| config.csp = OPT_OUT }
        expect(OPT_OUT).not_to be_frozen
      end
    end

    describe "per-request copies" do
      it "gives each request an independent writable copy and leaves the default untouched" do
        Configuration.default do |config|
          config.csp = { default_src: %w('self'), script_src: %w('self') }
          config.cookies = { httponly: { only: %w(_session) }, secure: true, samesite: OPT_OUT }
        end

        first = Rack::Request.new({})
        second = Rack::Request.new({})
        SecureHeaders.append_content_security_policy_directives(first, script_src: %w(first.example))
        SecureHeaders.append_content_security_policy_directives(second, script_src: %w(second.example))

        first_config = first.env[SECURE_HEADERS_CONFIG]
        second_config = second.env[SECURE_HEADERS_CONFIG]
        expect(first_config).not_to be(second_config)
        expect(first_config).not_to be_frozen
        expect(second_config).not_to be_frozen
        expect(first_config.csp).not_to be(Configuration.send(:default_config).csp)
        expect(first_config.cookies).not_to be(Configuration.send(:default_config).cookies)

        first_config.cookies[:httponly][:only] << "first-only"
        first_config.csp.update_directive(:img_src, %w(first-img.example))

        expect(second_config.cookies[:httponly][:only]).to eq(%w(_session))
        expect(second_config.csp.directive_value(:img_src)).to be_nil

        default_config = Configuration.send(:default_config)
        expect(default_config.csp.directive_value(:script_src)).to eq(%w('self'))
        expect(default_config.csp.directive_value(:img_src)).to be_nil
        expect(default_config.cookies[:httponly][:only]).to eq(%w(_session))
      end

      it "does not freeze or alias objects the caller still holds" do
        Configuration.default do |config|
          config.csp = { default_src: %w('self'), script_src: %w('self') }
        end
        caller_sources = %w(caller.example)

        SecureHeaders.override_content_security_policy_directives(request, script_src: caller_sources)
        request_config = request.env[SECURE_HEADERS_CONFIG]

        expect(request_config.csp.directive_value(:script_src)).not_to be(caller_sources)
        expect { caller_sources << "still-writable" }.not_to raise_error
        expect(request_config.csp.directive_value(:script_src)).to eq(%w(caller.example))
      end

      it "isolates interleaved requests with reused nested configuration" do
        shared_sources = %w(shared.cdn)
        shared_only = %w(_session)
        Configuration.default do |config|
          config.csp = { default_src: %w('self'), script_src: shared_sources }
          config.cookies = { httponly: { only: shared_only }, secure: true, samesite: OPT_OUT }
        end
        Configuration.override(:api) do |config|
          config.csp.merge!(script_src: shared_sources + %w(api.cdn))
        end

        first = Rack::Request.new({})
        second = Rack::Request.new({})
        SecureHeaders.append_content_security_policy_directives(first, script_src: %w(first.example))
        SecureHeaders.use_secure_headers_override(second, :api)
        SecureHeaders.append_content_security_policy_directives(first, img_src: %w(first-img.example))

        first_headers = SecureHeaders.header_hash_for(first)
        second_headers = SecureHeaders.header_hash_for(second)

        expect(first_headers[ContentSecurityPolicyConfig::HEADER_NAME]).to include("first.example")
        expect(first_headers[ContentSecurityPolicyConfig::HEADER_NAME]).to include("first-img.example")
        expect(first_headers[ContentSecurityPolicyConfig::HEADER_NAME]).not_to include("api.cdn")
        expect(second_headers[ContentSecurityPolicyConfig::HEADER_NAME]).to include("api.cdn")
        expect(second_headers[ContentSecurityPolicyConfig::HEADER_NAME]).not_to include("first.example")
      end
    end

    describe "generated header cache" do
      def request_config
        request.env[SECURE_HEADERS_CONFIG]
      end

      it "memoizes headers and rebuilds after a legitimate modification" do
        Configuration.default do |config|
          config.csp = { default_src: %w('self'), script_src: %w('self') }
        end
        SecureHeaders.override_x_frame_options(request, XFrameOptions::SAMEORIGIN)

        first_headers = SecureHeaders.header_hash_for(request)
        cached = request_config.instance_variable_get(:@generated_headers_cache)
        expect(cached).to eq(first_headers)
        expect(request_config.instance_variable_get(:@generated_headers_cache)).to be(cached)

        SecureHeaders.override_x_frame_options(request, XFrameOptions::DENY)
        expect(request_config.instance_variable_get(:@generated_headers_cache)).to be_nil

        second_headers = SecureHeaders.header_hash_for(request)
        expect(second_headers[XFrameOptions::HEADER_NAME]).to eq(XFrameOptions::DENY)
        expect(request_config.instance_variable_get(:@generated_headers_cache)).not_to be(cached)
      end

      it "invalidates the cache when the CSP is mutated directly" do
        Configuration.default do |config|
          config.csp = { default_src: %w('self'), script_src: %w('self') }
        end
        SecureHeaders.override_x_frame_options(request, XFrameOptions::SAMEORIGIN)
        SecureHeaders.header_hash_for(request)

        request_config.csp.merge!(img_src: %w(images.example))
        expect(request_config.instance_variable_get(:@generated_headers_cache)).to be_nil

        headers = SecureHeaders.header_hash_for(request)
        expect(headers[ContentSecurityPolicyConfig::HEADER_NAME]).to include("img-src images.example")
      end

      it "does not store a per-request config when nothing is modified" do
        Configuration.default
        SecureHeaders.header_hash_for(request)
        expect(request.env[SECURE_HEADERS_CONFIG]).to be_nil
      end
    end

    describe "middleware cookie handling" do
      let(:cookie_app) { lambda { |env| [200, env.merge("Set-Cookie" => "foo=bar"), []] } }
      let(:middleware) { Middleware.new(cookie_app) }

      it "suppresses Secure over http without mutating the registered cookie config" do
        Configuration.default do |config|
          config.cookies = { secure: true, httponly: true, samesite: OPT_OUT }
        end

        _, http_headers, = middleware.call(Rack::MockRequest.env_for("http://localhost"))
        expect(http_headers["Set-Cookie"]).to eq("foo=bar; HttpOnly")

        default_cookies = Configuration.send(:default_config).cookies
        expect(default_cookies[:secure]).to eq(true)
        expect(default_cookies).to be_frozen

        _, https_headers, = middleware.call(Rack::MockRequest.env_for("https://localhost"))
        expect(https_headers["Set-Cookie"]).to eq("foo=bar; secure; HttpOnly")
      end
    end
  end
end
