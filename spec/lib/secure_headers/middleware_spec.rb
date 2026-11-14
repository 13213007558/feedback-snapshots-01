# frozen_string_literal: true
require "spec_helper"

module SecureHeaders
  describe Middleware do
    let(:app) { lambda { |env| [200, env, "app"] } }
    let(:cookie_app) { lambda { |env| [200, env.merge("Set-Cookie" => "foo=bar"), "app"] } }

    let(:middleware) { Middleware.new(app) }
    let(:cookie_middleware) { Middleware.new(cookie_app) }

    before(:each) do
      reset_config
      Configuration.default
    end

    it "sets the headers" do
      _, env = middleware.call(Rack::MockRequest.env_for("https://looocalhost", {}))
      expect_default_values(env)
    end

    it "respects overrides" do
      request = Rack::Request.new("HTTP_X_FORWARDED_SSL" => "on")
      SecureHeaders.override_x_frame_options(request, "DENY")
      _, env = middleware.call request.env
      expect(env[XFrameOptions::HEADER_NAME]).to eq("DENY")
    end

    it "uses named overrides" do
      Configuration.override("my_custom_config") do |config|
        config.csp[:script_src] = %w(example.org)
      end
      request = Rack::Request.new({})
      SecureHeaders.use_secure_headers_override(request, "my_custom_config")
      _, env = middleware.call request.env
      expect(env[ContentSecurityPolicyConfig::HEADER_NAME]).to match("example.org")
    end

    context "Rack::Headers conversion" do
      it "converts headers to Rack::Headers when Rack::Headers is defined" do
        if defined?(Rack::Headers)
          _, headers, = middleware.call(Rack::MockRequest.env_for("https://localhost", {}))
          expect(headers.is_a?(Rack::Headers)).to be true
        else
          skip "Rack::Headers is not defined in this version of Rack"
        end
      end

      it "keeps headers as a hash when Rack::Headers is not defined" do
        # Temporarily hide the Rack::Headers constant if it exists
        if defined?(Rack::Headers)
          hide_const("Rack::Headers")
        end

        _, headers, = middleware.call(Rack::MockRequest.env_for("https://localhost", {}))
        expect(headers.is_a?(Hash)).to be true
      end
    end

    context "cookies" do
      before(:each) do
        reset_config
      end
      context "cookies should be flagged" do
        it "flags cookies as secure" do
          Configuration.default { |config| config.cookies = { secure: true, httponly: OPT_OUT, samesite: OPT_OUT } }
          request = Rack::Request.new("HTTPS" => "on")
          _, env = cookie_middleware.call request.env
          expect(env["Set-Cookie"]).to eq("foo=bar; secure")
        end
      end

      it "allows opting out of cookie protection with OPT_OUT alone" do
        Configuration.default { |config| config.cookies = OPT_OUT }

        # do NOT make this request https. non-https requests modify a config,
        # causing an exception when operating on OPT_OUT. This ensures we don't
        # try to modify the config.
        request = Rack::Request.new({})
        _, env = cookie_middleware.call request.env
        expect(env["Set-Cookie"]).to eq("foo=bar")
      end

      context "cookies should not be flagged" do
        it "does not flags cookies as secure" do
          Configuration.default { |config| config.cookies = { secure: OPT_OUT, httponly: OPT_OUT, samesite: OPT_OUT }  }
          request = Rack::Request.new("HTTPS" => "on")
          _, env = cookie_middleware.call request.env
          expect(env["Set-Cookie"]).to eq("foo=bar")
        end
      end
    end

    context "cookies" do
      before(:each) do
        reset_config
      end
      it "flags cookies from configuration" do
        Configuration.default { |config| config.cookies = { secure: true, httponly: true, samesite: { lax: true } } }
        request = Rack::Request.new("HTTPS" => "on")
        _, env = cookie_middleware.call request.env

        expect(env["Set-Cookie"]).to eq("foo=bar; secure; HttpOnly; SameSite=Lax")
      end

      it "flags cookies with a combination of SameSite configurations" do
        cookie_middleware = Middleware.new(lambda { |env| [200, env.merge("Set-Cookie" => "_session=foobar\n_guest=true"), "app"] })

        Configuration.default { |config| config.cookies = { samesite: { lax: { except: ["_session"] }, strict: { only: ["_session"] } }, httponly: OPT_OUT, secure: OPT_OUT } }
        request = Rack::Request.new("HTTPS" => "on")
        _, env = cookie_middleware.call request.env

        expect(env["Set-Cookie"]).to match("_session=foobar; SameSite=Strict")
        expect(env["Set-Cookie"]).to match("_guest=true; SameSite=Lax")
      end

      it "keeps cookies as array after flagging if they are already an array" do
        cookie_middleware = Middleware.new(lambda { |env| [200, env.merge("Set-Cookie" => ["_session=foobar", "_guest=true"]), "app"] })

        Configuration.default { |config| config.cookies = { samesite: { lax: { except: ["_session"] }, strict: { only: ["_session"] } }, httponly: OPT_OUT, secure: OPT_OUT } }
        request = Rack::Request.new("HTTPS" => "on")
        _, env = cookie_middleware.call request.env

        expect(env["Set-Cookie"]).to match_array(["_session=foobar; SameSite=Strict", "_guest=true; SameSite=Lax"])
      end

      it "disables secure cookies for non-https requests" do
        Configuration.default { |config| config.cookies = { secure: true, httponly: OPT_OUT, samesite: OPT_OUT } }

        request = Rack::Request.new("HTTPS" => "off")
        _, env = cookie_middleware.call request.env
        expect(env["Set-Cookie"]).to eq("foo=bar")
      end

      it "sets the secure cookie flag correctly on interleaved http/https requests" do
        Configuration.default { |config| config.cookies = { secure: true, httponly: OPT_OUT, samesite: OPT_OUT } }

        request = Rack::Request.new("HTTPS" => "off")
        _, env = cookie_middleware.call request.env
        expect(env["Set-Cookie"]).to eq("foo=bar")

        request = Rack::Request.new("HTTPS" => "on")
        _, env = cookie_middleware.call request.env
        expect(env["Set-Cookie"]).to eq("foo=bar; secure")
      end
    end

    context "cookie parsing" do
      # Independent parser: split one Set-Cookie field into its pair and
      # attributes without using SecureHeaders::Cookie.
      def parse_field(field)
        pair, *attributes = field.split(";")
        name, value = pair.split("=", 2)
        flags = attributes.each_with_object({}) do |attribute, result|
          key, attribute_value = attribute.strip.split("=", 2)
          result[key.downcase] = attribute_value.nil? ? true : attribute_value
        end
        [name, value, attributes, flags]
      end

      def call_with(set_cookie)
        app = lambda { |env| [200, env.merge("Set-Cookie" => set_cookie), "app"] }
        _, env = Middleware.new(app).call(Rack::Request.new("HTTPS" => "on").env)
        env["Set-Cookie"]
      end

      before(:each) do
        reset_config
        Configuration.default
      end

      it "flags every cookie in an array without merging same-named cookies" do
        output = call_with(["sid=a; Path=/", "sid=b; Path=/admin"])

        expect(output).to be_a(Array)
        expect(output.length).to eq(2)
        names_and_paths = output.map do |field|
          name, _, _, flags = parse_field(field)
          [name, flags["path"]]
        end
        expect(names_and_paths).to eq([["sid", "/"], ["sid", "/admin"]])
        output.each do |field|
          _, _, _, flags = parse_field(field)
          expect(flags["secure"]).to be(true)
          expect(flags["httponly"]).to be(true)
          expect(flags["samesite"]).to eq("Lax")
        end
      end

      it "flags every cookie in a newline-delimited string without merging them" do
        output = call_with("sid=a; Path=/\nsid=b; Path=/admin")

        expect(output).to be_a(String)
        fields = output.split("\n")
        expect(fields.length).to eq(2)
        expect(fields.map { |field| parse_field(field)[0] }).to eq(["sid", "sid"])
        expect(fields.map { |field| parse_field(field)[3]["path"] }).to eq(["/", "/admin"])
      end

      it "normalizes CRLF separators without merging cookies" do
        output = call_with("sid=a; Path=/\r\nsid=b; Path=/admin")

        expect(output).to eq("sid=a; Path=/; secure; HttpOnly; SameSite=Lax\nsid=b; Path=/admin; secure; HttpOnly; SameSite=Lax")
      end

      it "preserves an Expires date containing a comma" do
        output = call_with(["sid=a; Expires=Wed, 09 Jun 2021 10:18:14 GMT; Path=/"])

        _, _, attributes, flags = parse_field(output.first)
        expect(attributes.map(&:strip)).to include("Expires=Wed, 09 Jun 2021 10:18:14 GMT")
        expect(flags["expires"]).to eq("Wed, 09 Jun 2021 10:18:14 GMT")
        expect(flags["samesite"]).to eq("Lax")
      end

      it "does not mistake comma-separated text or a cookie named Secure for an attribute" do
        output = call_with([%q(foo="a, secure"; Path=/), "Secure=abc; Path=/"])

        expect(output.length).to eq(2)
        name, value, attributes, flags = parse_field(output[0])
        expect([name, value]).to eq(["foo", %q("a, secure")])
        expect(attributes.grep(/\A\s*secure\s*\z/i).length).to eq(1)
        expect(flags["secure"]).to be(true)
        expect(parse_field(output[1]).first).to eq("Secure")
      end

      it "does not mistake a percent-encoded or similarly named attribute for an existing one" do
        output = call_with("foo=bar; %53ecure; Secure2; XHttpOnly")
        _, _, attributes, flags = parse_field(output)

        expect(attributes.grep(/\A\s*secure\s*\z/i).length).to eq(1)
        expect(flags["secure"]).to be(true)
        expect(flags["httponly"]).to be(true)
      end

      it "does not duplicate existing attributes" do
        output = call_with("_session=x; Secure; HttpOnly; SameSite=Strict")

        expect(output).to eq("_session=x; Secure; HttpOnly; SameSite=Strict")
      end

      it "normalizes an invalid SameSite value to exactly one SameSite attribute" do
        output = call_with("foo=bar; SameSite=Bogus")
        _, _, attributes, flags = parse_field(output)

        expect(attributes.grep(/\A\s*samesite/i).length).to eq(1)
        expect(flags["samesite"]).to eq("Lax")
      end

      it "keeps malformed fields separate and unchanged" do
        output = call_with(["noequals", "foo=bar; Path=/"])

        expect(output.length).to eq(2)
        expect(output[0]).to eq("noequals")
        expect(output[1]).to eq("foo=bar; Path=/; secure; HttpOnly; SameSite=Lax")
      end

      it "keeps the cookie-pair value byte-for-byte identical" do
        value = %q("a, secure, HttpOnly")
        output = call_with("foo=#{value}; Path=/")
        _, parsed_value, = parse_field(output)

        expect(parsed_value).to eq(value)
      end
    end

    context "when disabled" do
      before(:each) do
        reset_config
        Configuration.disable!
      end

      it "does not set any headers" do
        _, env = middleware.call(Rack::MockRequest.env_for("https://localhost", {}))

        # Verify no security headers are set by checking all configured header classes
        Configuration::HEADERABLE_ATTRIBUTES.each do |attr|
          klass = Configuration::CONFIG_ATTRIBUTES_TO_HEADER_CLASSES[attr]
          # Handle CSP specially since it has multiple classes
          if attr == :csp
            expect(env[ContentSecurityPolicyConfig::HEADER_NAME]).to be_nil
            expect(env[ContentSecurityPolicyReportOnlyConfig::HEADER_NAME]).to be_nil
          elsif klass.const_defined?(:HEADER_NAME)
            expect(env[klass::HEADER_NAME]).to be_nil
          end
        end
      end

      it "does not flag cookies" do
        _, env = cookie_middleware.call(Rack::MockRequest.env_for("https://localhost", {}))
        expect(env["Set-Cookie"]).to eq("foo=bar")
      end
    end
  end
end
