# frozen_string_literal: true
require "spec_helper"

module SecureHeaders
  describe Cookie do
    let(:raw_cookie) { "_session=thisisatest" }

    # Independent RFC 6265-shaped parser used to verify the emitted header
    # without relying on the implementation under test.
    def parse_set_cookie(cookie)
      pair, *attributes = cookie.split(";")
      name, value = pair.split("=", 2)
      flags = attributes.each_with_object({}) do |attribute, result|
        key, attribute_value = attribute.strip.split("=", 2)
        result[key.downcase] = attribute_value.nil? ? true : attribute_value
      end
      [name, value, flags]
    end

    it "does not tamper with cookies when using OPT_OUT is used" do
      cookie = Cookie.new(raw_cookie, OPT_OUT)
      expect(cookie.to_s).to eq(raw_cookie)
    end

    it "applies httponly, secure, and samesite by default" do
      cookie = Cookie.new(raw_cookie, nil)
      expect(cookie.to_s).to eq("_session=thisisatest; secure; HttpOnly; SameSite=Lax")
    end

    it "preserves existing attributes" do
      cookie = Cookie.new("_session=thisisatest; secure", secure: true, httponly: OPT_OUT, samesite: OPT_OUT)
      expect(cookie.to_s).to eq("_session=thisisatest; secure")
    end

    it "prevents duplicate flagging of attributes" do
      cookie = Cookie.new("_session=thisisatest; secure", secure: true, httponly: OPT_OUT)
      expect(cookie.to_s.scan(/secure/i).count).to eq(1)
    end

    context "Secure cookies" do
      context "when configured with a boolean" do
        it "flags cookies as Secure" do
          cookie = Cookie.new(raw_cookie, secure: true, httponly: OPT_OUT, samesite: OPT_OUT)
          expect(cookie.to_s).to eq("_session=thisisatest; secure")
        end
      end

      context "when configured with a Hash" do
        it "flags cookies as Secure when whitelisted" do
          cookie = Cookie.new(raw_cookie, secure: { only: ["_session"] }, httponly: OPT_OUT, samesite: OPT_OUT)
          expect(cookie.to_s).to eq("_session=thisisatest; secure")
        end

        it "does not flag cookies as Secure when excluded" do
          cookie = Cookie.new(raw_cookie, secure: { except: ["_session"] }, httponly: OPT_OUT, samesite: OPT_OUT)
          expect(cookie.to_s).to eq("_session=thisisatest")
        end
      end
    end

    context "HttpOnly cookies" do
      context "when configured with a boolean" do
        it "flags cookies as HttpOnly" do
          cookie = Cookie.new(raw_cookie, httponly: true, secure: OPT_OUT, samesite: OPT_OUT)
          expect(cookie.to_s).to eq("_session=thisisatest; HttpOnly")
        end
      end

      context "when configured with a Hash" do
        it "flags cookies as HttpOnly when whitelisted" do
          cookie = Cookie.new(raw_cookie, httponly: { only: ["_session"] }, secure: OPT_OUT, samesite: OPT_OUT)
          expect(cookie.to_s).to eq("_session=thisisatest; HttpOnly")
        end

        it "does not flag cookies as HttpOnly when excluded" do
          cookie = Cookie.new(raw_cookie, httponly: { except: ["_session"] }, secure: OPT_OUT, samesite: OPT_OUT)
          expect(cookie.to_s).to eq("_session=thisisatest")
        end
      end
    end

    context "SameSite cookies" do
      %w(None Lax Strict).each do |flag|
        it "flags SameSite=#{flag}" do
          cookie = Cookie.new(raw_cookie, samesite: { flag.downcase.to_sym => { only: ["_session"] } }, secure: OPT_OUT, httponly: OPT_OUT)
          expect(cookie.to_s).to eq("_session=thisisatest; SameSite=#{flag}")
        end

        it "flags SameSite=#{flag} when configured with a boolean" do
          cookie = Cookie.new(raw_cookie, samesite: { flag.downcase.to_sym => true }, secure: OPT_OUT, httponly: OPT_OUT)
          expect(cookie.to_s).to eq("_session=thisisatest; SameSite=#{flag}")
        end

        it "does not flag cookies as SameSite=#{flag} when excluded" do
          cookie = Cookie.new(raw_cookie, samesite: { flag.downcase.to_sym => { except: ["_session"] } }, secure: OPT_OUT, httponly: OPT_OUT)
          expect(cookie.to_s).to eq("_session=thisisatest")
        end
      end

      it "flags SameSite=Strict when configured with a boolean" do
        cookie = Cookie.new(raw_cookie, { samesite: { strict: true }, secure: OPT_OUT, httponly: OPT_OUT })
        expect(cookie.to_s).to eq("_session=thisisatest; SameSite=Strict")
      end

      it "flags properly when both lax and strict are configured" do
        raw_cookie = "_session=thisisatest"
        cookie = Cookie.new(raw_cookie, samesite: { strict: { only: ["_session"] }, lax: { only: ["_additional_session"] } }, secure: OPT_OUT, httponly: OPT_OUT)
        expect(cookie.to_s).to eq("_session=thisisatest; SameSite=Strict")
      end

      it "ignores configuration if the cookie is already flagged" do
        raw_cookie = "_session=thisisatest; SameSite=Strict"
        cookie = Cookie.new(raw_cookie, samesite: { lax: true }, secure: OPT_OUT, httponly: OPT_OUT)
        expect(cookie.to_s).to eq(raw_cookie)
      end

      it "samesite: true sets all cookies to samesite=lax" do
        raw_cookie = "_session=thisisatest"
        cookie = Cookie.new(raw_cookie, samesite: true, secure: OPT_OUT, httponly: OPT_OUT)
        expect(cookie.to_s).to eq("_session=thisisatest; SameSite=Lax")
      end
    end

    context "attribute recognition" do
      let(:config) { { secure: true, httponly: true, samesite: { lax: true } } }

      it "does not treat a cookie with the same name as an existing attribute" do
        cookie = Cookie.new("Secure=abc; Path=/", config)
        expect(cookie.to_s).to eq("Secure=abc; Path=/; secure; HttpOnly; SameSite=Lax")
      end

      it "does not treat a comma inside a quoted value as an attribute separator" do
        cookie = Cookie.new(%q(foo="a, secure"; Path=/), config)
        expect(cookie.to_s).to eq(%q(foo="a, secure"; Path=/; secure; HttpOnly; SameSite=Lax))
      end

      it "does not treat a comma inside an attribute value as an attribute separator" do
        cookie = Cookie.new("foo=bar; Path=/a,secure", config)
        expect(cookie.to_s).to eq("foo=bar; Path=/a,secure; secure; HttpOnly; SameSite=Lax")
      end

      it "does not percent-decode attribute names" do
        cookie = Cookie.new("foo=bar; %53ecure", config)
        expect(cookie.to_s).to eq("foo=bar; %53ecure; secure; HttpOnly; SameSite=Lax")
      end

      it "does not match attribute names by prefix or suffix" do
        cookie = Cookie.new("foo=bar; Secure2; XHttpOnly; SameSiteX", config)
        expect(cookie.to_s).to eq("foo=bar; Secure2; XHttpOnly; SameSiteX; secure; HttpOnly; SameSite=Lax")
      end

      it "preserves an Expires attribute containing a comma" do
        raw_cookie = "foo=bar; Expires=Wed, 09 Jun 2021 10:18:14 GMT; Path=/"
        cookie = Cookie.new(raw_cookie, config)
        expect(cookie.to_s).to eq("#{raw_cookie}; secure; HttpOnly; SameSite=Lax")
      end

      it "recognizes existing attributes regardless of case and surrounding whitespace" do
        cookie = Cookie.new("foo=bar;  sEcUrE ; httponly ; samesite=Strict", config)
        expect(cookie.to_s).to eq("foo=bar;  sEcUrE ; httponly ; samesite=Strict")
      end

      it "preserves values containing separators and escape-like fragments verbatim" do
        raw_cookie = "foo=a%3Bsecure%2Csecure\\,secure; Path=/"
        cookie = Cookie.new(raw_cookie, config)
        expect(cookie.to_s).to eq("#{raw_cookie}; secure; HttpOnly; SameSite=Lax")
      end

      it "keeps the cookie-pair value byte-for-byte identical" do
        raw_cookie = %q(foo="a, secure, HttpOnly"; Path=/)
        name, value, = parse_set_cookie(Cookie.new(raw_cookie, config).to_s)
        expect(name).to eq("foo")
        expect(value).to eq(%q("a, secure, HttpOnly"))
      end
    end

    context "malformed SameSite attributes" do
      let(:config) { { secure: true, httponly: true, samesite: { lax: true } } }

      it "replaces a SameSite attribute with no value" do
        cookie = Cookie.new("foo=bar; SameSite", config)
        expect(cookie.to_s).to eq("foo=bar; SameSite=Lax; secure; HttpOnly")
      end

      it "replaces an unknown SameSite value without adding a duplicate attribute" do
        cookie = Cookie.new("foo=bar; SameSite=Bogus", config)
        output = cookie.to_s
        _, _, attributes = parse_set_cookie(output)
        expect(output).to eq("foo=bar; SameSite=Lax; secure; HttpOnly")
        expect(attributes["samesite"]).to eq("Lax")
      end

      it "normalizes every invalid SameSite attribute to the existing valid value" do
        cookie = Cookie.new("foo=bar; SameSite=Bogus; SameSite=Strict; SameSite=", config)
        output = cookie.to_s
        _, _, attributes = parse_set_cookie(output)
        expect(output).to eq("foo=bar; SameSite=Strict; SameSite=Strict; SameSite=Strict; secure; HttpOnly")
        expect(attributes["samesite"]).to eq("Strict")
      end

      it "leaves an unparseable line untouched" do
        %w(noequals =abc ;;;).each do |raw_cookie|
          expect(Cookie.new(raw_cookie, config).to_s).to eq(raw_cookie)
        end
      end
    end
  end

  context "with an invalid configuration" do
    it "raises an exception when not configured with a Hash" do
      expect do
        Cookie.validate_config!("configuration")
      end.to raise_error(CookiesConfigError)
    end

    it "raises an exception when configured without a boolean(true or OPT_OUT)/Hash" do
      expect do
        Cookie.validate_config!(secure: "true")
      end.to raise_error(CookiesConfigError)
    end

    it "raises an exception when configured with false" do
      expect do
        Cookie.validate_config!(secure: false)
      end.to raise_error(CookiesConfigError)
    end

    it "raises an exception when both only and except filters are provided" do
      expect do
        Cookie.validate_config!(secure: { only: [], except: [] })
      end.to raise_error(CookiesConfigError)
    end

    it "raises an exception when SameSite is not configured with a Hash" do
      expect do
        Cookie.validate_config!(samesite: true)
      end.to raise_error(CookiesConfigError)
    end

    cookie_options = %i(none lax strict)
    cookie_options.each do |flag|
      (cookie_options - [flag]).each do |other_flag|
        it "raises an exception when SameSite #{flag} and #{other_flag} enforcement modes are configured with booleans" do
          expect do
            Cookie.validate_config!(samesite: { flag => true, other_flag => true })
          end.to raise_error(CookiesConfigError)
        end
      end
    end

    it "raises an exception when SameSite lax and strict enforcement modes are configured with booleans" do
      expect do
        Cookie.validate_config!(samesite: { lax: true, strict: { only: ["_anything"] } })
      end.to raise_error(CookiesConfigError)
    end

    it "raises an exception when both only and except filters are provided to SameSite configurations" do
      expect do
        Cookie.validate_config!(samesite: { lax: { only: ["_anything"], except: ["_anythingelse"] } })
      end.to raise_error(CookiesConfigError)
    end

    it "raises an exception when both lax and strict only filters are provided to SameSite configurations" do
      expect do
        Cookie.validate_config!(samesite: { lax: { only: ["_anything"] }, strict: { only: ["_anything"] } })
      end.to raise_error(CookiesConfigError)
    end

    it "raises an exception when both lax and strict only filters are provided to SameSite configurations" do
      expect do
        Cookie.validate_config!(samesite: { lax: { except: ["_anything"] }, strict: { except: ["_anything"] } })
      end.to raise_error(CookiesConfigError)
    end
  end
end
