# frozen_string_literal: true
require "spec_helper"

module SecureHeaders
  describe SecureHeaders, "CSP validation rollout" do
    let(:request) { Rack::Request.new("HTTP_X_FORWARDED_SSL" => "on") }

    CLEAN_POLICY = { default_src: %w('self'), script_src: %w('self') }

    around(:each) do |example|
      reset_config
      Configuration.csp_validation_mode = :observe
      example.run
      Configuration.csp_validation_mode = :observe
      reset_config
    end

    describe "global mode" do
      it "defaults to observe" do
        expect(Configuration.csp_validation_mode).to eq(:observe)
      end

      it "rejects an unknown mode" do
        expect { Configuration.csp_validation_mode = :bogus }
          .to raise_error(ArgumentError, /Unknown CSP validation mode/)
      end
    end

    describe "default registration" do
      it "observes an invalid default config but keeps producing the legacy header" do
        allow(Kernel).to receive(:warn)
        expect do
          Configuration.default do |config|
            config.csp = CLEAN_POLICY.merge(script_src: ["a;script-src *"])
          end
        end.not_to raise_error

        hash = SecureHeaders.header_hash_for(request)
        expect(hash[ContentSecurityPolicyConfig::HEADER_NAME]).to include("script-src a script-src *")
        violations = SecureHeaders.content_security_policy_violations(request)
        expect(violations.map { |v| v[:directive] }).to eq([:script_src])
        expect(violations.first[:source]).to eq(:header_generation)
      end

      it "strictly rejects an invalid default config at registration" do
        Configuration.csp_validation_mode = :strict
        expect do
          Configuration.default do |config|
            config.csp = CLEAN_POLICY.merge(script_src: ["a;script-src *"])
          end
        end.to raise_error(CspValidation::CspValidationError) do |error|
          expect(error.violations.first[:directive]).to eq(:script_src)
          expect(error.violations.first[:policy]).to eq(:enforced)
        end
        expect(Configuration.instance_variable_defined?(:@default_config)).to eq(false)
      end

      it "accepts a clean config in strict mode" do
        Configuration.csp_validation_mode = :strict
        Configuration.default { |config| config.csp = CLEAN_POLICY }
        hash = SecureHeaders.header_hash_for(request)
        expect(hash[ContentSecurityPolicyConfig::HEADER_NAME]).to eq("default-src 'self'; script-src 'self'")
      end

      it "raises at header generation when an already-invalid config reaches the renderer in strict mode" do
        allow(Kernel).to receive(:warn)
        Configuration.csp_validation_mode = :strict
        # Bypass the registration gate by building an invalid object directly,
        # to prove the renderer itself is a strict gate.
        config = Configuration.new
        config.csp = { default_src: %w('self'), script_src: ["a;b"] }
        request.env[SecureHeaders::SECURE_HEADERS_CONFIG] = config
        expect { SecureHeaders.header_hash_for(request) }
          .to raise_error(CspValidation::CspValidationError)
      end
    end

    describe "named overrides" do
      it "observes violations when an override is applied to a request" do
        allow(Kernel).to receive(:warn)
        Configuration.default { |config| config.csp = CLEAN_POLICY }
        Configuration.override(:bad) do |config|
          config.csp[:script_src] = ["override;script-src *"]
        end
        SecureHeaders.use_secure_headers_override(request, :bad)
        SecureHeaders.header_hash_for(request)
        violations = SecureHeaders.content_security_policy_violations(request)
        expect(violations.map { |v| v[:directive] }).to eq([:script_src])
      end

      it "strictly rejects a request that selects an invalid override, leaving the default intact" do
        Configuration.csp_validation_mode = :strict
        Configuration.default { |config| config.csp = CLEAN_POLICY }
        Configuration.override(:bad) do |config|
          config.csp[:script_src] = ["override;script-src *"]
        end
        expect { SecureHeaders.use_secure_headers_override(request, :bad) }
          .to raise_error(CspValidation::CspValidationError)
        expect(request.env[SecureHeaders::SECURE_HEADERS_CONFIG]).to be_nil

        fresh = Rack::Request.new("HTTP_X_FORWARDED_SSL" => "on")
        hash = SecureHeaders.header_hash_for(fresh)
        expect(hash[ContentSecurityPolicyConfig::HEADER_NAME]).to eq("default-src 'self'; script-src 'self'")
      end
    end

    describe "named appends and single-request appends" do
      it "observes a bad named append and keeps the scrubbed header" do
        allow(Kernel).to receive(:warn)
        Configuration.default { |config| config.csp = CLEAN_POLICY }
        Configuration.named_append(:widget) do |_request|
          { script_src: ["widget;script-src *"] }
        end
        SecureHeaders.use_content_security_policy_named_append(request, :widget)
        hash = SecureHeaders.header_hash_for(request)
        expect(hash[ContentSecurityPolicyConfig::HEADER_NAME]).to include("script-src 'self' widget script-src *")
        violations = SecureHeaders.content_security_policy_violations(request)
        expect(violations.map { |v| v[:directive] }).to eq([:script_src])
        expect(violations.first[:source]).to eq(:request_append)
      end

      it "strictly rejects a bad append and leaves no partial policy behind" do
        Configuration.csp_validation_mode = :strict
        Configuration.default { |config| config.csp = CLEAN_POLICY }
        expect do
          SecureHeaders.append_content_security_policy_directives(request, script_src: ["widget;script-src *"])
        end.to raise_error(CspValidation::CspValidationError)
        expect(request.env[SecureHeaders::SECURE_HEADERS_CONFIG]).to be_nil

        fresh = Rack::Request.new("HTTP_X_FORWARDED_SSL" => "on")
        hash = SecureHeaders.header_hash_for(fresh)
        expect(hash[ContentSecurityPolicyConfig::HEADER_NAME]).to eq("default-src 'self'; script-src 'self'")
      end

      it "strictly rejects a bad override and leaves no partial policy behind" do
        Configuration.csp_validation_mode = :strict
        Configuration.default { |config| config.csp = CLEAN_POLICY }
        expect do
          SecureHeaders.override_content_security_policy_directives(request, script_src: ["widget;script-src *"])
        end.to raise_error(CspValidation::CspValidationError)
        expect(request.env[SecureHeaders::SECURE_HEADERS_CONFIG]).to be_nil
      end

      it "allows a per-request strict mode while the global default stays observe" do
        Configuration.default { |config| config.csp = CLEAN_POLICY }
        expect do
          SecureHeaders.append_content_security_policy_directives(
            request,
            { script_src: ["widget;script-src *"] },
            nil,
            validation_mode: :strict
          )
        end.to raise_error(CspValidation::CspValidationError)
        expect(request.env[SecureHeaders::SECURE_HEADERS_CONFIG]).to be_nil
      end
    end

    describe "enforced and report-only policies are located separately" do
      it "records which policy each violation belongs to" do
        allow(Kernel).to receive(:warn)
        Configuration.default do |config|
          config.csp = CLEAN_POLICY.merge(script_src: ["enforced;x"])
          config.csp_report_only = CLEAN_POLICY.merge(script_src: ["report\ny"])
        end
        SecureHeaders.header_hash_for(request)
        violations = SecureHeaders.content_security_policy_violations(request)
        expect(violations.map { |v| v[:policy] }).to eq(%i(enforced report_only))
        expect(violations.map { |v| v[:directive] }).to eq(%i(script_src script_src))
      end

      it "can reject only the report-only append in strict mode without touching enforced" do
        Configuration.csp_validation_mode = :strict
        Configuration.default do |config|
          config.csp = CLEAN_POLICY
          config.csp_report_only = CLEAN_POLICY
        end
        expect do
          SecureHeaders.append_content_security_policy_directives(
            request,
            { script_src: ["report;y"] },
            :report_only
          )
        end.to raise_error(CspValidation::CspValidationError)
        expect(request.env[SecureHeaders::SECURE_HEADERS_CONFIG]).to be_nil
      end

      it "collects enforced and report-only violations together for a :both change" do
        Configuration.csp_validation_mode = :strict
        Configuration.default do |config|
          config.csp = CLEAN_POLICY
          config.csp_report_only = CLEAN_POLICY
        end
        expect do
          SecureHeaders.append_content_security_policy_directives(
            request,
            { script_src: ["both;y"] },
            :both
          )
        end.to raise_error(CspValidation::CspValidationError) do |error|
          expect(error.violations.map { |v| v[:policy] }).to eq(%i(enforced report_only))
        end
        expect(request.env[SecureHeaders::SECURE_HEADERS_CONFIG]).to be_nil
      end
    end

    describe "stability across multiple offending directives" do
      it "returns the same ordered violation list on every request" do
        allow(Kernel).to receive(:warn)
        config_hash = {
          default_src: %w('self'),
          script_src: ["z;z"],
          img_src: ["a\na"],
          style_src: ["m\rm"],
        }
        Configuration.default { |config| config.csp = config_hash }

        runs = 3.times.map do
          req = Rack::Request.new("HTTP_X_FORWARDED_SSL" => "on")
          SecureHeaders.header_hash_for(req)
          SecureHeaders.content_security_policy_violations(req)
        end
        expect(runs.uniq.length).to eq(1)
        expect(runs.first.map { |v| v[:directive] }).to eq(%i(img_src script_src style_src))
      end
    end
  end
end
