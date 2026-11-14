# frozen_string_literal: true
require "spec_helper"

module SecureHeaders
  describe "Reporting-Endpoints reference integrity" do
    let(:request) { double("Request", scheme: "https", env: {}) }

    before(:each) do
      reset_config
    end

    # Configuration.default instance_evals its block, so helpers must be
    # captured local variables rather than example-group methods.
    build_csp = lambda do |report_to: nil, report_only: false|
      values = {
        default_src: %w('self'),
        script_src: %w('self')
      }
      values[:report_to] = report_to if report_to
      values[:report_only] = true if report_only
      values
    end

    configure_default = lambda do |report_to: "tenant-a", endpoints: { "tenant-a" => "https://a.example.com/reports" }|
      Configuration.default do |config|
        config.csp = build_csp.call(report_to: report_to)
        config.csp_report_only = build_csp.call(report_to: report_to, report_only: true)
        config.reporting_endpoints = endpoints
      end
    end

    it "accepts an enforced and report-only policy that share a resolver" do
      configure_default.call(report_to: "tenant-a")

      headers = SecureHeaders.header_hash_for(request)
      expect(headers[ContentSecurityPolicyConfig::HEADER_NAME]).to include("report-to tenant-a")
      expect(headers[ContentSecurityPolicyReportOnlyConfig::HEADER_NAME]).to include("report-to tenant-a")
      expect(headers[ReportingEndpoints::HEADER_NAME]).to eq('tenant-a="https://a.example.com/reports"')
    end

    it "resolves the same endpoint name to one destination for both policies" do
      Configuration.default do |config|
        config.csp = build_csp.call(report_to: "shared")
        config.csp_report_only = build_csp.call(report_to: "shared", report_only: true)
        config.reporting_endpoints = {
          "shared" => "https://reports.example.com/all",
          "shared-alt" => "https://reports.example.com/alt"
        }
      end

      headers = SecureHeaders.header_hash_for(request)
      expect(headers[ReportingEndpoints::HEADER_NAME]).to eq('shared="https://reports.example.com/all", shared-alt="https://reports.example.com/alt"')
      expect(headers[ContentSecurityPolicyConfig::HEADER_NAME]).to include("report-to shared")
      expect(headers[ContentSecurityPolicyReportOnlyConfig::HEADER_NAME]).to include("report-to shared")
      expect(headers[ContentSecurityPolicyConfig::HEADER_NAME]).not_to include("shared-alt")
    end

    it "rejects duplicate endpoint names introduced by symbol/string keys" do
      expect do
        Configuration.default do |config|
          config.csp = build_csp.call(report_to: "tenant-a")
          config.reporting_endpoints = {
            "tenant-a" => "https://a.example.com/reports",
            "tenant-a": "https://b.example.com/reports"
          }
        end
      end.to raise_error(ReportingEndpointsConfigError, /Duplicate reporting endpoint name/)
    end

    describe "named overrides" do
      before(:each) do
        configure_default.call

        Configuration.override(:tenant_b) do |config|
          config.csp.merge!(report_to: "tenant-b")
          config.csp_report_only.merge!(report_to: "tenant-b")
          config.reporting_endpoints = {
            "tenant-a" => "https://a.example.com/reports",
            "tenant-b" => "https://b.example.com/reports"
          }
        end

        Configuration.override(:tenant_b_without_endpoint) do |config|
          config.csp.merge!(report_to: "tenant-b")
          config.reporting_endpoints = {
            "tenant-a" => "https://a.example.com/reports"
          }
        end
      end

      it "selects the endpoint from the tenant override" do
        request_b = double("Request", scheme: "https", env: {})
        SecureHeaders.use_secure_headers_override(request_b, :tenant_b)

        headers = SecureHeaders.header_hash_for(request_b)
        expect(headers[ContentSecurityPolicyConfig::HEADER_NAME]).to include("report-to tenant-b")
        expect(headers[ReportingEndpoints::HEADER_NAME]).to include('tenant-b="https://b.example.com/reports"')
      end

      it "does not leak tenant state based on override call order" do
        request_a = double("Request", scheme: "https", env: {})
        request_b = double("Request", scheme: "https", env: {})
        SecureHeaders.use_secure_headers_override(request_a, :tenant_b)

        headers_a = SecureHeaders.header_hash_for(request_a)
        headers_b = SecureHeaders.header_hash_for(request_b)

        expect(headers_a[ContentSecurityPolicyConfig::HEADER_NAME]).to include("report-to tenant-b")
        expect(headers_b[ContentSecurityPolicyConfig::HEADER_NAME]).to include("report-to tenant-a")
        expect(headers_a[ReportingEndpoints::HEADER_NAME]).to include("tenant-b=")
        expect(headers_b[ReportingEndpoints::HEADER_NAME]).not_to include("tenant-b=")
      end

      it "raises when a tenant override revokes a referenced endpoint" do
        request_b = double("Request", scheme: "https", env: {})
        SecureHeaders.use_secure_headers_override(request_b, :tenant_b_without_endpoint)

        expect do
          SecureHeaders.header_hash_for(request_b)
        end.to raise_error(ReportingEndpointReferenceError, /undefined reporting endpoint "tenant-b"/)
      end

      it "raises when a tenant override removes the endpoint map entirely" do
        Configuration.override(:tenant_revoked) do |config|
          config.csp.merge!(report_to: "tenant-a")
          config.reporting_endpoints = nil
        end

        request_revoked = double("Request", scheme: "https", env: {})
        SecureHeaders.use_secure_headers_override(request_revoked, :tenant_revoked)

        expect do
          SecureHeaders.header_hash_for(request_revoked)
        end.to raise_error(ReportingEndpointReferenceError, /not configured/)
      end
    end

    describe "request overrides" do
      before(:each) do
        configure_default.call
      end

      it "allows updating the reference and endpoints together" do
        SecureHeaders.override_content_security_policy_directives(request, report_to: "tenant-c")
        SecureHeaders.override_reporting_endpoints(request, {
          "tenant-a" => "https://a.example.com/reports",
          "tenant-c" => "https://c.example.com/reports"
        })

        headers = SecureHeaders.header_hash_for(request)
        expect(headers[ContentSecurityPolicyConfig::HEADER_NAME]).to include("report-to tenant-c")
        expect(headers[ReportingEndpoints::HEADER_NAME]).to include('tenant-c="https://c.example.com/reports"')
      end

      it "raises when a request references a name it did not define" do
        SecureHeaders.override_content_security_policy_directives(request, report_to: "tenant-z")

        expect do
          SecureHeaders.header_hash_for(request)
        end.to raise_error(ReportingEndpointReferenceError, /undefined reporting endpoint "tenant-z"/)
      end

      it "raises when a request revokes the endpoint after selecting it" do
        SecureHeaders.override_reporting_endpoints(request, { "tenant-b" => "https://b.example.com/reports" })

        expect do
          SecureHeaders.header_hash_for(request)
        end.to raise_error(ReportingEndpointReferenceError, /undefined reporting endpoint "tenant-a"/)
      end

      it "allows removing the report_to reference while revoking endpoints" do
        SecureHeaders.override_content_security_policy_directives(request, report_to: OPT_OUT)
        SecureHeaders.override_reporting_endpoints(request, nil)

        headers = SecureHeaders.header_hash_for(request)
        expect(headers[ContentSecurityPolicyConfig::HEADER_NAME]).not_to include("report-to")
        expect(headers[ReportingEndpoints::HEADER_NAME]).to be_nil
      end
    end

    describe "malicious input" do
      {
        "quote" => 'csp" , evil="https://evil.example.com',
        "backslash" => 'csp\\endpoint',
        "cr" => "csp\r\nx-injected: 1",
        "lf" => "csp\nx-injected: 1",
        "semicolon" => "csp; script-src *",
        "comma" => "csp, evil",
        "space" => "csp endpoint",
        "tab" => "csp\tendpoint",
        "control" => "csp\u0001endpoint",
        "uppercase" => "CSP-ENDPOINT",
        "unicode" => "csp-报告"
      }.each do |label, name|
        it "rejects a #{label} endpoint name" do
          expect do
            ReportingEndpoints.validate_config!({ name => "https://example.com/reports" })
          end.to raise_error(ReportingEndpointsConfigError, /Endpoint name/)
        end
      end

      {
        "header injection" => "https://example.com/reports\r\nx-injected: 1",
        "quote injection" => 'https://example.com/reports", evil="https://evil.example.com',
        "backslash" => "https://example.com/reports\\evil",
        "space" => "https://example.com/re ports",
        "tab" => "https://example.com/re\tports",
        "control" => "https://example.com/re\u0001ports",
        "http" => "http://example.com/reports",
        "relative" => "/reports",
        "missing host" => "https:///reports",
        "unicode host" => "https://例え.テスト/reports",
        "malformed escape" => "https://example.com/%zz"
      }.each do |label, url|
        it "rejects a URL with #{label}" do
          expect do
            ReportingEndpoints.validate_config!({ "csp-endpoint" => url })
          end.to raise_error(ReportingEndpointsConfigError)
        end
      end

      it "rejects a malicious report_to reference" do
        expect do
          ContentSecurityPolicy.validate_config!(
            ContentSecurityPolicyConfig.new(
              default_src: %w('self'),
              script_src: %w('self'),
              report_to: 'csp-endpoint; script-src *'
            )
          )
        end.to raise_error(ContentSecurityPolicyConfigError, /report_to must be a lowercase reporting endpoint name/)
      end

      it "scrubs quotes, backslashes, and controls from directly constructed report_to values" do
        allow(Kernel).to receive(:warn)
        csp = ContentSecurityPolicy.new(
          default_src: %w('self'),
          script_src: %w('self'),
          report_to: "csp\"endpoint\u0000\n"
        )

        expect(csp.value).to include("report-to csp")
        expect(csp.value).not_to include('"')
        expect(csp.value).not_to include("\\")
        expect(csp.value).not_to include("\u0000")
        expect(csp.value).not_to include("\n")
      end

      it "emits exactly one endpoint even when a malicious name is embedded" do
        expect do
          ReportingEndpoints.make_header({
            "csp-endpoint" => "https://example.com/reports",
            'csp-endpoint", evil="https://evil.example.com' => "https://example.com/other"
          })
        end.to raise_error(ReportingEndpointsConfigError)
      end
    end

    describe "internationalized URLs" do
      it "percent-encodes a non-ASCII path and query" do
        header_name, value = ReportingEndpoints.make_header({
          "csp-endpoint" => "https://example.com/报告?q=值&next=/下一页"
        })

        expect(header_name).to eq("reporting-endpoints")
        expect(value).to eq('csp-endpoint="https://example.com/%E6%8A%A5%E5%91%8A?q=%E5%80%BC&next=/%E4%B8%8B%E4%B8%80%E9%A1%B5"')
        expect(value).to be_ascii_only
      end

      it "preserves existing percent escapes while encoding non-ASCII characters" do
        _name, value = ReportingEndpoints.make_header({
          "csp-endpoint" => "https://example.com/%E6%8A%A5/réports"
        })

        expect(value).to eq('csp-endpoint="https://example.com/%E6%8A%A5/r%C3%A9ports"')
      end

      it "emits an encoded internationalized path in a full header set" do
        configure_default.call(report_to: "tenant-e", endpoints: {
          "tenant-e" => "https://example.com/报告?q=值"
        })

        headers = SecureHeaders.header_hash_for(request)
        expect(headers[ContentSecurityPolicyConfig::HEADER_NAME]).to include("report-to tenant-e")
        expect(headers[ReportingEndpoints::HEADER_NAME]).to eq('tenant-e="https://example.com/%E6%8A%A5%E5%91%8A?q=%E5%80%BC"')
      end
    end
  end
end
