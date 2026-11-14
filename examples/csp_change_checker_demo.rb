# frozen_string_literal: true

# Demo for the CspChangeChecker prototype. Run with:
#   bundle exec ruby examples/csp_change_checker_demo.rb
#
# Every case is rendered through the production generator
# (SecureHeaders::ContentSecurityPolicy) before comparison, so what gets
# analysed is the effective header a browser would receive.

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))
require "secure_headers"
require "secure_headers/csp_change_checker"

include SecureHeaders

def show(title, old_config, new_config)
  report = CspChangeChecker.compare(old_config, new_config)
  puts "=" * 78
  puts title
  puts "-" * 78

  [[:enforced, report.enforced], [:report_only, report.report_only]].each do |label, channel|
    next if channel.nil?
    puts "[#{label}] #{channel.header_name}"
    puts "  old: #{channel.old_header_value || '(header absent)'}"
    puts "  new: #{channel.new_header_value || '(header absent)'}"
    channel.findings.each do |finding|
      puts "  - #{finding.directive}: #{finding.verdict}"
      puts "      evidence: #{finding.evidence}"
      puts "      witness : #{finding.witness}" if finding.witness
    end
    channel.unsupported_tokens.each do |token|
      puts "      unsupported in #{token.directive}: #{token.token} (#{token.reason})"
    end
  end

  report.notes.each { |note| puts "  note: #{note}" }
  puts "  >>> VERDICT: #{report.verdict.upcase}"
  puts
end

# Case 1: append + default-src fallback. The user only "adds one img host",
# but img-src previously inherited default-src 'none', so the effective
# img-src goes from deny-all to allowing an entire host. A string diff of the
# increment would miss the fallback entirely.
case1_old = { csp: { default_src: %w('none'), script_src: %w('self') } }
case1_new = {
  csp: ContentSecurityPolicy.combine_policies(
    case1_old[:csp], img_src: %w(tracker.example.com)
  )
}
show("Case 1: hidden loosening via default-src fallback on append", case1_old, case1_new)

# Case 2: adding a source silently drops an effective 'none' (the generator
# removes 'none' once siblings exist). object-src goes from deny-all to a host.
show(
  "Case 2: explicit 'none' silently discarded when a host is added",
  { csp: { default_src: %w('self'), object_src: %w('none') } },
  { csp: { default_src: %w('self'), object_src: %w('none' plugin.example.com) } }
)

# Case 3: scheme stripping makes two different config hashes render to the
# same header. This must be "equivalent", not a tightening or a loosening.
show(
  "Case 3: equivalent effective policy despite different raw hashes",
  { csp: { default_src: %w(https://cdn.example.com) } },
  { csp: { default_src: %w(cdn.example.com) } }
)

# Case 4: wildcard expansion. Dropping the https pin on a wildcard host opens
# the subdomains over http too. A naive textual/order-based diff can miss this.
show(
  "Case 4: wildcard host loses its scheme pin (http now allowed)",
  { csp: { default_src: %w(https://*.example.com) } },
  { csp: { default_src: %w(*.example.com) } }
)

# Case 5: nonce uncertainty. A nonce is per-request and the generator injects
# 'unsafe-inline' for backwards compatibility. No green verdict is possible.
show(
  "Case 5: nonce makes the effective script-src uncertifiable",
  { csp: { default_src: %w('self'), script_src: %w('self') } },
  {
    csp: {
      default_src: %w('self'),
      script_src: %w('self'),
      script_nonce: "per-request-value"
    }
  }
)

# Case 6: report-only tightening must not be presented as enforced tightening.
show(
  "Case 6: only the report-only policy tightens",
  { csp_report_only: { default_src: %w('self' tracker.example.com) } },
  { csp_report_only: { default_src: %w('self') } }
)

# Case 7: unsupported grammar (strict-dynamic) forces cannot_determine.
show(
  "Case 7: strict-dynamic is outside the modelled grammar",
  { csp: { default_src: %w('self'), script_src: %w('self') } },
  {
    csp: {
      default_src: %w('self'),
      script_src: [ContentSecurityPolicy::STRICT_DYNAMIC],
      script_nonce: "abc123",
      disable_nonce_backwards_compatibility: true
    }
  }
)

# Case 8: genuine one-way tightening for contrast.
show(
  "Case 8: genuine tightening (host removed, keyword retained)",
  { csp: { default_src: %w('self'), script_src: %w('self' cdn.example.com) } },
  { csp: { default_src: %w('self'), script_src: %w('self') } }
)
