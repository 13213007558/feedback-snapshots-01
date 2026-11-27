# frozen_string_literal: true

require "http"

# In-memory capture and channel checks for proxy diagnostics.
#
# Three channels are observed without opening a socket:
#
# * :proxy  — the CONNECT request sent to the proxy
# * :origin — the request sent through the tunnel to the application server
# * :event  — what the instrumentation feature hands to its instrumenter
#
# A Policy scopes two allowlists: which extra fields may travel to the proxy,
# and which fields may appear in an event that is safe to share. The
# Reconciler groups captured fields by normalized name, so spellings that
# differ only in case can be compared channel by channel.
module ProxyDiagnostics
  # Normalize a header name for case-insensitive comparisons
  #
  # @param name [String, Symbol]
  # @return [String]
  def self.normalize(name)
    HTTP::Headers.normalizer.call(name)
  end
end

require "support/proxy_diagnostics/harness"
require "support/proxy_diagnostics/policy"
require "support/proxy_diagnostics/acceptance"
require "support/proxy_diagnostics/fixture"
