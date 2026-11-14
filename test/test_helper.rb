# Add 'lib' to load path.
require 'test/unit'
require_relative '../lib/net/ldap'
require 'flexmock/test_unit'

# Whether integration tests should be run.
INTEGRATION = ENV.fetch("INTEGRATION", "skip") != "skip"

# BER identifier for an [APPLICATION n] constructed value: the APPLICATION
# class bits (0x40) plus the constructed bit (0x20). A real read_ber stores
# the full identifier octet (this base + the protocolOp tag number) in
# BerIdentifiedArray#ber_identifier, so test doubles that stand in for parsed
# PDUs must use the same full octet rather than the bare tag number.
APPLICATION_CONSTRUCTED_BASE = Net::BER::TAG_CLASS[:application] |
                               Net::BER::ENCODING_TYPE[:constructed]

# The CA file to verify certs against for tests.
# Override with CA_FILE env variable; otherwise checks for the VM-specific path
# and falls back to the test/fixtures/cacert.pem for local testing.
CA_FILE =
  ENV.fetch("CA_FILE") do
    if File.exist?("/etc/ssl/certs/cacert.pem")
      "/etc/ssl/certs/cacert.pem"
    else
      File.expand_path("fixtures/ca/docker-ca.pem", File.dirname(__FILE__))
    end
  end

BIND_CREDS = {
  method:   :simple,
  username: "cn=admin,dc=example,dc=org",
  password: "admin",
}.freeze

TLS_OPTS = OpenSSL::SSL::SSLContext::DEFAULT_PARAMS.merge({}).freeze

if RUBY_VERSION < "2.0"
  class String
    def b
      self
    end
  end
end

class MockInstrumentationService
  def initialize
    @events = {}
  end

  def instrument(event, payload)
    result = yield(payload)
    @events[event] ||= []
    @events[event] << [payload, result]
    result
  end

  def subscribe(event)
    @events[event] ||= []
    @events[event]
  end
end

class LDAPIntegrationTestCase < Test::Unit::TestCase
  # If integration tests aren't enabled, noop these tests.
  if !INTEGRATION
    def run(*)
      self
    end
  end

  def setup
    @service = MockInstrumentationService.new
    @ldap = Net::LDAP.new \
      host:           ENV.fetch('INTEGRATION_HOST', 'localhost'),
      port:           ENV.fetch('INTEGRATION_PORT', 389),
      search_domains: %w(dc=example,dc=org),
      uid:            'uid',
      instrumentation_service: @service
    @ldap.authenticate "cn=admin,dc=example,dc=org", "admin"
  end
end
