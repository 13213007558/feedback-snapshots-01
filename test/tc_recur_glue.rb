# Security regression tests for glue acceptance in Dnsruby::Recursor.
#
# A malicious delegation answer must not be able to smuggle addresses for
# unrelated nameservers into the recursor's authority caches:
#
#  - referrals for zones which cannot lead to the queried name are ignored
#  - additional A/AAAA records are only trusted as glue when they belong to
#    a nameserver at or below the delegated zone
#  - out-of-bailiwick nameservers are resolved independently
#
# The tests run the real Recursor against a scripted fake DNS network which
# records every server address the recursor chooses to query.

require_relative 'spec_helper'
require 'minitest/mock'

class TestRecurGlue < Minitest::Test
  ROOT_IP        = '10.0.0.1'.freeze
  TLD_IP         = '10.0.0.2'.freeze  # ns1.test. - attacker-controlled in these tests
  VICTIM_NS_IP   = '10.0.0.4'.freeze  # ns1.victim.test. (legitimate)
  INGLUE_NS_IP   = '10.0.0.5'.freeze  # ns1.inglue.test. (legitimate)
  ATTACKER_IP    = '6.6.6.6'.freeze   # smuggled address under attacker control
  SYSTEM_IP      = '192.0.2.254'.freeze # stand-in for the system resolver

  class << self
    attr_accessor :current_network
  end

  # Routes every Resolver#send_message through the scripted fake network
  # while a test has installed one.
  module SendMessageInterceptor
    def send_message(message)
      network = TestRecurGlue.current_network
      return super unless network
      network.handle(self, message)
    end
  end
  Dnsruby::Resolver.prepend(SendMessageInterceptor)

  # A scripted fake DNS network. Handlers are registered per server address;
  # every query the recursor makes is recorded as [server_addresses, qname, qtype].
  class FakeNetwork
    def initialize
      @handlers = {}
      @queries = []
      @mutex = Mutex.new
    end

    def on(server, &handler)
      @handlers[server] = handler
    end

    def handle(resolver, message)
      servers = resolver.single_resolvers.map(&:server)
      question = message.question.first
      qname = question.qname.to_s.downcase.sub(/\.*$/, '.')
      qtype = question.qtype.to_s
      @mutex.synchronize { @queries << [servers, qname, qtype] }
      server = servers.find { |s| @handlers.key?(s) }
      raise Dnsruby::ResolvTimeout, "FakeNetwork: no server for #{servers.inspect}" unless server
      @handlers[server].call(qname, qtype)
    end

    def queried_servers
      @mutex.synchronize { @queries.map(&:first).flatten.uniq }
    end
  end

  def setup
    reset_recursor_state
  end

  def teardown
    reset_recursor_state
  end

  def reset_recursor_state
    Dnsruby::Recursor.class_variable_set(:@@hints, nil)
    Dnsruby::Recursor.class_variable_set(:@@zones_cache, nil)
    Dnsruby::Recursor.class_variable_set(:@@authority_cache, Hash.new)
    Dnsruby::Recursor.class_variable_set(:@@nameservers, [])
  end

  def new_message(qname, qtype)
    msg = Dnsruby::Message.new
    msg.header.qr = true
    msg.add_question(qname, qtype, 'IN')
    msg
  end

  def referral(qname, qtype, owner, nsdname, glue = {})
    msg = new_message(qname, qtype)
    msg.add_authority(Dnsruby::RR.create("#{owner} 300 IN NS #{nsdname}"))
    glue.each do |name, address|
      msg.add_additional(Dnsruby::RR.create("#{name} 300 IN A #{address}"))
    end
    msg
  end

  def answer(qname, qtype, records)
    msg = new_message(qname, qtype)
    msg.header.aa = true
    records.each do |name, type, data|
      msg.add_answer(Dnsruby::RR.create("#{name} 300 IN #{type} #{data}"))
    end
    msg
  end

  def nxdomain(qname, qtype)
    msg = new_message(qname, qtype)
    msg.header.aa = true
    msg.header.rcode = Dnsruby::RCode.NXDOMAIN
    msg
  end

  def root_hints_answer(qname, qtype)
    msg = new_message(qname, qtype)
    msg.add_answer(Dnsruby::RR.create('. 300 IN NS a.root-servers.test.'))
    msg.add_additional(Dnsruby::RR.create("a.root-servers.test. 300 IN A #{ROOT_IP}"))
    msg
  end

  def build_network
    network = FakeNetwork.new

    network.on(ROOT_IP) do |qname, qtype|
      if qname == '.' && qtype == 'NS'
        root_hints_answer(qname, qtype)
      else
        referral(qname, qtype, 'test.', 'ns1.test.', 'ns1.test.' => TLD_IP)
      end
    end

    # The TLD server is attacker-controlled. Asked about attacker.test., it
    # answers with an unrelated delegation for victim.test. plus a smuggled
    # address for ns1.victim.test.
    network.on(TLD_IP) do |qname, qtype|
      if qname == 'attacker.test.' || qname.end_with?('.attacker.test.')
        referral(qname, qtype, 'victim.test.', 'ns1.victim.test.',
                 'ns1.victim.test.' => ATTACKER_IP)
      elsif qname == 'oobglue.test.' || qname.end_with?('.oobglue.test.')
        # Relevant delegation, but the nameserver is out-of-bailiwick and the
        # additional address for it must not be trusted.
        referral(qname, qtype, 'oobglue.test.', 'ns1.victim.test.',
                 'ns1.victim.test.' => ATTACKER_IP)
      elsif qname == 'oob.test.' || qname.end_with?('.oob.test.')
        # Out-of-bailiwick nameserver, no glue offered at all.
        referral(qname, qtype, 'oob.test.', 'ns1.victim.test.')
      elsif qname == 'inglue.test.' || qname.end_with?('.inglue.test.')
        referral(qname, qtype, 'inglue.test.', 'ns1.inglue.test.',
                 'ns1.inglue.test.' => INGLUE_NS_IP)
      elsif qname == 'victim.test.' || qname.end_with?('.victim.test.')
        referral(qname, qtype, 'victim.test.', 'ns1.victim.test.',
                 'ns1.victim.test.' => VICTIM_NS_IP)
      else
        nxdomain(qname, qtype)
      end
    end

    network.on(VICTIM_NS_IP) do |qname, qtype|
      case qname
      when 'www.victim.test.'  then answer(qname, qtype, [[qname, 'A', '192.0.2.100']])
      when 'www.oobglue.test.' then answer(qname, qtype, [[qname, 'A', '192.0.2.101']])
      when 'www.oob.test.'     then answer(qname, qtype, [[qname, 'A', '192.0.2.102']])
      when 'ns1.victim.test.'  then answer(qname, qtype, [[qname, 'A', VICTIM_NS_IP]])
      else nxdomain(qname, qtype)
      end
    end

    network.on(INGLUE_NS_IP) do |qname, qtype|
      if qname == 'www.inglue.test.'
        answer(qname, qtype, [[qname, 'A', '192.0.2.103']])
      else
        nxdomain(qname, qtype)
      end
    end

    # The smuggled address. If the recursor ever queries it, the attacker wins.
    network.on(ATTACKER_IP) do |qname, qtype|
      answer(qname, qtype, [[qname, 'A', ATTACKER_IP]])
    end

    # Stand-in for the system resolver: answers nameserver address lookups
    # and the recursor's root priming query.
    network.on(SYSTEM_IP) do |qname, qtype|
      case qname
      when '.'                 then root_hints_answer(qname, qtype)
      when 'ns1.victim.test.'  then answer(qname, qtype, [[qname, 'A', VICTIM_NS_IP]])
      when 'ns1.inglue.test.'  then answer(qname, qtype, [[qname, 'A', INGLUE_NS_IP]])
      else nxdomain(qname, qtype)
      end
    end

    network
  end

  def with_network
    network = build_network
    TestRecurGlue.current_network = network
    defaults = ->(*) { { nameserver: [SYSTEM_IP] } }
    Dnsruby::Config.stub(:default_config_hash, defaults) do
      yield network
    end
  ensure
    TestRecurGlue.current_network = nil
  end

  def answers_for(packet)
    packet.answer.select { |rr| rr.type == Dnsruby::Types::A }.map { |rr| rr.address.to_s }
  end

  # A controlled answer smuggles a delegation and address for victim.test.
  # while the recursor is asking about attacker.test. The poisoned data must
  # not influence later resolution of victim.test.
  def test_irrelevant_referral_does_not_poison_sibling_zone
    with_network do |network|
      recursor = Dnsruby::Recursor.new
      # Injection attempt: the controlled TLD answer refers victim.test. to
      # the attacker's address while we resolve an unrelated name.
      recursor.query_no_validation_or_recursion('www.attacker.test', 'A')

      packet = recursor.query_no_validation_or_recursion('www.victim.test', 'A')
      refute_nil(packet, 'resolution of www.victim.test failed')
      assert_equal(['192.0.2.100'], answers_for(packet))
      refute_includes(network.queried_servers, ATTACKER_IP,
                      'recursor queried the smuggled attacker address')
      assert_includes(network.queried_servers, VICTIM_NS_IP)
    end
  end

  # A relevant delegation whose nameserver is out-of-bailiwick: the smuggled
  # additional address must be ignored and the nameserver resolved
  # independently.
  def test_out_of_bailiwick_glue_is_not_trusted
    with_network do |network|
      recursor = Dnsruby::Recursor.new
      packet = recursor.query_no_validation_or_recursion('www.oobglue.test', 'A')
      refute_nil(packet, 'resolution of www.oobglue.test failed')
      assert_equal(['192.0.2.101'], answers_for(packet))
      refute_includes(network.queried_servers, ATTACKER_IP,
                      'recursor queried the smuggled attacker address')
      assert_includes(network.queried_servers, VICTIM_NS_IP)
      # ns1.victim.test. was resolved independently through the resolver.
      assert_includes(network.queried_servers, SYSTEM_IP)
    end
  end

  # Normal out-of-bailiwick nameserver without any glue must still resolve.
  def test_out_of_bailiwick_nameserver_without_glue_resolves
    with_network do |network|
      recursor = Dnsruby::Recursor.new
      packet = recursor.query_no_validation_or_recursion('www.oob.test', 'A')
      refute_nil(packet, 'resolution of www.oob.test failed')
      assert_equal(['192.0.2.102'], answers_for(packet))
      assert_includes(network.queried_servers, VICTIM_NS_IP)
    end
  end

  # Normal in-bailiwick glue must still be used to follow the delegation.
  def test_in_bailiwick_glue_still_used
    with_network do |network|
      recursor = Dnsruby::Recursor.new
      packet = recursor.query_no_validation_or_recursion('www.inglue.test', 'A')
      refute_nil(packet, 'resolution of www.inglue.test failed')
      assert_equal(['192.0.2.103'], answers_for(packet))
      assert_includes(network.queried_servers, INGLUE_NS_IP)
    end
  end
end
