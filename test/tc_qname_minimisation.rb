# --
# Copyright 2026 Nominet UK
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ++

require_relative 'spec_helper'

#  Tests for QNAME minimisation (RFC 9156) in Dnsruby::Recursor.
#
#  These tests use an in-memory authoritative DNS world.  A recording
#  resolver is injected into the Recursor via +resolver_factory+, so no
#  network traffic is generated and every (zone, qname, qtype) sent to
#  each level of the delegation chain is captured in a log.
class TestQNameMinimisation < Minitest::Test
  ROOT_IP = "192.0.2.1"
  EXAMPLE_IP = "192.0.2.2"
  SVC_IP = "192.0.2.3"
  APP_IP = "192.0.2.4"

  #  An in-memory tree of authoritative zones.  Records every query it
  #  receives as [zone_name, qname, qtype] in +log+.
  class FakeAuthWorld
    Zone = Struct.new(:name, :delegations, :records, :formerr_on)

    attr_reader :log

    def initialize
      @zones = {}
      @server_zone = {}
      @log = []
    end

    #  delegations: { "svc.example." => { "ns1.svc.example." => "192.0.2.3" } }
    #  records:     { "www.example." => { "A" => ["203.0.113.7"] } }
    #  formerr_on:  proc taking (qname, qtype); when truthy the zone
    #               answers FORMERR (simulating an incompatible server)
    def add_zone(name, servers:, delegations: {}, records: {}, formerr_on: nil)
      @zones[name] = Zone.new(name, delegations, records, formerr_on)
      servers.each {|ip| @server_zone[ip] = name }
    end

    def zone(name)
      @zones[name]
    end

    def respond(server, qname, qtype)
      zone_name = @server_zone[server]
      raise "Query sent to unknown server #{server}" unless zone_name
      zone = @zones[zone_name]
      qname = qname.downcase
      qname += "." unless qname.end_with?(".")
      qtype = qtype.to_s.upcase
      @log << [zone_name, qname, qtype]
      if (zone.formerr_on && zone.formerr_on.call(qname, qtype))
        return formerr_message(qname, qtype)
      end

      cut = zone.delegations.keys.find {|d| qname == d || qname.end_with?(".#{d}") }
      #  DS records are served by the parent zone; anything else at or
      #  below a zone cut is a referral.
      if (cut && !(qname == cut && qtype == "DS"))
        return referral_message(qname, qtype, cut, zone.delegations[cut])
      end

      records = zone.records[qname]
      if (records.nil?)
        #  A CNAME at an ancestor occludes everything below it.
        ancestor = zone.records.keys.select {|n|
          qname.end_with?(".#{n}") && zone.records[n]["CNAME"]
        }.max_by(&:length)
        if (ancestor)
          target = zone.records[ancestor]["CNAME"].first
          rewritten = qname.sub(/#{Regexp.escape(ancestor)}\z/, target)
          rrs = [rr(ancestor, "CNAME", target)]
          if ((target_records = zone.records[rewritten]))
            target_records.each {|type, rdatas|
              rdatas.each {|rdata| rrs << rr(rewritten, type, rdata) }
            }
          end
          return answer_message(qname, qtype, rrs)
        end
        return nxdomain_message(zone.name, qname, qtype)
      end
      if (records.key?(qtype))
        return answer_message(qname, qtype, records[qtype].map {|rdata| rr(qname, qtype, rdata) })
      end
      if (records.key?("CNAME"))
        return answer_message(qname, qtype, records["CNAME"].map {|rdata| rr(qname, "CNAME", rdata) })
      end
      nodata_message(zone.name, qname, qtype)
    end

    private

    def rr(name, type, rdata)
      Dnsruby::RR.create("#{name} 3600 IN #{type} #{rdata}")
    end

    def base_message(qname, qtype, aa)
      msg = Dnsruby::Message.new
      msg.header.qr = true
      msg.header.aa = aa
      msg.add_question(qname, qtype, "IN")
      msg.header.rcode = Dnsruby::RCode.new("NOERROR")
      msg
    end

    def referral_message(qname, qtype, cut, ns_map)
      msg = base_message(qname, qtype, false)
      ns_map.each do |ns, ip|
        msg.authority << rr(cut, "NS", ns)
        msg.additional << rr(ns, "A", ip)
      end
      msg
    end

    def nxdomain_message(zone_name, qname, qtype)
      msg = base_message(qname, qtype, true)
      msg.header.rcode = Dnsruby::RCode.new("NXDOMAIN")
      msg.authority << soa(zone_name)
      msg
    end

    def nodata_message(zone_name, qname, qtype)
      msg = base_message(qname, qtype, true)
      msg.authority << soa(zone_name)
      msg
    end

    def answer_message(qname, qtype, rrs)
      msg = base_message(qname, qtype, true)
      rrs.each {|r| msg.answer << r }
      msg
    end

    def formerr_message(qname, qtype)
      msg = base_message(qname, qtype, false)
      msg.header.rcode = Dnsruby::RCode.new("FORMERR")
      msg
    end

    def soa(zone_name)
      rr(zone_name, "SOA", "ns.#{zone_name} hostmaster.#{zone_name} 1 3600 600 86400 300")
    end
  end

  #  Stands in for Dnsruby::Resolver at one level of the recursion;
  #  answers from the FakeAuthWorld and records the query there.
  class RecordingResolver
    attr_accessor :dnssec, :recurse, :retry_delay

    def initialize(world, servers)
      @world = world
      @servers = servers
    end

    def single_resolvers
      []
    end

    def send_message(msg)
      question = msg.question[0]
      @world.respond(@servers.first, question.qname.to_s, question.qtype.to_s)
    end
  end

  def setup
    @saved_class_vars = {}
    [:@@hints, :@@zones_cache, :@@authority_cache, :@@nameservers].each do |var|
      @saved_class_vars[var] = Dnsruby::Recursor.class_variable_get(var)
    end
  end

  def teardown
    @saved_class_vars.each {|var, value| Dnsruby::Recursor.class_variable_set(var, value) }
  end

  #  A four-level delegation chain:
  #  . -> example. -> svc.example. -> app.svc.example. -> www.app.svc.example. A
  def build_world
    world = FakeAuthWorld.new
    world.add_zone(".", :servers => [ROOT_IP],
      :delegations => { "example." => { "ns1.example." => EXAMPLE_IP } })
    world.add_zone("example.", :servers => [EXAMPLE_IP],
      :delegations => { "svc.example." => { "ns1.svc.example." => SVC_IP } },
      :records => {
        #  DS records live in the parent zone
        "svc.example." => { "DS" => ["12345 8 2 #{'AB' * 32}"] },
      })
    world.add_zone("svc.example.", :servers => [SVC_IP],
      :delegations => { "app.svc.example." => { "ns1.app.svc.example." => APP_IP } },
      :records => {
        "svc.example." => { "DNSKEY" => ["256 3 8 AQIDBAUGBwgJCgsMDQ4PEA=="] },
      })
    world.add_zone("app.svc.example.", :servers => [APP_IP],
      :records => {
        "www.app.svc.example." => { "A" => ["203.0.113.7"] },
      })
    world
  end

  def make_recursor(world, minimise)
    rec = Dnsruby::Recursor.new(Dnsruby::Resolver.new)
    rec.qname_minimise = minimise
    rec.resolver_factory = ->(servers) { RecordingResolver.new(world, servers) }
    cache = Dnsruby::Recursor::AddressCache.new
    cache.push([ROOT_IP, 3600])
    hints = { "a.root-servers.test." => cache }
    Dnsruby::Recursor.class_variable_set(:@@hints, hints)
    Dnsruby::Recursor.class_variable_set(:@@zones_cache, { "." => hints })
    Dnsruby::Recursor.class_variable_set(:@@authority_cache, {})
    rec
  end

  def test_minimisation_disabled_by_default
    rec = Dnsruby::Recursor.new(Dnsruby::Resolver.new)
    assert_equal(false, rec.qname_minimise)
    assert_equal(true, rec.qname_minimise_fallback)
  end

  def test_minimised_resolution_matches_legacy_and_hides_full_qname
    legacy_world = build_world
    legacy = make_recursor(legacy_world, false)
    legacy_result = legacy.query_no_validation_or_recursion("www.app.svc.example.", Dnsruby::Types.A)

    minimised_world = build_world
    minimised = make_recursor(minimised_world, true)
    minimised_result = minimised.query_no_validation_or_recursion("www.app.svc.example.", Dnsruby::Types.A)

    #  The multi-level resolution result is identical either way.
    assert_equal(legacy_result.answer.map(&:to_s), minimised_result.answer.map(&:to_s))
    assert_equal(["203.0.113.7"], minimised_result.answer.map {|rr| rr.address.to_s })

    #  Legacy behaviour: every level was sent the full QNAME.
    assert_equal([
      [".", "www.app.svc.example.", "A"],
      ["example.", "www.app.svc.example.", "A"],
      ["svc.example.", "www.app.svc.example.", "A"],
      ["app.svc.example.", "www.app.svc.example.", "A"],
    ], legacy_world.log)

    #  Minimised: each level only saw the name it needed to find the
    #  next delegation; only the final level saw the full QNAME.
    assert_equal([
      [".", "example.", "A"],
      ["example.", "svc.example.", "A"],
      ["svc.example.", "app.svc.example.", "A"],
      ["app.svc.example.", "www.app.svc.example.", "A"],
    ], minimised_world.log)

    upper_levels = minimised_world.log.select {|zone, _, _| zone != "app.svc.example." }
    assert(upper_levels.none? {|_, qname, _| qname == "www.app.svc.example." },
      "Upper-level servers must not receive the full QNAME")
  end

  def test_dnssec_queries_are_never_minimised_away
    world = build_world
    rec = make_recursor(world, true)
    result = rec.query_no_validation_or_recursion("svc.example.", Dnsruby::Types.DNSKEY)

    assert_equal(1, result.answer.count {|rr| rr.type == Dnsruby::Types.DNSKEY })
    #  The root only learned the TLD...
    assert_equal([[".", "example.", "A"]], world.log.select {|zone, _, _| zone == "." })
    #  ...while the authoritative level got the full QNAME *and* qtype.
    assert(world.log.include?(["svc.example.", "svc.example.", "DNSKEY"]),
      "The DNSKEY query must reach the authoritative level intact")
  end

  def test_ds_query_is_served_by_parent_zone_intact
    world = build_world
    rec = make_recursor(world, true)
    result = rec.query_no_validation_or_recursion("svc.example.", Dnsruby::Types.DS)

    assert_equal(1, result.answer.count {|rr| rr.type == Dnsruby::Types.DS })
    #  DS comes from the parent; the child zone servers are never asked.
    assert(world.log.none? {|zone, _, _| zone == "svc.example." })
    assert(world.log.include?(["example.", "svc.example.", "DS"]))
  end

  def test_alias_at_minimised_step_continues_with_full_qname
    world = FakeAuthWorld.new
    world.add_zone(".", :servers => [ROOT_IP],
      :delegations => { "example." => { "ns1.example." => EXAMPLE_IP } })
    world.add_zone("example.", :servers => [EXAMPLE_IP],
      :records => {
        "svc.example." => { "CNAME" => ["svc2.example."] },
        "www.svc2.example." => { "A" => ["203.0.113.9"] },
      })
    rec = make_recursor(world, true)
    result = rec.query_no_validation_or_recursion("www.svc.example.", Dnsruby::Types.A)

    assert_equal(["203.0.113.9"],
      result.answer.select {|rr| rr.type == Dnsruby::Types.A }.map {|rr| rr.address.to_s })
    #  The minimised probe hit the alias; the same level was then asked
    #  the full QNAME, since the name provably belongs to that zone.
    assert_equal([
      [".", "example.", "A"],
      ["example.", "svc.example.", "A"],
      ["example.", "www.svc.example.", "A"],
    ], world.log)
  end

  def test_nxdomain_at_minimised_step_terminates_lookup
    legacy_world = build_world
    legacy = make_recursor(legacy_world, false)
    legacy_result = legacy.query_no_validation_or_recursion("www.gone.example.", Dnsruby::Types.A)

    world = build_world
    rec = make_recursor(world, true)
    result = rec.query_no_validation_or_recursion("www.gone.example.", Dnsruby::Types.A)

    assert_equal("NXDOMAIN", result.rcode.to_s)
    assert_equal(legacy_result.rcode.to_s, result.rcode.to_s)
    #  Resolution stopped at the NXDOMAIN: no further levels were asked.
    assert_equal([
      [".", "example.", "A"],
      ["example.", "gone.example.", "A"],
    ], world.log)
  end

  def test_nodata_at_minimised_step_continues_with_full_qname
    world = FakeAuthWorld.new
    world.add_zone(".", :servers => [ROOT_IP],
      :delegations => { "example." => { "ns1.example." => EXAMPLE_IP } })
    world.add_zone("example.", :servers => [EXAMPLE_IP],
      :records => {
        "svc.example." => { "TXT" => ['"v=spf1"'] },
        "www.svc.example." => { "A" => ["203.0.113.10"] },
      })
    rec = make_recursor(world, true)
    result = rec.query_no_validation_or_recursion("www.svc.example.", Dnsruby::Types.A)

    assert_equal(["203.0.113.10"], result.answer.map {|rr| rr.address.to_s })
    #  The NODATA response to the minimised probe told us the full QNAME
    #  belongs to this zone, so it was asked of the same level.
    assert_equal([
      [".", "example.", "A"],
      ["example.", "svc.example.", "A"],
      ["example.", "www.svc.example.", "A"],
    ], world.log)
  end

  def test_incompatible_server_with_fallback_enabled
    world = build_world
    #  The example. servers fail minimised probes with FORMERR.
    world.zone("example.").formerr_on = ->(qname, qtype) { qname == "svc.example." && qtype == "A" }
    rec = make_recursor(world, true)
    result = rec.query_no_validation_or_recursion("www.app.svc.example.", Dnsruby::Types.A)

    assert_equal(["203.0.113.7"], result.answer.map {|rr| rr.address.to_s })
    #  After the FORMERR, the level was retried with the full QNAME.
    assert_equal([
      [".", "example.", "A"],
      ["example.", "svc.example.", "A"],
      ["example.", "www.app.svc.example.", "A"],
      ["svc.example.", "app.svc.example.", "A"],
      ["app.svc.example.", "www.app.svc.example.", "A"],
    ], world.log)
  end

  def test_incompatible_server_with_fallback_disabled
    world = build_world
    world.zone("example.").formerr_on = ->(qname, qtype) { qname == "svc.example." && qtype == "A" }
    rec = make_recursor(world, true)
    rec.qname_minimise_fallback = false
    result = rec.query_no_validation_or_recursion("www.app.svc.example.", Dnsruby::Types.A)

    assert_nil(result)
    assert_match(/QNAME minimisation/, rec.errorstring)
    #  The full QNAME was never revealed to the incompatible level.
    assert(world.log.none? {|_, qname, _| qname == "www.app.svc.example." })
    assert_equal([
      [".", "example.", "A"],
      ["example.", "svc.example.", "A"],
    ], world.log)
  end
end
