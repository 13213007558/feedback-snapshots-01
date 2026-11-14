require_relative 'spec_helper'

# Offline tests for ServiceBindingSelector, the RFC 9460 section 3 client
# resolution procedure over an already-authenticated SVCB/HTTPS answer chain.
class TestServiceBindingSelector < Minitest::Test
  ORIGIN = 'example.com.'.freeze

  # Builds a typed record under an explicit owner so alias hops each carry
  # their own owner name, as RFC 9460 section 2.4 requires.
  def rr(owner, rdata, type = 'HTTPS')
    Dnsruby::RR.create("#{owner} 300 IN #{type} #{rdata}")
  end

  def selector(**options)
    Dnsruby::ServiceBindingSelector.new(**{ alpn: %w[h3 h2 http/1.1] }.merge(options))
  end

  def test_usable_chain_returns_priority_ordered_plans
    chain = [[
      rr(ORIGIN, '2 backup.example. alpn=h2 port=8443'),
      rr(ORIGIN, '1 . alpn=h2,h3 port=9000 ipv4hint=192.0.2.1,192.0.2.2 ipv6hint=2001:db8::1'),
    ]]
    selection = selector.select(chain)

    assert_equal(:usable, selection.status)
    assert(selection.usable?)
    assert(selection.fallback_allowed? == false)
    assert_equal([1, 2], selection.plans.map { |plan| plan.record.priority })

    first = selection.plans.first
    assert_equal(9000, first.port)
    assert_equal(%w[h3 h2], first.alpn, 'caller preference order is retained')
    assert_equal(%w[192.0.2.1 192.0.2.2], first.ipv4_hints)
    assert_equal(%w[2001:DB8::1], first.ipv6_hints)
    assert_nil(first.ech)
    assert_equal(false, first.ech?)
  end

  def test_equal_priority_candidates_keep_chain_order
    chain = [[
      rr(ORIGIN, '1 a.example. alpn=h2'),
      rr(ORIGIN, '1 b.example. alpn=h2'),
      rr(ORIGIN, '1 c.example. alpn=h2'),
    ]]
    plans = selector.select(chain).plans
    assert_equal(%w[a.example. b.example. c.example.],
                 plans.map { |plan| plan.target_name.to_s(true) })
  end

  def test_default_port_and_dot_target_use_the_owner
    plan = selector.select([[rr(ORIGIN, '1 . alpn=h2')]]).plans.first
    assert_equal(443, plan.port)
    assert_equal(ORIGIN, plan.target_name.to_s(true))
    assert_equal(ORIGIN, plan.server_name.to_s(true))
  end

  def test_explicit_default_port_is_honoured
    plan = selector(default_port: 8443).select([[rr(ORIGIN, '1 . alpn=h2')]]).plans.first
    assert_equal(8443, plan.port)
  end

  def test_alpn_default_set_applies_without_an_alpn_param
    # No alpn SvcParam: the HTTPS default (http/1.1) is offered.
    plan = selector.select([[rr(ORIGIN, '1 .')]]).plans.first
    assert_equal(['http/1.1'], plan.alpn)
  end

  def test_no_default_alpn_suppresses_the_default_set
    chain = [[rr(ORIGIN, '1 . alpn=h2 no-default-alpn')]]
    assert_equal(%w[h2], selector.select(chain).plans.first.alpn)

    # A caller that only speaks the suppressed default now has no intersection.
    selection = selector(alpn: %w[http/1.1]).select(chain)
    assert_equal(:no_compatible_candidate, selection.status)
    assert_equal(:no_alpn_match, selection.rejections.first.reason)
  end

  def test_all_alpn_mismatch_is_no_compatible_candidate_with_fallback
    chain = [[rr(ORIGIN, '1 . alpn=foo,bar')]]
    selection = selector(alpn: %w[h2]).select(chain)

    assert_equal(:no_compatible_candidate, selection.status)
    assert(selection.fallback_allowed?)
    assert_equal(false, selection.downgrade_forbidden?)
    assert_equal(:no_alpn_match, selection.rejections.first.reason)
    assert_includes(selection.rejections.first.message, 'ALPN')
  end

  def test_unsupported_mandatory_key_rejects_and_names_the_key
    chain = [[rr(ORIGIN, '1 . alpn=h2 mandatory=key123 key123=abc')]]
    selection = selector.select(chain)

    assert_equal(:no_compatible_candidate, selection.status)
    rejection = selection.rejections.first
    assert_equal(:unsupported_mandatory, rejection.reason)
    assert_equal([123], rejection.unsupported_keys)
    assert_includes(rejection.message, 'key123')
  end

  def test_known_mandatory_key_becomes_supported_when_caller_understands_it
    # ech is mandatory; a caller listing key 5 among its supported keys is fine.
    chain = [[rr(ORIGIN, '1 . alpn=h2 ech=AQID mandatory=ech')]]
    selection = selector(supported_keys: [0, 1, 2, 3, 4, 5, 6, 7, 8, 10]).select(chain)
    assert_equal(:usable, selection.status)
    assert(selection.plans.first.ech?)
  end

  def test_automatically_mandatory_https_port_is_gated
    # A caller that does not understand port (key 3) must ignore the RR even
    # though no explicit mandatory SvcParam names it (RFC 9460 section 9).
    chain = [[rr(ORIGIN, '1 . alpn=h2 port=9000')]]
    selection = selector(supported_keys: [1, 2]).select(chain)
    assert_equal(:no_compatible_candidate, selection.status)
    rejection = selection.rejections.first
    assert_equal(:unsupported_mandatory, rejection.reason)
    assert_includes(rejection.unsupported_keys, 3)
  end

  def test_svcb_record_has_no_https_automatic_mandatory_keys
    # The generic SVCB mapping does not make port automatically mandatory.
    chain = [[rr(ORIGIN, '1 . alpn=h2 port=9000', 'SVCB')]]
    selection = selector(supported_keys: [1, 2]).select(chain)
    assert_equal(:usable, selection.status)
    assert_equal(9000, selection.plans.first.port)
  end

  def test_ech_required_forbids_downgrade_when_no_candidate_offers_ech
    chain = [[
      rr(ORIGIN, '1 . alpn=h2'),
      rr(ORIGIN, '2 other.example. alpn=h3'),
    ]]
    selection = selector(require_ech: true).select(chain)

    assert_equal(:downgrade_forbidden, selection.status)
    assert(selection.downgrade_forbidden?)
    assert_equal(false, selection.fallback_allowed?)
    assert(selection.plans.empty?)
    assert_equal([:ech_required, :ech_required], selection.rejections.map(&:reason))
  end

  def test_ech_required_still_selects_an_ech_candidate
    chain = [[
      rr(ORIGIN, '1 . alpn=h2 ech=AQID'),
      rr(ORIGIN, '2 plain.example. alpn=h2'),
    ]]
    selection = selector(require_ech: true).select(chain)

    assert_equal(:usable, selection.status)
    assert_equal(1, selection.plans.length)
    assert(selection.plans.first.ech?)
    assert_equal(:ech_required, selection.rejections.first.reason)
  end

  def test_mandatory_gate_runs_before_alpn_and_ech_gates
    chain = [[rr(ORIGIN, '1 . alpn=foo mandatory=key123 key123=abc')]]
    selection = selector(alpn: %w[h2], require_ech: true).select(chain)
    assert_equal(:unsupported_mandatory, selection.rejections.first.reason)
  end

  def test_alias_mode_followed_to_service_mode_keeps_origin_identity
    chain = [
      [rr(ORIGIN, '0 svc.example.net.')],
      [rr('svc.example.net.', '1 . alpn=h2 port=8443 ipv4hint=192.0.2.9')],
    ]
    selection = selector.select(chain)

    assert_equal(:usable, selection.status)
    assert_equal(['svc.example.net.'], selection.alias_path.map { |name| name.to_s(true) })
    plan = selection.plans.first
    assert_equal('svc.example.net.', plan.target_name.to_s(true))
    assert_equal(ORIGIN, plan.server_name.to_s(true), 'SNI and certificate validation stay on the origin')
    assert_equal(%w[192.0.2.9], plan.ipv4_hints)
  end

  def test_alias_with_explicit_target_resolves_that_target_but_authenticates_origin
    chain = [
      [rr(ORIGIN, '0 pool.example.net.')],
      [rr('pool.example.net.', '1 edge.example.org. alpn=h2')],
    ]
    plan = selector.select(chain).plans.first
    assert_equal('edge.example.org.', plan.target_name.to_s(true))
    assert_equal(ORIGIN, plan.server_name.to_s(true))
  end

  def test_address_hints_never_replace_the_authenticated_name
    plan = selector.select([[
      rr(ORIGIN, '1 evil-target.example. alpn=h2 ipv4hint=198.51.100.7 ipv6hint=2001:db8::7'),
    ]]).plans.first
    assert_equal('evil-target.example.', plan.target_name.to_s(true))
    assert_equal(ORIGIN, plan.server_name.to_s(true))
    assert_includes(plan.ipv4_hints, '198.51.100.7')
  end

  def test_alias_target_of_root_means_unavailable
    selection = selector.select([[rr(ORIGIN, '0 .')]])
    assert_equal(:alias_unavailable, selection.status)
    assert(selection.fallback_allowed?)
    assert(selection.plans.empty?)
  end

  def test_alias_loop_is_detected
    # Both AliasMode RRs are owned by the same name, so the second hop
    # revisits an owner the chain already processed.
    chain = [
      [rr(ORIGIN, '0 www.example.com.')],
      [rr(ORIGIN, '0 www.example.com.')],
    ]
    assert_equal(:alias_loop, selector.select(chain).status)
  end

  def test_alias_chain_limit_is_enforced
    chain = Array.new(Dnsruby::ServiceBindingSelector::MAX_ALIAS_REDIRECTS + 1) do |index|
      [rr("hop#{index}.example.", "0 hop#{index + 1}.example.")]
    end
    assert_equal(:alias_limit, selector.select(chain).status)
  end

  def test_alias_without_a_following_group_is_a_missing_target
    selection = selector.select([[rr(ORIGIN, '0 gone.example.net.')]])
    assert_equal(:missing_alias_target, selection.status)
    assert(selection.fallback_allowed?)
  end

  def test_flat_record_array_is_treated_as_one_group
    records = [rr(ORIGIN, '1 . alpn=h2'), rr(ORIGIN, '2 b.example. alpn=h3')]
    selection = selector.select(records)
    assert_equal(:usable, selection.status)
    assert_equal([1, 2], selection.plans.map { |plan| plan.record.priority })
  end

  def test_empty_chain_has_no_records
    assert_equal(:no_records, selector.select([]).status)
    assert_equal(:no_records, selector.select(nil).status)
  end

  def test_non_svcb_records_are_ignored
    chain = [[
      Dnsruby::RR.create("#{ORIGIN} 300 IN A 192.0.2.1"),
      rr(ORIGIN, '1 . alpn=h2'),
    ]]
    assert_equal(:usable, selector.select(chain).status)
  end

  def test_each_rejected_candidate_is_reported
    chain = [[
      rr(ORIGIN, '1 . alpn=foo'),
      rr(ORIGIN, '2 . alpn=h2 mandatory=key9 key9=x'),
      rr(ORIGIN, '3 . alpn=h3'),
    ]]
    selection = selector(alpn: %w[h3]).select(chain)
    assert_equal(:usable, selection.status)
    reasons = selection.rejections.map(&:reason).sort
    assert_equal(%i[no_alpn_match unsupported_mandatory], reasons)
    assert_equal(2, selection.rejections.length)
  end
end
