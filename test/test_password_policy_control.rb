require_relative 'test_helper'

# Unit tests for the Password Policy Response control (draft-behera).
#
# Every test builds a real BER-encoded LDAPMessage, parses it with the same
# Net::LDAP::AsnSyntax the socket reader uses, and hands the resulting object
# to Net::LDAP::PDU, so the assertions exercise the actual wire decoding
# path rather than hand-constructed Ruby arrays.
class TestPasswordPolicyControl < Test::Unit::TestCase
  OID = Net::LDAP::LDAPControls::PASSWORD_POLICY_RESPONSE

  # Encode a context-specific INTEGER TLV (0x80..0x82) as used inside the
  # ppolicy control value.
  def context_integer(tag_number, value)
    encoded = value.to_ber.dup
    encoded.setbyte(0, 0x80 + tag_number)
    encoded
  end

  # The control value is an OCTET STRING wrapping the
  # PasswordPolicyResponseValue SEQUENCE.
  def policy_value(*elements)
    elements.to_ber_sequence.to_s.to_ber
  end

  def policy_control(elements, oid = OID, criticality = false)
    [oid.to_ber, criticality.to_ber, elements].to_ber_sequence
  end

  # Build and parse a full BindResponse LDAPMessage. +controls+ is an array
  # of already-encoded control sequences.
  def bind_pdu(result_code, controls = nil)
    bind_result = [
      result_code.to_ber_enumerated,
      "".to_ber,
      "".to_ber,
    ].to_ber_appsequence(Net::LDAP::PDU::BindResult)

    message_parts = [1.to_ber, bind_result]
    message_parts << controls.to_ber_contextspecific(0) if controls
    wire = message_parts.to_ber_sequence

    ber_object = wire.read_ber(Net::LDAP::AsnSyntax)
    Net::LDAP::PDU.new(ber_object)
  end

  # Parser-level tests -----------------------------------------------------

  def test_parses_time_before_expiration_warning
    pdu = bind_pdu(Net::LDAP::ResultCodeSuccess,
                   [policy_control(policy_value(context_integer(0, 300)))])
    policy = pdu.password_policy_response

    assert_not_nil policy
    assert_equal 300, policy.time_before_expiration
    assert policy.time_before_expiration?
    assert policy.warning?
    refute policy.error?
    refute policy.malformed?
  end

  def test_parses_grace_authn_remaining_warning
    pdu = bind_pdu(Net::LDAP::ResultCodeInvalidCredentials,
                   [policy_control(policy_value(context_integer(1, 3)))])
    policy = pdu.password_policy_response

    assert_equal 3, policy.grace_authn_remaining
    assert policy.grace_authn_remaining?
    assert policy.warning?
    refute policy.error?
  end

  def test_parses_all_error_codes
    expected = {
      0 => :passwordExpired,
      1 => :accountLocked,
      2 => :changeAfterReset,
      3 => :passwordModNotAllowed,
      4 => :mustSupplyOldPassword,
      5 => :insufficientPasswordQuality,
      6 => :passwordTooShort,
      7 => :passwordTooYoung,
      8 => :passwordInHistory,
    }

    expected.each do |number, name|
      pdu = bind_pdu(Net::LDAP::ResultCodeInvalidCredentials,
                     [policy_control(policy_value(context_integer(2, number)))])
      policy = pdu.password_policy_response

      assert_equal number, policy.error_code
      assert_equal name, policy.error
      assert policy.error?
      assert_not_nil policy.error_message
    end
  end

  def test_unknown_error_code_renders_generic_message
    pdu = bind_pdu(Net::LDAP::ResultCodeInvalidCredentials,
                   [policy_control(policy_value(context_integer(2, 99)))])
    policy = pdu.password_policy_response

    assert_equal 99, policy.error_code
    assert_nil policy.error
    assert_match(/99/, policy.error_message)
  end

  def test_empty_sequence_value_is_not_malformed
    pdu = bind_pdu(Net::LDAP::ResultCodeSuccess,
                   [policy_control(policy_value)])
    policy = pdu.password_policy_response

    assert_not_nil policy
    refute policy.malformed?
    refute policy.warning?
    refute policy.error?
  end

  def test_malformed_value_does_not_raise
    pdu = bind_pdu(Net::LDAP::ResultCodeInvalidCredentials,
                   [policy_control("not-a-sequence".to_ber)])
    policy = pdu.password_policy_response

    assert_not_nil policy
    assert policy.malformed?
    assert_nil policy.time_before_expiration
    assert_nil policy.grace_authn_remaining
    assert_nil policy.error_code
  end

  def test_truncated_value_is_malformed
    truncated = "\x30\x05\x80\x02\x01".b
    pdu = bind_pdu(Net::LDAP::ResultCodeInvalidCredentials,
                   [policy_control(truncated.to_ber)])

    assert pdu.password_policy_response.malformed?
  end

  def test_control_without_value_still_exposes_policy
    # OID + criticality only, no value (legal per RFC 4511 controls grammar).
    control = [OID.to_ber, false.to_ber].to_ber_sequence
    pdu = bind_pdu(Net::LDAP::ResultCodeSuccess, [control])
    policy = pdu.password_policy_response

    assert_not_nil policy
    refute policy.malformed?
    assert_nil policy.error
  end

  # PDU-level tests --------------------------------------------------------

  def test_absent_control_is_not_reported
    pdu = bind_pdu(Net::LDAP::ResultCodeSuccess)

    assert_empty pdu.result_controls
    assert_nil pdu.password_policy_response
  end

  def test_unrelated_control_is_ignored
    pdu = bind_pdu(Net::LDAP::ResultCodeSuccess,
                   [policy_control(policy_value(context_integer(2, 0)), "1.2.3.4")])

    assert_nil pdu.password_policy_response
    assert_equal 1, pdu.result_controls.size
  end

  def test_duplicate_policy_controls_first_wins_and_is_counted
    first = policy_control(policy_value(context_integer(2, 0))) # passwordExpired
    second = policy_control(policy_value(context_integer(1, 2))) # grace warning
    pdu = bind_pdu(Net::LDAP::ResultCodeInvalidCredentials, [first, second])
    policy = pdu.password_policy_response

    assert_equal 1, policy.duplicate_controls
    assert_equal :passwordExpired, policy.error
  end

  def test_malformed_control_does_not_break_other_controls
    good = policy_control(policy_value(context_integer(0, 60)))
    pdu = bind_pdu(Net::LDAP::ResultCodeSuccess, [good])

    assert_equal 1, pdu.result_controls.size
    assert_equal 60, pdu.password_policy_response.time_before_expiration
  end

  def test_raw_malformed_controls_field_does_not_raise
    # A controls field that is itself malformed (not a sequence of controls)
    # must still parse into a PDU exposing the result code.
    bind_result = [
      Net::LDAP::ResultCodeInvalidCredentials.to_ber_enumerated,
      "".to_ber,
      "".to_ber,
    ].to_ber_appsequence(Net::LDAP::PDU::BindResult)
    wire = [1.to_ber, bind_result, "garbage".to_ber_contextspecific(0)].to_ber_sequence
    ber_object = wire.read_ber(Net::LDAP::AsnSyntax)
    pdu = Net::LDAP::PDU.new(ber_object)

    assert_equal Net::LDAP::ResultCodeInvalidCredentials, pdu.result_code
    assert pdu.result_controls.first.malformed
    assert_equal :failure, pdu.bind_status
  end

  # Status mapping ---------------------------------------------------------

  def test_successful_bind_without_policy_is_success
    pdu = bind_pdu(Net::LDAP::ResultCodeSuccess)
    assert_equal :success, pdu.bind_status
  end

  def test_failed_bind_without_control_is_failure
    pdu = bind_pdu(Net::LDAP::ResultCodeInvalidCredentials)
    assert_equal :failure, pdu.bind_status
  end

  def test_time_warning_on_success_is_warning
    pdu = bind_pdu(Net::LDAP::ResultCodeSuccess,
                   [policy_control(policy_value(context_integer(0, 300)))])
    assert_equal :warning, pdu.bind_status
  end

  def test_time_warning_on_error_result_is_still_failure
    pdu = bind_pdu(Net::LDAP::ResultCodeInvalidCredentials,
                   [policy_control(policy_value(context_integer(0, 300)))])
    assert_equal :failure, pdu.bind_status
  end

  def test_grace_warning_means_password_change_required
    pdu = bind_pdu(Net::LDAP::ResultCodeInvalidCredentials,
                   [policy_control(policy_value(context_integer(1, 3)))])
    assert_equal :password_change_required, pdu.bind_status
    assert pdu.password_policy_response.password_change_required?
  end

  def test_password_expired_requires_change_even_though_bind_is_rejected
    pdu = bind_pdu(Net::LDAP::ResultCodeInvalidCredentials,
                   [policy_control(policy_value(context_integer(2, 0)))])
    assert_equal :password_change_required, pdu.bind_status
  end

  def test_change_after_reset_requires_change
    pdu = bind_pdu(Net::LDAP::ResultCodeSuccess,
                   [policy_control(policy_value(context_integer(2, 2)))])
    assert_equal :password_change_required, pdu.bind_status
  end

  def test_account_locked_is_distinct
    pdu = bind_pdu(Net::LDAP::ResultCodeInvalidCredentials,
                   [policy_control(policy_value(context_integer(2, 1)))])
    assert_equal :account_locked, pdu.bind_status
  end

  def test_other_policy_errors_are_policy_error
    [3, 4, 5, 6, 7, 8].each do |code|
      pdu = bind_pdu(Net::LDAP::ResultCodeInvalidCredentials,
                     [policy_control(policy_value(context_integer(2, code)))])
      assert_equal :policy_error, pdu.bind_status, "error code #{code}"
    end
  end

  def test_warning_and_error_together_error_wins
    value = policy_value(context_integer(0, 300), context_integer(2, 0))
    pdu = bind_pdu(Net::LDAP::ResultCodeInvalidCredentials,
                   [policy_control(value)])
    policy = pdu.password_policy_response

    assert_equal 300, policy.time_before_expiration
    assert_equal :passwordExpired, policy.error
    assert_equal :password_change_required, pdu.bind_status
  end

  # Operation result hand-off ---------------------------------------------

  def test_get_operation_result_carries_policy_and_status
    ldap = Net::LDAP.new
    pdu = bind_pdu(Net::LDAP::ResultCodeInvalidCredentials,
                   [policy_control(policy_value(context_integer(2, 0)))])
    ldap.instance_variable_set(:@result, pdu)

    result = ldap.get_operation_result
    assert_equal Net::LDAP::ResultCodeInvalidCredentials, result.code
    assert_equal :password_change_required, result.bind_status
    assert_equal :passwordExpired, result.password_policy_response.error
  end

  def test_get_operation_result_without_policy
    ldap = Net::LDAP.new
    ldap.instance_variable_set(:@result, bind_pdu(Net::LDAP::ResultCodeSuccess))

    result = ldap.get_operation_result
    assert_nil result.password_policy_response
    assert_equal :success, result.bind_status
  end
end

# Exercises the multi-step SASL bind path to prove that only the final
# BindResponse (not intermediate saslBindInProgress messages) determines the
# password-policy login state handed back to the caller.
class TestPasswordPolicySASLBind < Test::Unit::TestCase
  OID = Net::LDAP::LDAPControls::PASSWORD_POLICY_RESPONSE

  def context_integer(tag_number, value)
    encoded = value.to_ber.dup
    encoded.setbyte(0, 0x80 + tag_number)
    encoded
  end

  def policy_value(*elements)
    elements.to_ber_sequence.to_s.to_ber
  end

  def policy_control(elements)
    [OID.to_ber, false.to_ber, elements].to_ber_sequence
  end

  # Build a parsed BindResponse BER object as the socket reader would hand
  # to Net::LDAP::PDU (the connection wraps it in a PDU itself).
  def bind_response(message_id, result_code, controls = nil)
    bind_result = [
      result_code.to_ber_enumerated,
      "".to_ber,
      "".to_ber,
    ].to_ber_appsequence(Net::LDAP::PDU::BindResult)

    parts = [message_id.to_ber, bind_result]
    parts << controls.to_ber_contextspecific(0) if controls
    wire = parts.to_ber_sequence
    wire.read_ber(Net::LDAP::AsnSyntax)
  end

  def test_only_final_sasl_response_policy_is_returned
    intermediate = bind_response(
      1,
      Net::LDAP::ResultCodeSaslBindInProgress,
      [policy_control(policy_value(context_integer(0, 10)))],
    )
    final = bind_response(
      1,
      Net::LDAP::ResultCodeInvalidCredentials,
      [policy_control(policy_value(context_integer(2, 0)))],
    )

    socket = flexmock("socket")
    socket.should_receive(:write)
    socket.should_receive(:read_ber).and_return(intermediate).and_return(final)

    connection = Net::LDAP::Connection.new(:socket => socket)
    result = connection.bind(
      method: :sasl,
      mechanism: "DIGEST-MD5",
      initial_credential: "initial",
      challenge_response: proc { |_challenge| "next-credential" },
    )

    # The adapter returns the final PDU, whose control drives the status.
    assert_equal Net::LDAP::ResultCodeInvalidCredentials, result.result_code
    assert_equal :passwordExpired, result.password_policy_response.error
    assert_equal :password_change_required, result.bind_status
  end

  def test_sasl_intermediate_without_policy_then_success
    intermediate = bind_response(1, Net::LDAP::ResultCodeSaslBindInProgress)
    final = bind_response(1, Net::LDAP::ResultCodeSuccess)

    socket = flexmock("socket")
    socket.should_receive(:write)
    socket.should_receive(:read_ber).and_return(intermediate).and_return(final)

    connection = Net::LDAP::Connection.new(:socket => socket)
    result = connection.bind(
      method: :sasl,
      mechanism: "DIGEST-MD5",
      initial_credential: "initial",
      challenge_response: proc { |_challenge| "next-credential" },
    )

    assert_nil result.password_policy_response
    assert_equal :success, result.bind_status
  end
end
