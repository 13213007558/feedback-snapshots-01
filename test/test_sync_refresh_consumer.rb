# -*- ruby encoding: utf-8 -*-
require_relative "test_helper"
require_relative "sync_protocol_helper"

class TestSyncRefreshConsumer < Test::Unit::TestCase
  include SyncProtocolHelper

  MESSAGE_ID = 1

  def setup
    @u1 = uuid(1)
    @u2 = uuid(2)
    @u3 = uuid(3)
    @u4 = uuid(4)

    @previous = {
      @u1 => entry("cn=one", "cn" => "one", "mail" => "one@example.com"),
      @u2 => entry("cn=two", "cn" => "two"),
      @u3 => entry("cn=three", "cn" => "three"),
    }
  end

  def feed(consumer, *bytes_list)
    bytes_list.each { |bytes| consumer.process(parse_pdu(bytes)) }
  end

  # Initial content poll: every entry arrives as state add, then a present
  # (refreshDeletes=FALSE) Sync Done.
  def test_initial_content_poll_materials_full_snapshot
    consumer = Net::LDAP::Sync::RefreshConsumer.new({})

    feed(
      consumer,
      entry_pdu(MESSAGE_ID, "cn=one", Net::LDAP::Sync::STATE_ADD, @u1, "cn" => "one"),
      entry_pdu(MESSAGE_ID, "cn=two", Net::LDAP::Sync::STATE_ADD, @u2, "cn" => "two"),
      done_pdu(MESSAGE_ID, cookie: "ck-1", refresh_deletes: false),
    )

    result = consumer.result
    assert consumer.finished?
    assert_equal [@u1, @u2].sort, result.entries.keys.sort
    assert_equal "ck-1", result.cookie
    assert_equal false, result.refresh_deletes
    assert_equal [@u1, @u2].sort, result.changelog[:add].sort
    assert_empty result.changelog[:delete]
  end

  # Present-phase incremental poll:
  #   u1 modified (add), u2 present, u3 absent -> deleted implicitly.
  def test_present_phase_deletes_unmentioned_entries
    consumer = Net::LDAP::Sync::RefreshConsumer.new(@previous)

    feed(
      consumer,
      entry_pdu(MESSAGE_ID, "cn=one", Net::LDAP::Sync::STATE_ADD, @u1, "cn" => "one-v2"),
      entry_pdu(MESSAGE_ID, "cn=two", Net::LDAP::Sync::STATE_PRESENT, @u2),
      done_pdu(MESSAGE_ID, cookie: "ck-2", refresh_deletes: false),
    )

    result = consumer.result
    assert_equal [@u1, @u2].sort, result.entries.keys.sort
    assert_equal "one-v2", result.entries[@u1][:cn].first
    assert_equal @previous[@u2].object_id, result.entries[@u2].object_id
    assert_equal [@u1], result.changelog[:add]
    assert_equal [@u2], result.changelog[:present]
    assert_equal [@u3].sort, (@previous.keys - result.entries.keys)
  end

  # Delete-phase incremental poll: explicit delete messages; everything not
  # named survives. Add/modify of changed entries is allowed in either mode.
  def test_delete_phase_keeps_unmentioned_entries
    consumer = Net::LDAP::Sync::RefreshConsumer.new(@previous)

    feed(
      consumer,
      entry_pdu(MESSAGE_ID, "", Net::LDAP::Sync::STATE_DELETE, @u3),
      done_pdu(MESSAGE_ID, cookie: "ck-3", refresh_deletes: true),
    )

    result = consumer.result
    assert_equal [@u1, @u2].sort, result.entries.keys.sort
    assert_equal @previous[@u1].object_id, result.entries[@u1].object_id
    assert_equal @previous[@u2].object_id, result.entries[@u2].object_id
    assert_equal [@u3], result.changelog[:delete]
  end

  # Two-phase present -> delete, delimited by refreshPresent refreshDone=FALSE.
  def test_two_phase_present_then_delete
    consumer = Net::LDAP::Sync::RefreshConsumer.new(@previous)

    feed(
      consumer,
      # present phase: u1 changed, u2 confirmed present; u3 not named here
      entry_pdu(MESSAGE_ID, "cn=one", Net::LDAP::Sync::STATE_ADD, @u1, "cn" => "one-v2"),
      entry_pdu(MESSAGE_ID, "cn=two", Net::LDAP::Sync::STATE_PRESENT, @u2),
      info_pdu(MESSAGE_ID, sync_info_refresh_present(cookie: "ck-mid", refresh_done: false)),
      # delete phase: u3 explicitly deleted
      entry_pdu(MESSAGE_ID, "", Net::LDAP::Sync::STATE_DELETE, @u3),
      done_pdu(MESSAGE_ID, cookie: "ck-4", refresh_deletes: true),
    )

    result = consumer.result
    assert_equal [@u1, @u2].sort, result.entries.keys.sort
    assert_equal "one-v2", result.entries[@u1][:cn].first
    assert_equal [@u3], result.changelog[:delete]
    assert_equal "ck-4", result.cookie
    assert_include consumer.cookies, "ck-mid"
  end

  # Coalesced syncIdSet messages for present and delete UUIDs.
  def test_sync_id_set_coalescing
    consumer = Net::LDAP::Sync::RefreshConsumer.new(@previous)

    feed(
      consumer,
      entry_pdu(MESSAGE_ID, "cn=one", Net::LDAP::Sync::STATE_ADD, @u1, "cn" => "one-v2"),
      info_pdu(MESSAGE_ID, sync_info_id_set(refresh_deletes: false, uuids: [@u2])),
      info_pdu(MESSAGE_ID, sync_info_refresh_present(refresh_done: false)),
      info_pdu(MESSAGE_ID, sync_info_id_set(refresh_deletes: true, uuids: [@u3])),
      done_pdu(MESSAGE_ID, cookie: "ck-5", refresh_deletes: true),
    )

    result = consumer.result
    assert_equal [@u1, @u2].sort, result.entries.keys.sort
    assert_equal [@u2], result.changelog[:present]
    assert_equal [@u3], result.changelog[:delete]
  end

  def test_newcookie_info_message_is_accepted_and_recorded
    consumer = Net::LDAP::Sync::RefreshConsumer.new(@previous)

    feed(
      consumer,
      info_pdu(MESSAGE_ID, sync_info_newcookie("ck-early")),
      entry_pdu(MESSAGE_ID, "cn=two", Net::LDAP::Sync::STATE_PRESENT, @u2),
      done_pdu(MESSAGE_ID, cookie: "ck-final", refresh_deletes: false),
    )

    assert_include consumer.cookies, "ck-early"
    assert_equal "ck-final", consumer.result.cookie
  end

  def test_empty_present_refresh_yields_empty_snapshot
    consumer = Net::LDAP::Sync::RefreshConsumer.new(@previous)

    feed(consumer, done_pdu(MESSAGE_ID, cookie: "ck-empty", refresh_deletes: false))

    assert_empty consumer.result.entries
  end

  def test_empty_delete_refresh_keeps_everything
    consumer = Net::LDAP::Sync::RefreshConsumer.new(@previous)

    feed(consumer, done_pdu(MESSAGE_ID, cookie: "ck-empty", refresh_deletes: true))

    assert_equal @previous.keys.sort, consumer.result.entries.keys.sort
  end

  # ---- Failure handling: nothing may be published ----

  def test_truncated_stream_raises_and_keeps_result_unavailable
    consumer = Net::LDAP::Sync::RefreshConsumer.new(@previous)

    feed(
      consumer,
      entry_pdu(MESSAGE_ID, "cn=one", Net::LDAP::Sync::STATE_ADD, @u1, "cn" => "x"),
    )

    assert_raise(Net::LDAP::Sync::IncompleteRefreshError) { consumer.result }
    refute consumer.finished?
  end

  def test_non_success_result_code_aborts_without_snapshot
    consumer = Net::LDAP::Sync::RefreshConsumer.new(@previous)

    assert_raise(Net::LDAP::Sync::IncompleteRefreshError) do
      feed(
        consumer,
        entry_pdu(MESSAGE_ID, "cn=two", Net::LDAP::Sync::STATE_PRESENT, @u2),
        result_pdu(MESSAGE_ID, Net::LDAP::ResultCodeUnwillingToPerform, "busy"),
      )
    end

    refute consumer.finished?
    assert_raise(Net::LDAP::Sync::IncompleteRefreshError) { consumer.result }
  end

  def test_sync_refresh_required_raises_refresh_required_error
    consumer = Net::LDAP::Sync::RefreshConsumer.new(@previous)

    error = assert_raise(Net::LDAP::Sync::RefreshRequiredError) do
      feed(
        consumer,
        entry_pdu(MESSAGE_ID, "cn=two", Net::LDAP::Sync::STATE_PRESENT, @u2),
        done_pdu(MESSAGE_ID, result_code: Net::LDAP::Sync::RESULT_SYNC_REFRESH_REQUIRED,
                            cookie: "ck-reload"),
      )
    end

    assert_equal "ck-reload", error.cookie
    refute consumer.finished?
  end

  def test_success_without_sync_done_control_is_rejected
    consumer = Net::LDAP::Sync::RefreshConsumer.new(@previous)

    assert_raise(Net::LDAP::Sync::ProtocolError) do
      feed(consumer, result_pdu(MESSAGE_ID, Net::LDAP::ResultCodeSuccess))
    end
  end

  def test_contradictory_duplicate_verdict_in_one_phase_is_rejected
    consumer = Net::LDAP::Sync::RefreshConsumer.new(@previous)

    assert_raise(Net::LDAP::Sync::ProtocolError) do
      feed(
        consumer,
        entry_pdu(MESSAGE_ID, "cn=two", Net::LDAP::Sync::STATE_PRESENT, @u2),
        entry_pdu(MESSAGE_ID, "", Net::LDAP::Sync::STATE_DELETE, @u2),
        done_pdu(MESSAGE_ID, cookie: "ck", refresh_deletes: false),
      )
    end
  end

  def test_delete_phase_without_boundary_is_rejected
    consumer = Net::LDAP::Sync::RefreshConsumer.new(@previous)

    assert_raise(Net::LDAP::Sync::ProtocolError) do
      feed(
        consumer,
        entry_pdu(MESSAGE_ID, "cn=two", Net::LDAP::Sync::STATE_PRESENT, @u2),
        entry_pdu(MESSAGE_ID, "", Net::LDAP::Sync::STATE_DELETE, @u3),
        done_pdu(MESSAGE_ID, cookie: "ck", refresh_deletes: true),
      )
    end
  end

  def test_terminal_control_phase_mismatch_is_rejected
    consumer = Net::LDAP::Sync::RefreshConsumer.new(@previous)

    assert_raise(Net::LDAP::Sync::ProtocolError) do
      feed(
        consumer,
        entry_pdu(MESSAGE_ID, "", Net::LDAP::Sync::STATE_DELETE, @u3),
        done_pdu(MESSAGE_ID, cookie: "ck", refresh_deletes: false),
      )
    end
  end

  def test_refresh_present_done_true_in_refresh_only_is_rejected
    consumer = Net::LDAP::Sync::RefreshConsumer.new(@previous)

    assert_raise(Net::LDAP::Sync::ProtocolError) do
      feed(
        consumer,
        info_pdu(MESSAGE_ID, sync_info_refresh_present(refresh_done: true)),
        done_pdu(MESSAGE_ID, cookie: "ck", refresh_deletes: false),
      )
    end
  end

  def test_present_for_unknown_uuid_is_rejected
    consumer = Net::LDAP::Sync::RefreshConsumer.new(@previous)

    assert_raise(Net::LDAP::Sync::ProtocolError) do
      feed(
        consumer,
        entry_pdu(MESSAGE_ID, "cn=new", Net::LDAP::Sync::STATE_PRESENT, @u4),
        done_pdu(MESSAGE_ID, cookie: "ck", refresh_deletes: false),
      )
    end
  end

  def test_previous_mirror_is_not_mutated
    previous = @previous.dup
    consumer = Net::LDAP::Sync::RefreshConsumer.new(previous)

    feed(
      consumer,
      entry_pdu(MESSAGE_ID, "", Net::LDAP::Sync::STATE_DELETE, @u3),
      done_pdu(MESSAGE_ID, cookie: "ck", refresh_deletes: true),
    )

    assert_equal [@u1, @u2, @u3].sort, previous.keys.sort
    assert_equal "one", previous[@u1][:cn].first
  end
end

class TestSyncRefreshConsumerCrossPhase < Test::Unit::TestCase
  include SyncProtocolHelper

  MESSAGE_ID = 1

  def test_uuid_present_then_deleted_across_phases_resolves_to_delete
    u1 = uuid(1)
    u2 = uuid(2)
    previous = {
      u1 => entry("cn=one", "cn" => "one"),
      u2 => entry("cn=two", "cn" => "two"),
    }
    consumer = Net::LDAP::Sync::RefreshConsumer.new(previous)

    # u2 confirmed present in the present phase, then deleted in the delete
    # phase. Per RFC 4533 this is a legal cross-phase sequence and must
    # resolve to a single delete verdict without raising.
    [
      entry_pdu(MESSAGE_ID, "cn=one", Net::LDAP::Sync::STATE_PRESENT, u1),
      entry_pdu(MESSAGE_ID, "cn=two", Net::LDAP::Sync::STATE_PRESENT, u2),
      info_pdu(MESSAGE_ID, sync_info_refresh_present(refresh_done: false)),
      entry_pdu(MESSAGE_ID, "", Net::LDAP::Sync::STATE_DELETE, u2),
      done_pdu(MESSAGE_ID, cookie: "ck", refresh_deletes: true),
    ].each { |bytes| consumer.process(parse_pdu(bytes)) }

    result = consumer.result
    assert_equal [u1], result.entries.keys
    assert_equal [u2], result.changelog[:delete]
    assert_equal [u1], result.changelog[:present]
  end
end

class TestSyncRefreshConsumerProtocolGuards < Test::Unit::TestCase
  include SyncProtocolHelper

  MESSAGE_ID = 1

  def build(previous = {})
    Net::LDAP::Sync::RefreshConsumer.new(previous)
  end

  def test_refresh_delete_info_is_rejected_in_refresh_only
    consumer = build
    pdu = parse_pdu(info_pdu(MESSAGE_ID, sync_info_refresh_delete(refresh_done: true)))

    assert_raise(Net::LDAP::Sync::ProtocolError) { consumer.process(pdu) }
  end

  def test_empty_sync_id_set_is_a_noop
    u1 = uuid(1)
    previous = { u1 => entry("cn=one", "cn" => "one") }
    consumer = build(previous)

    [
      info_pdu(MESSAGE_ID, sync_info_id_set(refresh_deletes: false, uuids: [])),
      entry_pdu(MESSAGE_ID, "cn=one", Net::LDAP::Sync::STATE_PRESENT, u1),
      done_pdu(MESSAGE_ID, cookie: "ck", refresh_deletes: false),
    ].each { |bytes| consumer.process(parse_pdu(bytes)) }

    assert_equal [u1], consumer.result.entries.keys
  end

  def test_modify_state_is_recorded_in_changelog
    u1 = uuid(1)
    previous = { u1 => entry("cn=one", "cn" => "old") }
    consumer = build(previous)

    [
      entry_pdu(MESSAGE_ID, "cn=one", Net::LDAP::Sync::STATE_MODIFY, u1, "cn" => "new"),
      done_pdu(MESSAGE_ID, cookie: "ck", refresh_deletes: false),
    ].each { |bytes| consumer.process(parse_pdu(bytes)) }

    assert_equal [u1], consumer.result.changelog[:modify]
    assert_equal "new", consumer.result.entries[u1][:cn].first
  end

  def test_delete_for_unknown_uuid_is_rejected
    consumer = build({ uuid(1) => entry("cn=one") })

    assert_raise(Net::LDAP::Sync::ProtocolError) do
      consumer.process(parse_pdu(
        entry_pdu(MESSAGE_ID, "", Net::LDAP::Sync::STATE_DELETE, uuid(7))
      ))
    end
  end
end
