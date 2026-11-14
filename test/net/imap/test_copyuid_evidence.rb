# frozen_string_literal: true

require "net/imap"
require "test/unit"

class TestCopyUIDEvidence < Net::IMAP::TestCase
  CopyUIDEvidence = Net::IMAP::CopyUIDEvidence
  CopyUIDData     = Net::IMAP::CopyUIDData
  UINT32_MAX      = 2**32 - 1

  def export(response, mailbox: "Archive/2026")
    CopyUIDEvidence.export(source_mailbox: mailbox, response: response)
  end

  test "small real-format response: every pair matches hand annotation" do
    report = export(
      "A142 OK [COPYUID 38505 3955:3960,3962 4482:4487,4489] COPY completed"
    )
    assert_equal "Archive/2026", report.source_mailbox
    assert_equal "OK",           report.tagged_status
    assert_equal 38505,          report.uidvalidity
    assert_equal "3955:3960,3962", report.source_uid_set
    assert_equal "4482:4487,4489", report.assigned_uid_set
    # original interval order is preserved, not normalized
    assert_equal %w[3955:3960 3962], report.source_entries
    assert_equal %w[4482:4487 4489], report.assigned_entries
    assert_equal 7, report.source_count
    assert_equal 7, report.assigned_count
    assert_predicate report, :clean?
    assert_predicate report, :mapping_established?
    # hand-annotated expectation, checked pair by pair
    expected = {
      3955 => 4482,
      3956 => 4483,
      3957 => 4484,
      3958 => 4485,
      3959 => 4486,
      3960 => 4487,
      3962 => 4489,
    }
    assert_equal expected.size, report.mapping.message_count
    expected.each do |source_uid, assigned_uid|
      assert_includes report.mapping.each_pair.to_a,
                      [source_uid, assigned_uid]
    end
    assert_equal expected, report.mapping.each_pair.to_h
  end

  test "mapping agrees with net-imap ResponseParser and CopyUIDData" do
    text = "A142 OK [COPYUID 38505 3955:3960,3962 4482:4487,4489] Done\r\n"
    report = export(text)
    parsed = Net::IMAP::ResponseParser.new.parse(text)
    copyuid = parsed.data.code.data
    assert_instance_of CopyUIDData, copyuid
    assert_instance_of CopyUIDData, report.copy_uid_data
    assert_equal copyuid.each_uid_pair.to_a, report.mapping.each_pair.to_a
    assert_equal copyuid.uidvalidity, report.uidvalidity
  end

  test "untagged MOVE-style response is accepted" do
    report = export("* OK [COPYUID 38505 1:2 10:11] moved")
    assert_equal "OK", report.tagged_status
    assert_equal [[1, 10], [2, 11]], report.mapping.each_pair.to_a
  end

  test "declared order is preserved; sets are not sorted before pairing" do
    report = export("A1 OK [COPYUID 7 2,1 10,20] Done")
    # positional pairing in declared order: 2->10, 1->20.
    # sorting both sets first would wrongly yield 1->10, 2->20.
    assert_equal [[2, 10], [1, 20]], report.mapping.each_pair.to_a
    assert_equal %w[2 1], report.source_entries
  end

  test "reversed ranges are reported separately" do
    report = export("A1 OK [COPYUID 7 9:7 1:3] Done")
    findings = report.findings_by(:reversed_range)
    assert_equal 1, findings.size
    assert_equal :source, findings.first.side
    assert_equal ["9:7"], findings.first.detail[:entries]
    # mapping still follows net-imap's ascending-entry convention
    assert_equal [[7, 1], [8, 2], [9, 3]], report.mapping.each_pair.to_a
  end

  test "overlapping ranges are reported separately" do
    report = export("A1 OK [COPYUID 7 1:5,3:8 10:20] Done")
    findings = report.findings_by(:overlapping_ranges)
    assert_equal 1, findings.size
    assert_equal :source, findings.first.side
    assert_equal [["1:5", "3:8"]], findings.first.detail[:pairs]
    # overlap implies duplicates, reported as their own category
    duplicates = report.findings_by(:duplicate_uids)
    assert_equal 1, duplicates.size
    assert_equal 3, duplicates.first.detail[:duplicate_occurrences]
    assert_equal "3:5", duplicates.first.detail[:duplicated_uids]
    # positional mapping still established, split into aligned segments
    assert_equal [1..5, 3..8], report.mapping.segments.map(&:source)
    assert_equal [10..14, 15..20], report.mapping.segments.map(&:assigned)
  end

  test "duplicate UIDs are reported separately" do
    report = export("A1 OK [COPYUID 7 3,3 7,8] Done")
    findings = report.findings_by(:duplicate_uids)
    assert_equal 1, findings.size
    assert_equal :source, findings.first.side
    assert_equal 1, findings.first.detail[:duplicate_occurrences]
    assert_equal "3", findings.first.detail[:duplicated_uids]
    # duplicates are not deduplicated away before pairing
    assert_equal [[3, 7], [3, 8]], report.mapping.each_pair.to_a
  end

  test "unequal counts are reported and no mapping is fabricated" do
    report = export("A1 OK [COPYUID 7 1:3 10:11] Done")
    findings = report.findings_by(:unequal_counts)
    assert_equal 1, findings.size
    assert_equal({ source_count: 3, assigned_count: 2 },
                 findings.first.detail)
    refute_predicate report, :mapping_established?
    assert_nil report.mapping
    # CopyUIDData itself refuses this data; the report must not crash on it
    assert_raise(Net::IMAP::DataFormatError) do
      CopyUIDData.new(uidvalidity: 7, source_uids: "1:3",
                      assigned_uids: "10:11")
    end
    assert_nil report.copy_uid_data
  end

  test "missing COPYUID is reported; OK alone never fabricates a mapping" do
    report = export("A1 OK COPY completed")
    assert_equal "OK", report.tagged_status
    findings = report.findings_by(:missing_copyuid)
    assert_equal 1, findings.size
    assert_equal({ tagged_status: "OK" }, findings.first.detail)
    refute_predicate report, :mapping_established?
    assert_nil report.uidvalidity
    refute_predicate report, :clean?
  end

  test "malformed COPYUID codes are reported" do
    # only one uid-set
    report = export("A1 OK [COPYUID 38505 1:3] Done")
    assert_equal 1, report.findings_by(:malformed_copyuid).size
    refute_predicate report, :mapping_established?
    # uid-set cannot contain '*'
    report = export("A1 OK [COPYUID 1 1:* 5:6] Done")
    assert_equal 1, report.findings_by(:malformed_copyuid).size
    # uidvalidity must be a nonzero uint32
    report = export("A1 OK [COPYUID 0 1 2] Done")
    assert_equal 1, report.findings_by(:malformed_copyuid).size
    report = export("A1 OK [COPYUID #{UINT32_MAX + 1} 1 2] Done")
    assert_equal 1, report.findings_by(:malformed_copyuid).size
    # zero is not a valid uniqueid
    report = export("A1 OK [COPYUID 1 0 2] Done")
    assert_equal 1, report.findings_by(:malformed_copyuid).size
  end

  test "huge ranges stay ranges: one segment for two billion messages" do
    report = export(
      "A1 OK [COPYUID 4000000000 1:2000000000 2294967296:4294967295] Done"
    )
    assert_predicate report, :clean?
    assert_equal 1, report.mapping.segments.size
    assert_equal 2_000_000_000, report.mapping.message_count
    segment = report.mapping.segments.first
    assert_equal 1..2_000_000_000, segment.source
    assert_equal 2_294_967_296..UINT32_MAX, segment.assigned
    # the export contains interval bounds, not expanded integers
    exported = report.to_h[:mapping][:segments]
    assert_equal [{ source:   { first: 1, last: 2_000_000_000 },
                    assigned: { first: 2_294_967_296, last: UINT32_MAX },
                    count:    2_000_000_000 }],
                 exported
  end

  test "the full uint32 range maps as a single segment" do
    report = export(
      "A1 OK [COPYUID 1 1:4294967295 1:4294967295] Done"
    )
    assert_equal 1, report.mapping.segments.size
    assert_equal UINT32_MAX, report.mapping.message_count
  end

  test "segment count scales with entry count, not uid magnitude" do
    count  = 10_000
    source = (1..count).map { 2 * _1 - 1 }.join(",") # 1,3,5,...,19999
    report = export("A1 OK [COPYUID 1 #{source} 100001:110000] Done")
    assert_predicate report, :clean?
    assert_equal count, report.mapping.segments.size
    assert_equal count, report.mapping.message_count
    assert_equal count, report.source_count
  end

  test "export from an already parsed CopyUIDData" do
    copyuid = CopyUIDData.new(uidvalidity:   38505,
                              source_uids:   "3955:3960,3962",
                              assigned_uids: "4482:4487,4489")
    report = CopyUIDEvidence.export(source_mailbox: "Archive/2026",
                                    copyuid: copyuid)
    assert_equal 38505, report.uidvalidity
    assert_equal copyuid.each_uid_pair.to_a, report.mapping.each_pair.to_a
    assert_raise(ArgumentError) do
      CopyUIDEvidence.export(source_mailbox: "M")
    end
    assert_raise(ArgumentError) do
      CopyUIDEvidence.export(source_mailbox: "M", response: "A1 OK x",
                             copyuid: copyuid)
    end
  end

  test "report and its collections are frozen" do
    report = export("A1 OK [COPYUID 7 1:2 10:11] Done")
    assert_predicate report, :frozen?
    assert_predicate report.findings, :frozen?
    assert_predicate report.source_entries, :frozen?
    assert_predicate report.mapping.segments, :frozen?
    assert_raise(FrozenError) { report.mapping.segments << nil }
  end

  test "to_h separates server-declared data from local validation" do
    report = export("A1 OK [COPYUID 7 1:2 10:11] Done")
    exported = report.to_h
    assert_equal "net-imap/copyuid-correspondence", exported[:evidence_type]
    assert_equal "Archive/2026", exported[:source_mailbox]
    assert_equal({ tagged_status: "OK", uidvalidity: 7,
                   source_uid_set: "1:2", assigned_uid_set: "10:11" },
                 exported[:server_declared])
    assert_equal %w[1:2],  exported[:local_validation][:source_entries]
    assert_equal 2,        exported[:local_validation][:source_count]
    assert_equal [],       exported[:findings]
    assert_match(/declared order/i, exported[:mapping][:basis])
    assert_match(/not proof/i, exported[:limitations])
  end
end
