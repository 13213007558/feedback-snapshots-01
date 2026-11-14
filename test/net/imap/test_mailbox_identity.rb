# frozen_string_literal: true

require "net/imap"
require "test/unit"

class MailboxIdentityTest < Net::IMAP::TestCase
  MailboxIdentity = Net::IMAP::MailboxIdentity
  Codec           = MailboxIdentity::Codec
  Adapter         = MailboxIdentity::Adapter
  MigrationReport = MailboxIdentity::MigrationReport

  # In-memory transport double: records every command it receives so tests
  # can prove what would (and would not) have been sent to the server.
  class MemoryTransport
    Command = Data.define(:name, :wire_bytes)

    attr_reader :sent

    def initialize
      @sent = []
    end

    def command(name, wire_bytes)
      @sent << Command.new(name: name, wire_bytes: wire_bytes.b)
    end

    def sent?(name) = @sent.any? { _1.name == name }
  end

  NFC = "R\u00E9sum\u00E9"             # composed
  NFD = "R\u0065\u0301sum\u0065\u0301" # same display, different codepoints

  test "identity stores logical name, negotiated mode, and wire bytes" do
    adapter = Adapter.new(utf8: false)
    identity = adapter.identity_for("Git & 日本語")
    assert_equal "Git & 日本語", identity.logical_name
    assert_equal :legacy, identity.mode
    assert_equal Codec.encode_utf7("Git & 日本語"), identity.wire_bytes
    assert_equal Encoding::ASCII_8BIT, identity.wire_bytes.encoding
    assert_predicate identity.wire_bytes, :frozen?
  end

  test "strict codec round-trips legal names in both modes" do
    legacy = Adapter.new(utf8: false)
    utf8   = Adapter.new(utf8: true)
    name   = "Git & 日本語"
    legacy_identity = legacy.identity_for(name)
    utf8_identity   = utf8.identity_for(name)
    # wire bytes differ by mode...
    assert_equal "Git &- &ZeVnLIqe-", legacy_identity.wire_bytes
    assert_equal name.b, utf8_identity.wire_bytes
    # ...but decode back to the same logical name and identity
    assert_equal legacy_identity, legacy.parse(legacy_identity.wire_bytes)
    assert_equal utf8_identity,   utf8.parse(utf8_identity.wire_bytes)
    assert_equal legacy_identity, utf8_identity
    assert_equal name, legacy.parse(legacy_identity.wire_bytes).logical_name
    assert_equal name, utf8.parse(utf8_identity.wire_bytes).logical_name
  end

  test "display-similar mailboxes keep distinct identities" do
    refute_equal NFC, NFD
    adapter = Adapter.new(utf8: false)
    nfc = adapter.identity_for(NFC)
    nfd = adapter.identity_for(NFD)
    refute_equal nfc, nfd
    refute_equal nfc.wire_bytes, nfd.wire_bytes
    # approving one never authorizes the other
    adapter.approve(NFC)
    assert adapter.approved?(NFC)
    refute adapter.approved?(NFD)
    assert_raise(MailboxIdentity::AuthorizationError) do
      adapter.authorized_identity(NFD)
    end
  end

  test "INBOX case-insensitivity is separate from other names" do
    adapter = Adapter.new(utf8: false, delimiter: "/")
    assert_equal adapter.identity_for("INBOX"), adapter.identity_for("inbox")
    assert_equal adapter.identity_for("Inbox"), adapter.identity_for("INBOX")
    assert_predicate adapter.identity_for("iNbOx"), :inbox?
    # other names stay case-sensitive, even below INBOX in the hierarchy
    refute_equal adapter.identity_for("Sent"), adapter.identity_for("sent")
    refute_predicate adapter.identity_for("inbox/sub"), :inbox?
    adapter.approve("INBOX")
    assert adapter.approved?("inbox")
    refute adapter.approved?("INBOXY")
  end

  test "utf-8 wire bytes are refused when the server has not enabled them" do
    legacy = Adapter.new(utf8: false)
    assert_equal :legacy, legacy.mode
    assert_raise(MailboxIdentity::ModeError) do
      legacy.identity_for("日本語", mode: :utf8)
    end
    assert_raise(MailboxIdentity::ModeError) do
      legacy.parse("日本語".b, mode: :utf8)
    end
    # legacy mode still sends modified UTF-7, never raw UTF-8
    identity = legacy.identity_for("日本語")
    assert_predicate identity.wire_bytes, :ascii_only?
  end

  test "utf8 mode sends and parses UTF-8 bytes strictly" do
    adapter = Adapter.new(utf8: true)
    identity = adapter.identity_for("日本語")
    assert_equal :utf8, identity.mode
    assert_equal "日本語".b, identity.wire_bytes
    assert_raise(MailboxIdentity::MailboxNameError) do
      adapter.parse("\xff\xfe".b, mode: :utf8)
    end
  end

  test "hierarchy delimiter comes from the connection" do
    dot = Adapter.new(utf8: false, delimiter: ".")
    assert_equal %w[Archive 2026 tax], dot.segments("Archive.2026.tax")
    assert_equal "Archive.2026.tax", dot.join("Archive", "2026", "tax")
    none = Adapter.new(utf8: false)
    assert_raise(MailboxIdentity::ModeError) { none.segments("a/b") }
    assert_raise(MailboxIdentity::ModeError) { none.join("a", "b") }
  end

  test "select authorizes before touching the transport" do
    transport = MemoryTransport.new
    adapter = Adapter.new(utf8: false)
    adapter.approve("日本語")
    identity = adapter.select(transport, "日本語")
    assert_equal 1, transport.sent.size
    assert_equal "SELECT", transport.sent.first.name
    assert_equal identity.wire_bytes, transport.sent.first.wire_bytes
    # rejected: no SELECT is sent and approvals are unchanged
    assert_raise(MailboxIdentity::AuthorizationError) do
      adapter.select(transport, "日本語-backup")
    end
    assert_equal 1, transport.sent.size
    assert_equal %w[日本語], adapter.approved_names
  end

  test "strict codec rejects malformed and non-canonical legacy names" do
    rejections = {
      "A&B"     => "bare ampersand",
      "A&"      => "unterminated ampersand",
      "A&Z"     => "missing terminator",
      "&AEE-"   => "printable ASCII inside shifted section",
      "&2AA-"   => "lone UTF-16 surrogate",
      "&2A-"    => "odd UTF-16 byte count",
      "&AOkA-"  => "non-canonical base64 padding bits",
      "a\tb"     => "control character",
      "caf\xC3\xA9".b => "non-ASCII byte in legacy name",
    }
    rejections.each do |wire, why|
      assert_raise(MailboxIdentity::MailboxNameError, why) do
        Codec.decode_utf7(wire)
      end
    end
    # and nothing is "fixed": no replacement characters, no normalization
    assert_equal "café", Codec.decode_utf7("caf&AOk-")
    assert_equal NFD, Codec.decode_utf7(Codec.encode_utf7(NFD))
  end

  test "encode rejects invalid UTF-8 instead of repairing it" do
    invalid = "caf\xE9".b.force_encoding(Encoding::UTF_8)
    refute_predicate invalid, :valid_encoding?
    assert_raise(MailboxIdentity::MailboxNameError) { Codec.encode_utf7(invalid) }
    assert_raise(MailboxIdentity::MailboxNameError) do
      Adapter.new(utf8: true).identity_for(invalid)
    end
  end

  test "migration report lists conflicts for manual confirmation" do
    adapter = Adapter.new(utf8: false)
    report = adapter.migration_report([
      Codec.encode_utf7(NFC),          # ok
      Codec.encode_utf7(NFD),          # confusable with NFC
      "INBOX",                         # collides with "inbox"
      "inbox",                         # collides with "INBOX"
      "A&B",                           # undecodable
    ])
    refute_predicate report, :ok?
    kinds = report.conflicts.map(&:kind)
    assert_includes kinds, :undecodable
    assert_includes kinds, :collision
    assert_includes kinds, :confusable
    confusable = report.conflicts.find { _1.kind == :confusable }
    assert_equal [NFC, NFD].sort, confusable.entries.map(&:logical_name).sort
    collision = report.conflicts.find { _1.kind == :collision }
    assert_equal %w[INBOX inbox], collision.entries.map(&:logical_name)
    # rejected migration: raises, sends nothing, changes no authorization
    transport = MemoryTransport.new
    adapter.approve("Sent")
    error = assert_raise(MailboxIdentity::MigrationConflictError) do
      adapter.apply_migration(report)
    end
    assert_same report, error.report
    assert_equal %w[Sent], adapter.approved_names
    refute transport.sent?("SELECT")
    # the report summarizes every conflict for manual review
    summary = report.summary
    assert_match(/5 approved name\(s\), 3 conflict\(s\)/, summary)
    assert_match(/undecodable: "A&B"/, summary)
    assert_match(/collision: "INBOX", "inbox"/, summary)
    assert_match(/confusable: /, summary)
    assert_include summary, NFC.inspect
    assert_include summary, NFD.inspect
  end

  test "clean migration commits logical names usable in both modes" do
    legacy = Adapter.new(utf8: false)
    report = legacy.migration_report([
      "INBOX",
      Codec.encode_utf7("Git & 日本語"),
      Codec.encode_utf7("Résumé"),
    ])
    assert_predicate report, :ok?
    migrated = legacy.apply_migration(report)
    assert_equal %w[INBOX Git\ &\ 日本語 Résumé], migrated
    # the same approvals survive the encoding switch unchanged
    utf8 = Adapter.new(utf8: true)
    migrated.each { utf8.approve(_1) }
    transport = MemoryTransport.new
    utf8.select(transport, "Git & 日本語")
    assert_equal "Git & 日本語".b, transport.sent.first.wire_bytes
    legacy.select(MemoryTransport.new, "Git & 日本語")
    assert_equal legacy.authorized_identity("Git & 日本語"),
                 utf8.authorized_identity("Git & 日本語")
  end
end
