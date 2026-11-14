# frozen_string_literal: true

require "net/imap"
require "test/unit"
require "tmpdir"
require_relative "../../../sample/forensic_collector"

class ForensicCollectorTest < Test::Unit::TestCase
  include ForensicIMAP

  test "complete collection preserves raw source bytes and digest" do
    result, audit, source = ForensicIMAP.run_demo(chunk_bytes: 64)

    assert_true result.complete?
    assert_equal :complete, result.status
    assert_equal "INBOX", result.mailbox
    assert_equal 42, result.uid
    assert_equal 2026111401, result.uidvalidity
    assert_equal "BODY.PEEK[]", result.section
    assert_equal source, result.source
    assert_equal Encoding::BINARY, result.source.encoding
    assert_equal Digest::SHA256::hexdigest(source), result.sha256
    assert_equal source.bytesize, result.rfc822_size
    assert_equal source.bytesize, result.received_bytes
    assert_equal result.received_bytes, result.chunks.sum(&:received)
    assert_true result.chunks.length > 1
    assert_equal 64, result.chunks.first.received
    assert_equal "BODY.PEEK[]<0>", result.chunks.first.request
    origin = 0
    result.chunks.each do |chunk|
      assert_equal origin, chunk.origin
      assert_equal "BODY.PEEK[]<#{origin}>", chunk.request
      assert_equal "BODY[]<#{origin}>", chunk.response_attr
      assert_equal Digest::SHA256.hexdigest(
        source.byteslice(chunk.origin, chunk.received)
      ), chunk.sha256
      origin += chunk.received
    end
    assert_equal source.bytesize, origin
    assert_equal [], result.initial_flags
    assert_equal [], result.final_flags
    assert_equal audit[:commands], audit[:client_commands]
    assert_equal result.sha256, audit[:messages][42][:sha256]
    assert_equal 0, audit[:messages][42][:flags].length
  end

  test "manifest and raw file match collector and server digests" do
    result, audit, _source = ForensicIMAP.run_demo(chunk_bytes: 32)
    assert_true result.complete?
    manifest = result.manifest
    assert_equal "INBOX", manifest[:mailbox]
    assert_equal 2026111401, manifest[:uidvalidity]
    assert_equal 42, manifest[:uid]
    assert_equal "BODY.PEEK[]", manifest[:section]
    assert_equal result.source.bytesize, manifest[:bytes]
    assert_equal result.sha256, manifest[:sha256]
    assert_equal result.chunks.length, manifest[:chunks].length
    assert_equal audit[:messages][42][:sha256], manifest[:sha256]

    Dir.mktmpdir do |dir|
      path = File.join(dir, "message.eml")
      saved = result.write_raw(path)
      assert_equal path, saved[:path]
      written = File.binread(path)
      assert_equal _source, written
      assert_equal result.sha256, Digest::SHA256.hexdigest(written)
    end
  end

  test "collection is by UID with BODY.PEEK and sends no mutating command" do
    result, audit, _source = ForensicIMAP.run_demo(chunk_bytes: 96)
    assert_true result.complete?

    lines = audit[:client_commands]
    verbs = lines.map { |line| ForensicIMAP.command_verb(line) }
    assert_equal "EXAMINE", verbs.first
    assert_equal "LOGOUT", verbs.last
    assert_true verbs.all? {
      ["EXAMINE", "NOOP", "UID FETCH", "LOGOUT"].include?(_1)
    }
    body_lines = lines.grep(/UID FETCH.*BODY\.PEEK/)
    assert_true body_lines.length > 1
    body_lines.each { assert_match(/BODY\.PEEK\[\]/n, _1) }
    refute_match(/BODY\[\]/n, lines.join("\n"))
    refute_match(/\bSTORE\b|\bEXPUNGE\b|\bCLOSE\b|\bAPPEND\b|\bCOPY\b|\bMOVE\b/n,
                 lines.join("\n"))

    report = ForensicIMAP.read_only_audit(lines)
    assert_true report[:ok]
    assert_empty report[:forbidden]
    assert_empty report[:unsafe_fetches]
    assert_match(/cannot prove the mailbox was unchanged/i, report[:note])
  end

  test "a missing section mid-stream never yields a stitched source" do
    result, _audit, _source = ForensicIMAP.run_demo(
      chunk_bytes: 64, faults: {omit_section_at: 2}
    )
    assert_equal :missing_section, result.status
    assert_false result.complete?
    assert_nil result.source
    assert_nil result.sha256
    assert_equal 1, result.chunks.length
    assert_equal 64, result.received_bytes
    assert_equal 0, result.chunks.first.origin
    assert_equal 64, result.chunks.first.received
    assert_match(/no BODY section/i, result.error)
    assert_raise(RuntimeError) { result.manifest }
    Dir.mktmpdir do |dir|
      assert_raise(RuntimeError) { result.write_raw(File.join(dir, "no")) }
    end
  end

  test "wrong echoed origin is reported as incomplete" do
    result, audit, _source = ForensicIMAP.run_demo(
      chunk_bytes: 64, faults: {wrong_offset_next: true}
    )
    assert_equal :offset_mismatch, result.status
    assert_nil result.source
    assert_nil result.sha256
    assert_equal 0, result.received_bytes
    assert_match(/BODY\[\]<1>/, result.error)
    assert_empty result.chunks
    assert_equal audit[:commands], audit[:client_commands]
  end

  test "wire-level short literal is reported as a connection error" do
    result, _audit, _source = ForensicIMAP.run_demo(
      chunk_bytes: 64, faults: {truncate_literal_at: 2}
    )
    assert_equal :connection_error, result.status
    assert_false result.complete?
    assert_nil result.source
    assert_nil result.sha256
    assert_equal 1, result.chunks.length
    assert_equal 64, result.received_bytes
    assert_match(/EOF|end of file|parse|connection/i, result.error)
  end

  test "content change without MODSEQ bump is caught by chunk re-read" do
    # Find how many initial chunk reads occur, then mutate only during the
    # verification pass.  A change made before the affected chunk was first
    # read cannot be distinguished from the original by this method; that
    # limitation is documented in the prototype.
    initial, _audit, _source = ForensicIMAP.run_demo(chunk_bytes: 64)
    assert_true initial.complete?
    first_verification_fetch = initial.chunks.length + 1
    mutation = ->(bytes) { bytes.sub("forensic sample", "forensic samplX") }
    result, _audit, _source = ForensicIMAP.run_demo(
      chunk_bytes: 64,
      faults: {
        mutate_after_fetches: first_verification_fetch,
        mutation_after: first_verification_fetch,
        mutation: mutation, bump_modseq_on_mutation: false,
      }
    )
    assert_equal :changed_during_fetch, result.status
    assert_nil result.source
    assert_nil result.sha256
    assert_match(/chunk at origin \d+ changed/i, result.error)
    assert_equal result.rfc822_size, result.chunks.sum(&:received)
    assert_equal initial.chunks.length, result.chunks.length
  end

  test "metadata change with MODSEQ bump is reported before verification" do
    mutation = ->(bytes) { bytes.sub("forensic sample", "forensic samplX") }
    result, _audit, _source = ForensicIMAP.run_demo(
      chunk_bytes: 64, faults: {mutate_after_fetches: 1, mutation: mutation}
    )
    assert_equal :changed_during_fetch, result.status
    assert_nil result.source
    assert_match(/metadata changed.*modseq/i, result.error)
    assert_equal result.rfc822_size, result.chunks.sum(&:received)
  end

  test "missing UIDVALIDITY is reported as incomplete, not raised" do
    result, _audit, _source = ForensicIMAP.run_demo(
      chunk_bytes: 64, faults: {omit_uidvalidity: true}
    )
    assert_equal :missing_uidvalidity, result.status
    assert_false result.complete?
    assert_nil result.uidvalidity
    assert_nil result.source
    assert_nil result.sha256
  end

  test "audit rejects mutating and non-PEEK body commands" do
    report = ForensicIMAP.read_only_audit([
      "RUBY0001 EXAMINE INBOX",
      "RUBY0002 UID STORE 42 +FLAGS (\\Seen)",
      "RUBY0003 UID EXPUNGE 42",
      "RUBY0004 UID FETCH 42 BODY[]<0>",
      "RUBY0005 FETCH 1 RFC822.TEXT",
      "RUBY0006 UID FETCH 42 (RFC822.SIZE)",
      "RUBY0007 UID FETCH 42 BODY.PEEK[]<0>",
    ])
    assert_false report[:ok]
    assert_equal ["UID STORE", "UID EXPUNGE", "UID FETCH", "FETCH"], report[:forbidden]
    assert_equal 2, report[:unsafe_fetches].length
  end

  test "demo source contains non-ASCII, mixed newlines, and binary parts" do
    source = ForensicIMAP.demo_message
    assert_true source.include?("正文包含非 ASCII".b)
    assert_true source.include?("bare LF\nending".b)
    assert_true source.include?("\r\n")
    assert_match(/Content-Transfer-Encoding: base64/n, source)
    assert_true source.include?(%w[00 01 02 7F 80 FE FF].pack("H*"))
    assert_match(/application\/octet-stream/n, source)
  end
end
