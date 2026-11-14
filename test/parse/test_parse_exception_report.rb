require "test/unit"

require "stringio"

require "rexml/document"
require "rexml/streamlistener"

# In-memory samples showing how REXML::ParseException separates
# "locating the original evidence" (structured record: raw byte
# position, parse phase, cause chain) from "what may be written to
# ordinary logs" (the default #to_s, which never contains the input
# body nor nested exception messages).
module REXMLTests
  class TestParseExceptionReport < Test::Unit::TestCase
    def parse(xml)
      REXML::Document.new(xml)
    end

    # UTF-8 input: the default rendering points at the problem without
    # echoing the input, even when the input carries secrets.
    def test_default_rendering_omits_input_body
      xml = "<a><b></a><password>hunter2</password>"
      exception = assert_raise(REXML::ParseException) do
        parse(xml)
      end
      assert_equal(<<-DETAIL.chomp, exception.to_s)
Missing end tag for 'b' (got 'a')
Line: 1
Position: 10
      DETAIL
      assert_not_include(exception.to_s, "hunter2")
      assert_not_include(exception.to_s, "unconsumed characters")
    end

    # The structured record locates the exact evidence byte: the
    # malformed "<2" tag start.  Note that byte_position is exact even
    # though Position (the legacy, read-ahead IO offset) has already
    # moved past the evidence.
    def test_structured_record_points_at_problem_byte
      xml = "<a>1<2</a>"
      exception = assert_raise(REXML::ParseException) do
        parse(xml)
      end
      assert_equal(
        {
          message: "malformed XML: missing tag start",
          line: 1,
          position: 10,
          byte_position: 4,
          phase: :element,
          causes: [],
        },
        exception.to_h
      )
      assert_equal("<2", xml.byteslice(exception.byte_position, 2))
    end

    # UTF-16 input: byte_position addresses the raw (undecoded) bytes,
    # so the evidence can be lifted straight from the original input.
    def test_utf16_byte_position_addresses_raw_bytes
      xml = "<r><a><1/></a></r>"
      raw = "\xff\xfe".b + xml.encode(Encoding::UTF_16LE).b
      exception = assert_raise(REXML::ParseException) do
        parse(raw)
      end
      assert_equal(:element, exception.phase)
      # The raw bytes at byte_position are the UTF-16LE encoding of the
      # offending "<1" tag start (BOM included in the offset).
      assert_equal("<1".encode(Encoding::UTF_16LE).b,
                   raw.byteslice(exception.byte_position, 4).b)
    end

    # Fragmented IO: the parser reads the IO lazily and in pieces, but
    # byte_position still addresses the raw stream, and formatting the
    # exception performs no IO and consumes no further input.
    def test_fragmented_io_byte_position_and_non_consuming_format
      xml = "<root>1<2</root><token>sekrit</token>"
      io = StringIO.new(xml)
      exception = assert_raise(REXML::ParseException) do
        parse(io)
      end
      assert_equal("<2", xml.byteslice(exception.byte_position, 2))

      io_pos_before = io.pos
      buffer_before = exception.source.buffer
      exception.to_s
      exception.full_report
      exception.to_h
      assert_equal(io_pos_before, io.pos)
      assert_equal(buffer_before, exception.source.buffer)
    end

    # Entity expansion failure: the phase says where it happened and
    # the byte position addresses the input that triggered it: the
    # offending reference lies immediately before byte_position.
    def test_entity_expansion_failure_carries_phase_and_position
      xml = <<-XML
<!DOCTYPE r [
  <!ENTITY a "&a;">
]>
<r>&a;</r>
      XML
      listener = Class.new { include REXML::StreamListener }.new
      exception = assert_raise(REXML::ParseException) do
        REXML::Document.parse_stream(xml, listener)
      end
      assert_equal(:entity_expansion, exception.phase)
      assert_equal("Detected an entity reference loop: a",
                   exception.to_h[:message])
      assert_equal("&a;", xml.byteslice(exception.byte_position - 3, 3))
    end

    # Nested exceptions: the cause chain is preserved in the record,
    # but the default rendering shows only class names, so a nested
    # message carrying a token cannot leak into ordinary logs.
    def test_nested_exception_token_stays_out_of_default_rendering
      inner = RuntimeError.new("bad token: tok_live_abc123")
      exception = REXML::ParseException.new("Exception parsing",
                                            nil,
                                            nil,
                                            inner)
      assert_equal([inner], exception.causes)
      assert_equal([{class: "RuntimeError",
                     message: "bad token: tok_live_abc123"}],
                   exception.to_h[:causes])
      assert_include(exception.to_s, "Caused by: RuntimeError")
      assert_not_include(exception.to_s, "tok_live_abc123")
      assert_include(exception.full_report, "tok_live_abc123")
    end

    # Controlled diagnostics: opting in (here explicitly, or via
    # REXML_DIAGNOSTICS=true) makes #to_s include the input excerpt
    # and the raw byte position; the default does neither.
    def test_controlled_diagnostics_vs_default
      xml = "<a><b></a><password>hunter2</password>"
      exception = assert_raise(REXML::ParseException) do
        parse(xml)
      end

      default_report = exception.to_s
      assert_not_include(default_report, "hunter2")
      assert_not_include(default_report, "Byte:")

      begin
        REXML::ParseException.diagnostics_enabled = true
        diagnostic_report = exception.to_s
        assert_include(diagnostic_report, "Byte: 10")
        assert_include(diagnostic_report, "Phase: element")
        assert_include(diagnostic_report, "Last 80 unconsumed characters:")
        assert_equal(exception.full_report, diagnostic_report)
      ensure
        REXML::ParseException.diagnostics_enabled = nil
      end

      assert_equal(default_report, exception.to_s)
    end
  end
end
