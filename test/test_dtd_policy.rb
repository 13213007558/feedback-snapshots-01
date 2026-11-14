# frozen_string_literal: false

require "test/unit"

require "rexml/document"
require "rexml/parsers/baseparser"
require "rexml/parsers/pullparser"
require "rexml/parsers/sax2parser"
require "rexml/sax2listener"
require "rexml/streamlistener"

module REXMLTests
  # Tests the explicit declaration admission policy that lets callers reject
  # DOCTYPE declarations from external input while keeping full DTD support
  # (including internal entities) for trusted input.
  class TestDTDPolicy < Test::Unit::TestCase
    INTERNAL_DTD = <<~XML.freeze
      <?xml version="1.0"?>
      <!DOCTYPE root [
        <!ENTITY greeting "EXPANDED">
        <!ATTLIST root fixed CDATA "default">
      ]>
      <root>&greeting;</root>
    XML

    EXTERNAL_DTD = <<~XML.freeze
      <?xml version="1.0"?>
      <!DOCTYPE root SYSTEM "urn:external:dtd">
      <root/>
    XML

    # DOCTYPE-looking text that lives inside comments and CDATA sections must
    # never be mistaken for a real declaration.
    LOOKALIKE_XML = <<~XML.freeze
      <root>
        <!-- <!DOCTYPE in-a-comment [<!ENTITY x "no">]> -->
        <![CDATA[<!DOCTYPE in-cdata SYSTEM "urn:x">]]>
        <a>&lt;!DOCTYPE as-text&gt;</a>
      </root>
    XML

    module AssertRejectsDTD
      def assert_rejects_dtd
        exception = assert_raise(REXML::ParseException) do
          yield
        end
        assert_equal("DOCTYPE declaration is not allowed in this input",
                     exception.message.lines.first.chomp)
        exception
      end
    end

    sub_test_case "Document (tree) entry" do
      include AssertRejectsDTD

      def test_rejects_internal_doctype_from_external_input
        assert_rejects_dtd do
          REXML::Document.new(INTERNAL_DTD, disallow_dtd: true)
        end
      end

      def test_rejects_external_doctype_from_external_input
        assert_rejects_dtd do
          REXML::Document.new(EXTERNAL_DTD, disallow_dtd: true)
        end
      end

      def test_default_keeps_dtd_and_internal_entities
        document = REXML::Document.new(INTERNAL_DTD)
        assert_not_nil(document.doctype)
        assert_equal("EXPANDED", document.root.text)
        assert_equal("default", document.root.attributes["fixed"])
      end

      def test_explicit_false_keeps_dtd
        document = REXML::Document.new(INTERNAL_DTD, disallow_dtd: false)
        assert_not_nil(document.doctype)
      end

      def test_allows_doctype_lookalikes_in_comment_and_cdata
        document = REXML::Document.new(LOOKALIKE_XML, disallow_dtd: true)
        assert_nil(document.doctype)
        assert_equal("<!DOCTYPE in-cdata SYSTEM \"urn:x\">",
                     document.root.cdatas.first.value)
      end

      def test_reports_the_policy
        document = REXML::Document.new
        assert_equal(false, document.disallow_dtd?)
        restricted = REXML::Document.new(nil, disallow_dtd: true)
        assert_equal(true, restricted.disallow_dtd?)
      end
    end

    sub_test_case "PullParser entry" do
      include AssertRejectsDTD

      def test_rejects_doctype
        assert_rejects_dtd do
          parser = REXML::Parsers::PullParser.new(INTERNAL_DTD,
                                                   disallow_dtd: true)
          parser.pull while parser.has_next?
        end
      end

      def test_rejection_precedes_any_dtd_event
        seen = []
        parser = REXML::Parsers::PullParser.new(INTERNAL_DTD,
                                                 disallow_dtd: true)
        assert_raise(REXML::ParseException) do
          while parser.has_next?
            seen << parser.pull.event_type
          end
        end
        assert_not_include(seen, :start_doctype)
        assert_not_include(seen, :entitydecl)
        assert_not_include(seen, :attlistdecl)
        assert_not_include(seen, :start_element)
      end

      def test_default_keeps_entity_replacement
        parser = REXML::Parsers::PullParser.new(INTERNAL_DTD)
        texts = []
        while parser.has_next?
          event = parser.pull
          texts << event[1] if event.event_type == :text
        end
        assert_include(texts, "EXPANDED")
      end

      def test_allows_doctype_lookalikes
        parser = REXML::Parsers::PullParser.new(LOOKALIKE_XML,
                                                 disallow_dtd: true)
        events = []
        while parser.has_next?
          events << parser.pull.event_type
        end
        assert_include(events, :comment)
        assert_include(events, :cdata)
      end

      def test_reports_the_policy
        assert_equal(true,
                     REXML::Parsers::PullParser.new("<r/>",
                                                    disallow_dtd: true).disallow_dtd?)
        assert_equal(false,
                     REXML::Parsers::PullParser.new("<r/>").disallow_dtd?)
      end
    end

    sub_test_case "SAX2Parser entry" do
      class RecordingListener
        include REXML::SAX2Listener
        attr_reader :events

        def initialize
          @events = []
        end

        def xmldecl(*args); @events << [:xmldecl]; end
        def start_document; @events << [:start_document]; end
        def doctype(*args); @events << [:doctype, args]; end
        def entitydecl(*args); @events << [:entitydecl]; end
        def attlistdecl(*args); @events << [:attlistdecl]; end
        def start_element(*args); @events << [:start_element]; end
        def characters(text); @events << [:characters, text]; end
      end

      def test_rejects_doctype_before_dtd_callbacks
        listener = RecordingListener.new
        parser = REXML::Parsers::SAX2Parser.new(INTERNAL_DTD,
                                                disallow_dtd: true)
        parser.listen(listener)
        assert_raise(REXML::ParseException) { parser.parse }
        names = listener.events.map(&:first)
        assert_not_include(names, :doctype)
        assert_not_include(names, :entitydecl)
        assert_not_include(names, :attlistdecl)
        assert_not_include(names, :start_element)
      end

      def test_default_runs_dtd_callbacks_and_expands_entities
        listener = RecordingListener.new
        parser = REXML::Parsers::SAX2Parser.new(INTERNAL_DTD)
        parser.listen(listener)
        parser.parse
        names = listener.events.map(&:first)
        assert_include(names, :doctype)
        assert_include(names, :entitydecl)
        character_texts = listener.events.select { |event|
          event.first == :characters
        }.map(&:last)
        assert_include(character_texts, "EXPANDED")
      end

      def test_allows_doctype_lookalikes
        listener = RecordingListener.new
        parser = REXML::Parsers::SAX2Parser.new(LOOKALIKE_XML,
                                                disallow_dtd: true)
        parser.listen(listener)
        parser.parse
        names = listener.events.map(&:first)
        assert_not_include(names, :doctype)
      end
    end

    sub_test_case "StreamParser entry" do
      class RecordingStreamListener
        include REXML::StreamListener
        attr_reader :events

        def initialize
          @events = []
        end

        def xmldecl(*); @events << :xmldecl; end
        def doctype(*); @events << :doctype; end
        def entitydecl(*); @events << :entitydecl; end
        def attlistdecl(*); @events << :attlistdecl; end
        def tag_start(*); @events << :tag_start; end
        def text(*); @events << :text; end
      end

      def test_rejects_doctype_before_dtd_callbacks
        listener = RecordingStreamListener.new
        assert_raise(REXML::ParseException) do
          REXML::Document.parse_stream(INTERNAL_DTD, listener,
                                       disallow_dtd: true)
        end
        assert_not_include(listener.events, :doctype)
        assert_not_include(listener.events, :entitydecl)
        assert_not_include(listener.events, :attlistdecl)
        assert_not_include(listener.events, :tag_start)
      end

      def test_default_runs_dtd_callbacks
        listener = RecordingStreamListener.new
        REXML::Document.parse_stream(INTERNAL_DTD, listener)
        assert_include(listener.events, :doctype)
        assert_include(listener.events, :entitydecl)
      end

      def test_allows_doctype_lookalikes
        listener = RecordingStreamListener.new
        REXML::Document.parse_stream(LOOKALIKE_XML, listener,
                                     disallow_dtd: true)
        assert_not_include(listener.events, :doctype)
      end
    end

    sub_test_case "policy isolation" do
      def test_parsers_with_different_policies_do_not_interfere
        restricted = REXML::Parsers::BaseParser.new(INTERNAL_DTD,
                                                     disallow_dtd: true)
        assert_raise(REXML::ParseException) do
          restricted.pull while restricted.has_next?
        end

        trusted = REXML::Parsers::BaseParser.new(INTERNAL_DTD)
        assert_equal(false, trusted.disallow_dtd?)
        events = []
        events << trusted.pull[0] until events.include?(:start_doctype)
        assert_equal(:start_doctype, events.last)
        assert_not_include(events, :entitydecl)
      end

      def test_document_context_does_not_leak_between_instances
        assert_raise(REXML::ParseException) do
          REXML::Document.new(INTERNAL_DTD, disallow_dtd: true)
        end
        document = REXML::Document.new(INTERNAL_DTD)
        assert_not_nil(document.doctype)
        assert_equal(false, document.disallow_dtd?)
      end

      def test_global_security_limits_are_unaffected
        original = REXML::Security.entity_expansion_limit
        REXML::Parsers::BaseParser.new("<r/>", disallow_dtd: true)
        assert_equal(original, REXML::Security.entity_expansion_limit)
      ensure
        REXML::Security.entity_expansion_limit = original
      end
    end

    sub_test_case "fragmented (chunked) input" do
      # Delivers +xml+ over a real pipe, flushing one small fragment at a
      # time. The reader therefore sees bytes whose boundaries do not line up
      # with markup tokens, so "<!DOC" and "TYPE ..." can arrive in separate
      # reads. This drives IOSource's incremental buffering the same way a
      # socket or other streaming transport would.
      def chunked_io(xml, fragment_size)
        reader, writer = IO.pipe
        Thread.new do
          begin
            xml.chars.each_slice(fragment_size) do |fragment|
              writer.write(fragment.join)
              writer.flush
            end
          rescue Errno::EPIPE
            # The parser may stop reading as soon as it rejects the DTD.
          ensure
            writer.close rescue nil
          end
        end
        reader
      end

      def test_doctype_split_across_fragments_is_rejected
        io = chunked_io(INTERNAL_DTD, 4)
        assert_raise(REXML::ParseException) do
          REXML::Document.new(io, disallow_dtd: true)
        end
      ensure
        io&.close
      end

      def test_doctype_token_split_character_by_character
        io = chunked_io(EXTERNAL_DTD, 1)
        parser = REXML::Parsers::PullParser.new(io, disallow_dtd: true)
        assert_raise(REXML::ParseException) do
          parser.pull while parser.has_next?
        end
      ensure
        io&.close
      end

      def test_stream_entry_rejects_split_doctype_before_callback
        listener = RecordingStreamListener.new
        io = chunked_io(INTERNAL_DTD, 3)
        assert_raise(REXML::ParseException) do
          REXML::Document.parse_stream(io, listener, disallow_dtd: true)
        end
        assert_not_include(listener.events, :doctype)
        assert_not_include(listener.events, :entitydecl)
      ensure
        io&.close
      end

      def test_clean_chunked_document_still_parses
        io = chunked_io(LOOKALIKE_XML, 5)
        document = REXML::Document.new(io, disallow_dtd: true)
        assert_nil(document.doctype)
        assert_equal("<!DOCTYPE in-cdata SYSTEM \"urn:x\">",
                     document.root.cdatas.first.value)
      ensure
        io&.close
      end

      def test_internal_dtd_chunked_keeps_entities_by_default
        io = chunked_io(INTERNAL_DTD, 6)
        document = REXML::Document.new(io)
        assert_equal("EXPANDED", document.root.text)
      ensure
        io&.close
      end
    end
  end
end
