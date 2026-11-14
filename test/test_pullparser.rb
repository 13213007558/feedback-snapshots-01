# frozen_string_literal: false

require 'rexml/parsers/pullparser'

module REXMLTests
  class PullParserTester < Test::Unit::TestCase
    include REXML
    def test_basics
      source = '<?xml version="1.0"?>
      <!DOCTYPE blah>
      <a>foo &lt;<b attribute="value">bar</b> nooo</a>'
      parser = REXML::Parsers::PullParser.new(source)
      res = { :text=>0 }
      until parser.empty?
        results = parser.pull
        res[ :xmldecl ] = true if results.xmldecl?
        res[ :doctype ] = true if results.doctype?
        res[ :a ] = true if results.start_element? and results[0] == 'a'
        if results.start_element? and results[0] == 'b'
          res[ :b ] = true
          assert_equal 'value', results[1]['attribute']
        end
        res[ :text ] += 1 if results.text?
      end
      [ :xmldecl, :doctype, :a, :b ].each { |tag|
        assert res[tag] , "#{tag} wasn't processed"
      }
      assert_equal 4, res[ :text ]
    rescue ParseException
      puts $!
    end

    def test_bad_document
      source = "<a><b></a>"
      parser = REXML::Parsers::PullParser.new(source)
      assert_raise(ParseException, "Parsing should have failed") {
        parser.pull while parser.has_next?
      }
    end

    def test_entity_replacement
      source = '<!DOCTYPE foo [
      <!ENTITY la "1234">
      <!ENTITY lala "--&la;--">
      <!ENTITY lalal "&la;&la;">
      ]><a><la>&la;</la><lala>&lala;</lala></a>'
      pp = REXML::Parsers::PullParser.new( source )
      el_name = ''
      while pp.has_next?
        event = pp.pull
        case event.event_type
        when :start_element
          el_name = event[0]
        when :text
          case el_name
          when 'la'
            assert_equal('1234', event[1])
          when 'lala'
            assert_equal('--1234--', event[1])
          end
        end
      end
    end

    def test_character_references
      source = '<root><a>&#65;</a><b>&#x42;</b></root>'
      parser = REXML::Parsers::PullParser.new( source )

      events = {}
      element_name = ''
      while parser.has_next?
        event = parser.pull
        case event.event_type
        when :start_element
          element_name = event[0]
        when :text
          events[element_name] = event[1]
        end
      end

      assert_equal('A', events['a'])
      assert_equal("B", events['b'])
    end

    def test_text_entity_references
      source = '<root><a>&lt;P&gt; &lt;I&gt; &lt;B&gt; Text &lt;/B&gt;  &lt;/I&gt;</a></root>'
      parser = REXML::Parsers::PullParser.new( source )

      events = []
      while parser.has_next?
        event = parser.pull
        case event.event_type
        when :text
          events << event[1]
        end
      end

      assert_equal(["<P> <I> <B> Text </B>  </I>"], events)
    end

    def test_text_content_with_line_breaks
      source = "<root><a>A</a><b>B\n</b><c>C\r\n</c></root>"
      parser = REXML::Parsers::PullParser.new( source )

      events = {}
      element_name = ''
      while parser.has_next?
        event = parser.pull
        case event.event_type
        when :start_element
          element_name = event[0]
        when :text
          events[element_name] = event[1]
        end
      end

      assert_equal('A', events['a'])
      assert_equal("B\n", events['b'])
      assert_equal("C\n", events['c'])
    end

    def test_peek_unshift
      source = "<a><b/></a>"
      REXML::Parsers::PullParser.new(source)
      # FINISH ME!
    end

    def test_inspect
      xml =  '<a id="1"><b id="2">Hey</b></a>'
      parser = Parsers::PullParser.new( xml )
      while parser.has_next?
        pull_event = parser.pull
        if pull_event.start_element?
          peek = parser.peek()
          peek.inspect
        end
      end
    end

    def test_peek
      xml =  '<a id="1"><b id="2">Hey</b></a>'
      parser = Parsers::PullParser.new( xml )
      names = %w{ a b }
      while parser.has_next?
        pull_event = parser.pull
        if pull_event.start_element?
          assert_equal( :start_element, pull_event.event_type )
          assert_equal( names.shift, pull_event[0] )
          if names[0] == 'b'
            peek = parser.peek()
            assert_equal( :start_element, peek.event_type )
            assert_equal( names[0], peek[0] )
          end
        end
      end
      assert_equal( 0, names.length )
    end

    def test_peek_does_not_change_decoded_events
      source = <<-XML
<!DOCTYPE member [
  <!ENTITY a "A">
  <!ENTITY b "--&a;--">
  <!ENTITY c "&b;&b;">
]>
<member>&c;&c;</member>
      XML

      baseline_parser = REXML::Parsers::PullParser.new(source)
      baseline = collect_event_signatures(baseline_parser)
      baseline_count = baseline_parser.entity_expansion_count
      assert_operator(baseline_count, :>, 0)
      expanded = baseline.find do |event|
        event[0] == :text and event[1] == "&c;&c;"
      end
      assert_equal("--A----A----A----A--", expanded[2])

      # peek(0) before each pull
      parser = REXML::Parsers::PullParser.new(source)
      events = []
      while parser.has_next?
        event = parser.peek(0)
        events << event_signature(event)
        parser.pull
        break if event.event_type == :end_document
      end
      assert_equal(baseline, events)
      assert_equal(baseline_count, parser.entity_expansion_count)

      # deep peek before reading anything
      parser = REXML::Parsers::PullParser.new(source)
      assert_equal(:end_document, parser.peek(100).event_type)
      assert_equal(baseline, collect_event_signatures(parser))
      assert_equal(baseline_count, parser.entity_expansion_count)

      # repeated deep peeks
      parser = REXML::Parsers::PullParser.new(source)
      10.times { parser.peek(100) }
      assert_equal(baseline, collect_event_signatures(parser))
      assert_equal(baseline_count, parser.entity_expansion_count)

      # peek(-1) prepares the whole document
      parser = REXML::Parsers::PullParser.new(source)
      parser.peek(-1)
      assert_equal(baseline, collect_event_signatures(parser))
      assert_equal(baseline_count, parser.entity_expansion_count)

      # rollback: pull, put the event back, pull it again
      parser = REXML::Parsers::PullParser.new(source)
      events = []
      loop do
        event = parser.pull
        parser.unshift(event)
        replayed = parser.pull
        assert_same(event, replayed)
        events << event_signature(replayed)
        break if event.event_type == :end_document
      end
      assert_equal(baseline, events)
      assert_equal(baseline_count, parser.entity_expansion_count)
    end

    def test_peek_rejects_entity_expansion_limit
      source = <<-XML
<!DOCTYPE member [
  <!ENTITY a "&b;&b;&b;&b;">
  <!ENTITY b "&c;&c;&c;&c;">
  <!ENTITY c "&d;&d;&d;&d;">
  <!ENTITY d "xxxx">
]>
<member>&a;</member>
      XML
      limit = 50

      result = parse_events_until_error(source, :entity_expansion_limit, limit,
                                        ->(parser) { parser.peek(100) })
      assert_equal(RuntimeError, result[:error_class])
      assert_equal("number of entity expansions exceeded, processing aborted.",
                   result[:error_message])
      result = drain_after_error(result)
      assert_equal(false, result[:has_next_after_error])
      assert_equal(true, result[:empty_after_error])
      assert_not_include_text_event(result[:events])
      assert_operator(result[:entity_expansion_count], :>, limit)

      # The same limit is enforced when only the text event is peeked after
      # the declarations and the start tag have been consumed.
      parser = REXML::Parsers::PullParser.new(source)
      parser.entity_expansion_limit = limit
      7.times { parser.pull }
      assert_raise(RuntimeError.new(result[:error_message])) do
        parser.peek(0)
      end
      assert_equal(false, parser.has_next?)
      assert_raise(RuntimeError.new(result[:error_message])) do
        parser.pull
      end

      # The read order without any peek rejects at the same place.
      parser = REXML::Parsers::PullParser.new(source)
      parser.entity_expansion_limit = limit
      assert_raise(RuntimeError.new(result[:error_message])) do
        while parser.has_next?
          parser.pull
        end
      end
      assert_operator(parser.entity_expansion_count, :>, limit)
    end

    def test_read_order_does_not_change_security_rejection
      cases = {
        "entity expansion limit" => [
          <<-XML,
<!DOCTYPE member [
  <!ENTITY a "&b;&b;&b;&b;">
  <!ENTITY b "&c;&c;&c;&c;">
  <!ENTITY c "&d;&d;&d;&d;">
  <!ENTITY d "xxxx">
]>
<member>&a;</member>
          XML
          :entity_expansion_limit,
          50,
        ],
        "entity expansion text limit" => [
          <<-XML,
<!DOCTYPE member [
  <!ENTITY a "&b;&b;&b;">
  <!ENTITY b "&c;&d;&e;">
  <!ENTITY c "xxxxxxxxxx">
  <!ENTITY d "yyyyyyyyyy">
  <!ENTITY e "zzzzzzzzzz">
]>
<member>&a;</member>
          XML
          :entity_expansion_text_limit,
          50,
        ],
        "recursive entity" => [
          <<-XML,
<!DOCTYPE member [
  <!ENTITY a "&b;">
  <!ENTITY b "&a;">
]>
<member>&a;</member>
          XML
          :entity_expansion_limit,
          100000,
        ],
      }

      look_aheads = {
        "peek(0)" => ->(parser) { parser.peek(0) },
        "peek(100)" => ->(parser) { parser.peek(100) },
        "repeated peek" => ->(parser) { 5.times { parser.peek(50) } },
        "peek(-1)" => ->(parser) { parser.peek(-1) },
      }

      cases.each do |name, (source, limit_name, limit)|
        baseline = parse_events_until_error(source, limit_name, limit) do |parser|
          nil
        end

        look_aheads.each do |look_ahead_name, look_ahead|
          actual = parse_events_until_error(source, limit_name, limit,
                                            look_ahead)
          message = "#{name} / #{look_ahead_name}"
          actual = drain_after_error(actual)
          baseline = drain_after_error(baseline)

          assert_equal(baseline[:events], actual[:events], message)
          assert_equal(baseline[:error_class], actual[:error_class], message)
          assert_equal(baseline[:error_message], actual[:error_message],
                       message)
          assert_equal(baseline[:entity_expansion_count],
                       actual[:entity_expansion_count],
                       message)
          assert_equal(false, actual[:has_next_after_error], message)
          assert_equal(true, actual[:empty_after_error], message)
        end
      end
    end

    def test_peek_rejects_recursive_entity
      source = <<-XML
<!DOCTYPE member [
  <!ENTITY a "&b;">
  <!ENTITY b "&a;">
]>
<member>&a;</member>
      XML

      result = parse_events_until_error(source, :entity_expansion_limit,
                                        100000)
      assert_equal(REXML::ParseException, result[:error_class])
      assert_match(/Detected an entity reference loop: a/,
                   result[:error_message])
      result = drain_after_error(result)
      assert_equal(false, result[:has_next_after_error])
      assert_equal(true, result[:empty_after_error])
      assert_not_include_text_event(result[:events])

      parser = REXML::Parsers::PullParser.new(source)
      assert_raise(REXML::ParseException) do
        while parser.has_next?
          parser.pull
        end
      end
    end

    def test_peek_rejects_entity_expansion_text_limit
      source = <<-XML
<!DOCTYPE member [
  <!ENTITY a "&b;&b;&b;">
  <!ENTITY b "&c;&d;&e;">
  <!ENTITY c "xxxxxxxxxx">
  <!ENTITY d "yyyyyyyyyy">
  <!ENTITY e "zzzzzzzzzz">
]>
<member>&a;</member>
      XML

      result = parse_events_until_error(source, :entity_expansion_text_limit,
                                        50, ->(parser) { parser.peek(100) })
      assert_equal(RuntimeError, result[:error_class])
      assert_equal("entity expansion has grown too large",
                   result[:error_message])
      result = drain_after_error(result)
      assert_equal(false, result[:has_next_after_error])
      assert_equal(true, result[:empty_after_error])
      assert_not_include_text_event(result[:events])
    end

    def test_reset_does_not_unlock_failed_document
      source = <<-XML
<!DOCTYPE member [<!ENTITY a "&b;&b;">]><member>&a;</member><tail>unreviewed</tail>
      XML

      parser = REXML::Parsers::PullParser.new(source)
      parser.entity_expansion_limit = 0
      assert_raise(RuntimeError) do
        parser.peek(100)
      end
      parser.reset
      assert_equal(false, parser.has_next?)
      assert_equal(true, parser.empty?)
      assert_raise(RuntimeError) do
        parser.pull
      end
      assert_raise(RuntimeError) do
        parser.peek(0)
      end
    end

    def test_reset_discards_peeked_state_for_new_document
      sources = [
        %q{<?xml version="1.0"?><!DOCTYPE message [<!ENTITY x "X1">]>} +
          "<message>First &x;</message>",
        %q{<?xml version="1.0"?><!DOCTYPE message [<!ENTITY y "Y2">]>} +
          "<message>Second &y;</message>",
        %q{<?xml version="1.0"?><!DOCTYPE message [<!ENTITY x "X3">]>} +
          "<message>Third &x;</message>",
      ]
      expected = sources.collect do |source|
        parser = REXML::Parsers::PullParser.new(source)
        [collect_document_event_signatures(parser),
         parser.entity_expansion_count]
      end

      IO.pipe do |reader, writer|
        sources.each {|source| writer.write(source)}
        writer.close

        parser = REXML::Parsers::PullParser.new(reader)
        actual = []
        while parser.has_next?
          assert_equal(:end_document, parser.peek(100).event_type)
          parser.peek(0)
          parser.peek(5)
          parser.peek(-1)
          actual << [collect_document_event_signatures(parser),
                     parser.entity_expansion_count]
          parser.reset
        end
        assert_equal(expected, actual)
      end
    end

    def test_reset
      xml_chunks = [
        "<message>First valid and complete message</message>",
        "<message>Second valid and complete message</message>",
        "<message>Third valid and complete message</message>"
      ]

      messages = []

      IO.pipe do |reader, writer|
        xml_chunks.each do |chunk|
          writer.write(chunk)
        end
        writer.close

        parser = REXML::Parsers::PullParser.new(reader)
        while parser.has_next?
          parser.pull
          message_text = parser.pull
          messages << message_text[0]
          parser.pull
          parser.reset
        end
      end

      assert_equal(
        messages,
        ["First valid and complete message",
         "Second valid and complete message",
         "Third valid and complete message"]
      )
    end

    private

    def collect_event_signatures(parser)
      events = []
      while parser.has_next?
        event = parser.pull
        events << event_signature(event)
        break if event.event_type == :end_document
      end
      events
    end

    def collect_document_event_signatures(parser)
      events = []
      while parser.has_next?
        event = parser.pull
        events << event_signature(event)
        break if event.event_type == :end_element
      end
      events
    end

    def parse_events_until_error(source, limit_name, limit, look_ahead=nil)
      parser = REXML::Parsers::PullParser.new(source)
      parser.public_send("#{limit_name}=", limit)
      events = []
      error = nil
      begin
        while parser.has_next?
          look_ahead.call(parser) if look_ahead
          event = parser.pull
          events << event_signature(event)
        end
      rescue StandardError => caught
        error = caught
      end
      {
        events: events,
        parser: parser,
        error_class: error&.class,
        error_message: error&.message,
        entity_expansion_count: parser.entity_expansion_count,
        has_next_after_error: parser.has_next?,
        empty_after_error: parser.empty?,
      }
    end

    def drain_after_error(result)
      parser = result[:parser]
      while parser.has_next?
        result[:events] << event_signature(parser.pull)
      end
      assert_raise(result[:error_class]) do
        parser.pull
      end
      result.merge(
        has_next_after_error: parser.has_next?,
        empty_after_error: parser.empty?,
        entity_expansion_count: parser.entity_expansion_count
      )
    end

    def assert_not_include_text_event(events)
      events.each do |event|
        assert_not_equal(:text, event[0], "unreviewed text was delivered")
      end
    end

    def event_signature(event)
      case event.event_type
      when :text
        [event.event_type, event[0], event[1]]
      when :entitydecl
        [event.event_type, event[0], event[1]]
      else
        [event.event_type]
      end
    end

    class EntityExpansionLimitTest < Test::Unit::TestCase
      class GeneralEntityTest < self
        def test_have_value
          source = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE member [
  <!ENTITY a "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
  <!ENTITY b "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
  <!ENTITY c "&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;">
  <!ENTITY d "&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;">
  <!ENTITY e "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx">
]>
<member>
&a;
</member>
          XML

          parser = REXML::Parsers::PullParser.new(source)
          assert_raise(RuntimeError.new("entity expansion has grown too large")) do
            while parser.has_next?
              parser.pull
            end
          end
        end

        def test_empty_value
          source = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE member [
  <!ENTITY a "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
  <!ENTITY b "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
  <!ENTITY c "&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;">
  <!ENTITY d "&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;">
  <!ENTITY e "">
]>
<member>
&a;
</member>
          XML

          parser = REXML::Parsers::PullParser.new(source)
          parser.entity_expansion_limit = 100000
          while parser.has_next?
            parser.pull
          end
          assert_equal(11111, parser.entity_expansion_count)

          parser = REXML::Parsers::PullParser.new(source)
          assert_raise(RuntimeError.new("number of entity expansions exceeded, processing aborted.")) do
            while parser.has_next?
              parser.pull
            end
          end
          assert do
            parser.entity_expansion_count > REXML::Security.entity_expansion_limit
          end
        end

        def test_with_default_entity
          source = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE member [
  <!ENTITY a "a">
  <!ENTITY a2 "&a; &a;">
]>
<member>
&a;
&a2;
&lt;
</member>
          XML

          parser = REXML::Parsers::PullParser.new(source)
          parser.entity_expansion_limit = 4
          while parser.has_next?
            parser.pull
          end

          parser = REXML::Parsers::PullParser.new(source)
          parser.entity_expansion_limit = 3
          assert_raise(RuntimeError.new("number of entity expansions exceeded, processing aborted.")) do
            while parser.has_next?
              parser.pull
            end
          end
        end

        def test_with_only_default_entities
          member_value = "&lt;p&gt;#{'A' * REXML::Security.entity_expansion_text_limit}&lt;/p&gt;"
          source = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<member>
#{member_value}
</member>
          XML

          parser = REXML::Parsers::PullParser.new(source)
          events = {}
          element_name = ''
          while parser.has_next?
            event = parser.pull
            case event.event_type
            when :start_element
              element_name = event[0]
            when :text
              events[element_name] = event[1]
            end
          end

          expected_value = "<p>#{'A' * REXML::Security.entity_expansion_text_limit}</p>"
          assert_equal(expected_value, events['member'].strip)
          assert_equal(0, parser.entity_expansion_count)
          assert do
            events['member'].bytesize > REXML::Security.entity_expansion_text_limit
          end
        end

        def test_entity_expansion_text_limit
          source = <<-XML
<!DOCTYPE member [
  <!ENTITY a "&b;&b;&b;">
  <!ENTITY b "&c;&d;&e;">
  <!ENTITY c "xxxxxxxxxx">
  <!ENTITY d "yyyyyyyyyy">
  <!ENTITY e "zzzzzzzzzz">
]>
<member>&a;</member>
          XML

          parser = REXML::Parsers::PullParser.new(source)
          parser.entity_expansion_text_limit = 90
          events = {}
          element_name = ''
          while parser.has_next?
            event = parser.pull
            case event.event_type
            when :start_element
              element_name = event[0]
            when :text
              events[element_name] = event[1]
            end
          end
          assert_equal(90, events['member'].size)
        end
      end
    end
  end
end
