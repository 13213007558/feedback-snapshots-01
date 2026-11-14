# frozen_string_literal: false
require 'forwardable'

require_relative '../parseexception'
require_relative 'baseparser'
require_relative '../xmltokens'

module REXML
  module Parsers
    # = Using the Pull Parser
    # <em>This API is experimental, and subject to change.</em>
    #  parser = PullParser.new( "<a>text<b att='val'/>txet</a>" )
    #  while parser.has_next?
    #    res = parser.next
    #    puts res[1]['att'] if res.start_tag? and res[0] == 'b'
    #  end
    # See the PullEvent class for information on the content of the results.
    # The data is identical to the arguments passed for the various events to
    # the StreamListener API.
    #
    # Notice that:
    #  parser = PullParser.new( "<a>BAD DOCUMENT" )
    #  while parser.has_next?
    #    res = parser.next
    #    raise res[1] if res.error?
    #  end
    #
    # Nat Price gave me some good ideas for the API.
    class PullParser
      include XMLTokens
      extend Forwardable

      def_delegators( :@parser, :entity )
      def_delegators( :@parser, :source )

      def initialize stream
        @entities = {}
        @listeners = nil
        @parser = BaseParser.new( stream )
        @my_stack = []
        @element_depth = 0
        @document_finished = false
        @failure = nil
      end

      def add_listener( listener )
        @listeners = [] unless @listeners
        @listeners << listener
      end

      def entity_expansion_count
        @parser.entity_expansion_count
      end

      def entity_expansion_limit=( limit )
        @parser.entity_expansion_limit = limit
      end

      def entity_expansion_text_limit=( limit )
        @parser.entity_expansion_text_limit = limit
      end

      def each
        while has_next?
          yield self.pull
        end
      end

      def empty?
        !has_next?
      end

      def has_next?
        return true unless @my_stack.empty?
        return false if @failure
        @parser.has_next?
      end

      def peek depth=0
        raise %Q[Illegal argument "#{depth}"] if depth < -1
        if @failure
          # Reviewed events that were decoded before the failure are still
          # safe to observe.  Anything beyond them would need to read the
          # source again, which is forbidden until a new parser is used.
          if depth == -1
            return @my_stack.last unless @my_stack.empty?
          elsif depth < @my_stack.length
            return @my_stack[depth]
          end
          raise_failure
        end
        begin
          if depth == -1
            until document_boundary?
              @my_stack.push(decode_event(@parser.pull))
            end
            return @my_stack.last || end_document_event
          end
          while @my_stack.length <= depth and !document_boundary?
            @my_stack.push(decode_event(@parser.pull))
          end
          return @my_stack[depth] if depth < @my_stack.length
        rescue StandardError => error
          abort_with(error)
        end
        # Nothing but the :end_document sentinel is left.  It is not a real
        # event of the document, so do not buffer it: deep peeks all observe
        # the same sentinel and a following pull sees the same event stream
        # as a parser that never looked ahead.
        end_document_event
      end

      def pull
        return @my_stack.shift unless @my_stack.empty?
        raise_failure if @failure
        begin
          decode_event(@parser.pull)
        rescue StandardError => error
          abort_with(error)
        end
      end

      def unshift token
        @my_stack.unshift token
      end

      def reset
        # Start a new document.  The old document's buffered events, entity
        # table and expansion budget must not leak into the new one.
        #
        # A latched failure is intentionally kept: reset can't resynchronize a
        # stream whose document failed an entity check, so the unreviewed tail
        # of that document must stay unreachable.  Use a new parser to parse a
        # new document after such a failure.
        @my_stack.clear
        @entities.clear
        @element_depth = 0
        @document_finished = false
        @parser.reset
      end

      private

      def end_document_event
        PullEvent.new([:end_document])
      end

      # True when the root element has been closed and continuing would start
      # a new document instead of continuing the current one.  Pre-reading
      # must never consume the next document: #reset is the only supported
      # way to move to it.
      #
      # Trailing comments and non-XML processing instructions still belong to
      # the current document.  An XML declaration starts a new document.
      def document_boundary?
        return false unless @document_finished
        source = @parser.source
        source.ensure_buffer
        rest = source.buffer
        # Scan bytes so a malformed tail can't raise an encoding error here.
        first_non_space = rest.b.index(/[^ \t\r\n\f\v]/n)
        return true if first_non_space.nil?
        # A trailing comment or a non-declaration processing instruction
        # (for example, xml-stylesheet) still belongs to this document.
        prefix = rest.byteslice(first_non_space, 6)
        if prefix.start_with?("<!--")
          false
        elsif prefix.start_with?("<?")
          !!(prefix =~ /\A<\?xml(?:\s|\?>)/n)
        else
          true
        end
      end

      # Decode an event exactly once, when it is read from the underlying
      # parser.  Both #pull and #peek use this path, so buffered events are
      # already decoded and entity expansion is charged exactly once no matter
      # how deeply or how often the caller looks ahead.
      def decode_event event
        case event[0]
        when :entitydecl
          @entities[ event[1] ] =
            event[2] unless event[2] =~ /PUBLIC|SYSTEM/
        when :start_element
          @element_depth += 1
        when :end_element
          @element_depth -= 1
          @document_finished = true if @element_depth == 0
        when :text
          unnormalized = @parser.unnormalize( event[1], @entities )
          event << unnormalized
        end
        PullEvent.new( event )
      end

      # Once decoding fails (for example, an entity expansion limit is hit or
      # a recursive entity is found), stop reading the source.  Events that
      # were decoded before the failure are already reviewed and charged, so
      # they stay deliverable; the failure is then repeated forever and no
      # later event, including any text from the failed expansion, can be
      # pulled.  This makes the delivered event sequence and the expansion
      # count independent of how far the consumer pre-read.
      def abort_with(error)
        @failure = error
        raise error
      end

      def raise_failure
        raise @failure
      end
    end

    # A parsing event.  The contents of the event are accessed as an +Array?,
    # and the type is given either by the ...? methods, or by accessing the
    # +type+ accessor.  The contents of this object vary from event to event,
    # but are identical to the arguments passed to +StreamListener+s for each
    # event.
    class PullEvent
      # The type of this event.  Will be one of :tag_start, :tag_end, :text,
      # :processing_instruction, :comment, :doctype, :attlistdecl, :entitydecl,
      # :notationdecl, :entity, :cdata, :xmldecl, or :error.
      def initialize(arg)
        @contents = arg
      end

      def []( start, endd=nil)
        if start.kind_of? Range
          @contents.slice( start.begin+1 .. start.end )
        elsif start.kind_of? Numeric
          if endd.nil?
            @contents.slice( start+1 )
          else
            @contents.slice( start+1, endd )
          end
        else
          raise "Illegal argument #{start.inspect} (#{start.class})"
        end
      end

      def event_type
        @contents[0]
      end

      # Content: [ String tag_name, Hash attributes ]
      def start_element?
        @contents[0] == :start_element
      end

      # Content: [ String tag_name ]
      def end_element?
        @contents[0] == :end_element
      end

      # Content: [ String raw_text, String unnormalized_text ]
      def text?
        @contents[0] == :text
      end

      # Content: [ String text ]
      def instruction?
        @contents[0] == :processing_instruction
      end

      # Content: [ String text ]
      def comment?
        @contents[0] == :comment
      end

      # Content: [ String name, String pub_sys, String long_name, String uri ]
      def doctype?
        @contents[0] == :start_doctype
      end

      # Content: [ String text ]
      def attlistdecl?
        @contents[0] == :attlistdecl
      end

      # Content: [ String text ]
      def elementdecl?
        @contents[0] == :elementdecl
      end

      # Due to the wonders of DTDs, an entity declaration can be just about
      # anything.  There's no way to normalize it; you'll have to interpret the
      # content yourself.  However, the following is true:
      #
      # * If the entity declaration is an internal entity:
      #   [ String name, String value ]
      # Content: [ String text ]
      def entitydecl?
        @contents[0] == :entitydecl
      end

      # Content: [ String text ]
      def notationdecl?
        @contents[0] == :notationdecl
      end

      # Content: [ String text ]
      def entity?
        @contents[0] == :entity
      end

      # Content: [ String text ]
      def cdata?
        @contents[0] == :cdata
      end

      # Content: [ String version, String encoding, String standalone ]
      def xmldecl?
        @contents[0] == :xmldecl
      end

      def error?
        @contents[0] == :error
      end

      def inspect
        @contents[0].to_s + ": " + @contents[1..-1].inspect
      end
    end
  end
end
