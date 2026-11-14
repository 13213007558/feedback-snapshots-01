# frozen_string_literal: true

require_relative 'helper'
require 'weakref'

module Psych
  # Fault-injection matrix for the native parser's resource lifecycle.
  #
  # Every Ruby callback the native parser drives (IO#read, event_location and
  # the scalar / collection / document / stream events) is a point where an
  # exception can unwind through libyaml while GC runs.  These tests inject a
  # controlled failure at each of those points and then check, with evidence:
  #
  #   * the exact callback sequence observed before the failure,
  #   * the identity of the exception that comes out (its source),
  #   * that event data handed to Ruby is neither released early nor leaks
  #     into the next parse,
  #   * that both the same parser and a different parser produce a clean,
  #     identical result afterwards,
  #   * that the IO object, the parser object and the event strings are all
  #     collectable once the failed parse is over.
  #
  # A final controlled lifecycle fault proves the verification helpers
  # actually detect contamination and premature release instead of merely
  # recording "nothing crashed".
  class TestParserLifecycle < TestCase
    class FaultInjected < RuntimeError; end

    SOURCE_YAML = <<~YAML
      ---
      - &a scalar one
      - *a
      - key: value
      ...
    YAML

    RECOVERY_YAML = "--- recovered scalar\n"

    EVENTS = %i[
      event_location
      start_stream start_document end_document
      alias scalar
      start_sequence end_sequence
      start_mapping end_mapping
      end_stream
    ].freeze

    # Records the exact callback sequence, pins every string the native side
    # hands over (so premature release can be detected later), optionally runs
    # GC inside every callback, and raises a tagged exception at one chosen
    # (event, occurrence) point.
    class LifecycleHandler < Handler
      attr_reader :events, :pinned

      def initialize fault: nil, gc: false
        @fault  = fault
        @gc     = gc
        @events = []
        @pinned = []
        @seen   = Hash.new 0
      end

      EVENTS.each do |name|
        define_method(name) do |*args|
          record name, args
        end
      end

      private

      def record name, args
        GC.start if @gc
        @events << [name, args.map { |a| String === a ? a.dup : a }]
        args.each { |a| @pinned << a if String === a }
        @seen[name] += 1
        if @fault && @fault[:event] == name && @fault[:occurrence] == @seen[name]
          GC.start
          raise @fault[:error]
        end
      end
    end

    # IO-like object that fails with a tagged exception on a chosen read call,
    # runs GC inside #read, and answers in small chunks so libyaml performs
    # several reads before the failure.
    class ReadFaultIO
      attr_reader :reads

      def initialize payload, fail_at: nil, error: nil, gc: true, chunk: 4
        @payload = payload
        @offset  = 0
        @fail_at = fail_at
        @error   = error
        @gc      = gc
        @chunk   = chunk
        @reads   = 0
      end

      def external_encoding
        Encoding::UTF_8
      end

      def read size
        @reads += 1
        GC.start if @gc
        if @fail_at && @reads == @fail_at
          GC.start
          raise @error
        end
        return nil if @offset >= @payload.bytesize

        n = [size, @chunk, @payload.bytesize - @offset].min
        chunk = @payload.byteslice @offset, n
        @offset += n
        chunk
      end
    end

    # Misbehaving IO that hands the same mutable buffer object back on every
    # read, the way a careless C extension would.  The parser must copy the
    # bytes out before the next read overwrites them.
    class RecycledBufferIO
      attr_reader :buffer

      def initialize payload, chunk: 7
        @payload = payload
        @offset  = 0
        @chunk   = chunk
        @buffer  = +""
      end

      def external_encoding
        Encoding::UTF_8
      end

      def read size
        return nil if @offset >= @payload.bytesize

        n = [size, @chunk, @payload.bytesize - @offset].min
        @buffer.replace @payload.byteslice(@offset, n)
        @offset += n
        @buffer
      end
    end

    def parse_with yaml, handler = LifecycleHandler.new, parser: nil
      parser ||= Parser.new handler
      parser.handler = handler
      parser.parse yaml
      handler
    end

    def reference_events yaml
      parse_with(yaml).events
    end

    # Index just past the +occurrence+-th +name+ event in +events+.
    def prefix_length events, name, occurrence
      seen = 0
      events.each_with_index do |(event_name, *), i|
        next unless event_name == name
        seen += 1
        return i + 1 if seen == occurrence
      end
      flunk "no #{occurrence}th #{name} in reference events"
    end

    def strings_in events
      events.flat_map { |_, args| args.select { |a| String === a } }
    end

    def assert_clean_recovery actual, expected
      assert_equal expected, actual,
        "events after a failed parse must be exactly the events of the new " \
        "document: nothing missing, nothing stale from the aborted parse"
    end

    def assert_data_intact pinned, expected
      assert_equal expected, pinned,
        "strings delivered to the handler must survive GC with their " \
        "contents unchanged"
    end

    def assert_eventually_collected weakref, message
      10.times do
        GC.start
        return unless weakref.weakref_alive?
      end
      flunk message
    end

    def test_reference_document_shape
      names = reference_events(SOURCE_YAML).map(&:first)
      assert_equal %i[
        event_location start_stream
        event_location start_document
        event_location start_sequence
        event_location scalar
        event_location alias
        event_location start_mapping
        event_location scalar
        event_location scalar
        event_location end_mapping
        event_location end_sequence
        event_location end_document
        event_location end_stream
      ], names

      scalars = reference_events(SOURCE_YAML).select { |(n, *)| n == :scalar }
      assert_equal ["scalar one", "key", "value"], scalars.map { |_, a| a[0] }
    end

    # The matrix: raise at every (event, occurrence) point the document
    # reaches, with GC running inside every callback, then verify the
    # callback prefix, the exception source, data lifetime, and recovery on
    # both the same parser and a different parser.
    def test_fault_injection_matrix
      reference          = reference_events SOURCE_YAML
      recovery_reference = reference_events RECOVERY_YAML

      counts = Hash.new 0
      points = reference.map { |(name, *)| [name, counts[name] += 1] }

      points.each do |name, occurrence|
        error   = FaultInjected.new "#{name}##{occurrence}"
        handler = LifecycleHandler.new(
          fault: { event: name, occurrence: occurrence, error: error },
          gc: true)
        parser  = Parser.new handler

        raised = assert_raise(FaultInjected, "#{name}##{occurrence}") do
          parser.parse SOURCE_YAML
        end
        assert_same error, raised,
          "the exception must come from the injected fault, not the parser"

        prefix = reference[0, prefix_length(reference, name, occurrence)]
        assert_equal prefix, handler.events,
          "callback sequence before the #{name}##{occurrence} failure"

        # Same parser, reused after the failure.
        recovery = LifecycleHandler.new
        parser.handler = recovery
        parser.parse RECOVERY_YAML
        assert_clean_recovery recovery.events, recovery_reference

        # A different parser must agree with the reused one.
        assert_clean_recovery reference_events(RECOVERY_YAML), recovery.events

        # Event data from the failed parse is still alive and intact...
        GC.start
        assert_data_intact handler.pinned, strings_in(prefix)

        # ...and shares no identity with the data of the next parse.
        recovery_ids = recovery.pinned.map(&:object_id)
        assert handler.pinned.none? { |s| recovery_ids.include? s.object_id },
          "event data from the aborted parse must not be reused by the next one"
      end
    end

    def test_io_read_fault_then_same_and_other_parser
      error  = FaultInjected.new "io read blew up"
      io     = ReadFaultIO.new SOURCE_YAML, fail_at: 3, error: error
      parser = Parser.new LifecycleHandler.new

      raised = assert_raise(FaultInjected) { parser.parse io }
      assert_same error, raised
      assert_operator io.reads, :>=, 3

      recovery_reference = reference_events RECOVERY_YAML

      # Same parser, string input.
      assert_clean_recovery parse_with(RECOVERY_YAML, parser: parser).events,
        recovery_reference

      # Same parser, another IO input.
      assert_clean_recovery \
        parse_with(ReadFaultIO.new(RECOVERY_YAML), parser: parser).events,
        recovery_reference

      # A different parser agrees.
      assert_clean_recovery reference_events(RECOVERY_YAML), recovery_reference
    end

    def test_io_read_data_is_copied_before_next_read
      io      = RecycledBufferIO.new SOURCE_YAML
      handler = parse_with io

      # Overwrite the buffer the IO kept handing back, then collect garbage:
      # nothing the handler recorded may change.
      io.buffer.replace "X" * 64
      GC.start

      assert_data_intact handler.pinned, strings_in(handler.events)
      assert_equal ["scalar one", "key", "value"],
        handler.events.select { |(n, *)| n == :scalar }.map { |_, a| a[0] }
    end

    # Runs the failing parse on a short-lived thread.  Once the thread is
    # joined its machine stack is gone, so a major GC gives a deterministic
    # verdict: anything still reachable is retained by a live object, not by
    # a stale stack slot of the aborted parse.
    def fail_on_thread
      Thread.new { yield }.value
    end

    def test_failed_parse_releases_io
      pend "GC.start is only a hint on JRuby" if RUBY_PLATFORM =~ /java/

      parser = Parser.new LifecycleHandler.new
      ref = fail_on_thread do
        io = ReadFaultIO.new SOURCE_YAML, fail_at: 1,
          error: FaultInjected.new("boom")
        begin
          parser.parse io
        rescue FaultInjected
        end
        WeakRef.new io
      end
      assert_eventually_collected ref,
        "the parser must not retain the IO object after the read failed"

      # The parser itself is still usable.
      assert_clean_recovery parse_with(RECOVERY_YAML, parser: parser).events,
        reference_events(RECOVERY_YAML)
    end

    def test_failed_parse_releases_parser_and_handler
      pend "GC.start is only a hint on JRuby" if RUBY_PLATFORM =~ /java/

      parser_ref, handler_ref = fail_on_thread do
        handler = LifecycleHandler.new(
          fault: { event: :scalar, occurrence: 1, error: FaultInjected.new })
        parser = Parser.new handler
        begin
          parser.parse SOURCE_YAML
        rescue FaultInjected
        end
        [WeakRef.new(parser), WeakRef.new(handler)]
      end
      assert_eventually_collected parser_ref,
        "a parser whose parse raised must be collectable"
      assert_eventually_collected handler_ref,
        "a handler whose callback raised must be collectable"
    end

    def test_failed_parse_releases_event_strings
      pend "GC.start is only a hint on JRuby" if RUBY_PLATFORM =~ /java/

      refs = fail_on_thread do
        handler = LifecycleHandler.new(
          fault: { event: :end_stream, occurrence: 1, error: FaultInjected.new })
        begin
          Parser.new(handler).parse SOURCE_YAML
        rescue FaultInjected
        end
        handler.pinned.map { |s| WeakRef.new s }
      end
      refs.each do |ref|
        assert_eventually_collected ref,
          "event strings must be released once the failed parse is dropped"
      end
    end

    def test_parse_under_gc_stress
      GC.stress = true
      handler = parse_with "--- gc stress scalar\n"
      assert_equal [[:scalar, ["gc stress scalar", nil, nil, true, false, 1]]],
        handler.events.select { |(n, *)| n == :scalar }
      GC.start
      assert_data_intact handler.pinned, strings_in(handler.events)
    ensure
      GC.stress = false
    end

    # One controlled lifecycle fault, injected by hand, must be caught by the
    # same checks the matrix relies on.  This proves the tests identify
    # lifecycle bugs instead of only recording that nothing crashed.
    def test_controlled_lifecycle_fault_is_detected
      expected = reference_events RECOVERY_YAML

      # Simulated native bug: an event from the aborted parse survives and is
      # delivered again inside the next parse.
      contaminated = expected.dup
      contaminated.insert 2, [:scalar, ["stale from aborted parse", nil, nil, true, false, 1]]
      assert_raise(Test::Unit::AssertionFailedError) do
        assert_clean_recovery contaminated, expected
      end

      # Simulated native bug: the buffer behind an already-delivered scalar
      # is recycled, corrupting data the handler was given earlier.
      handler = parse_with SOURCE_YAML
      handler.pinned.first.replace "corrupted by buffer reuse"
      assert_raise(Test::Unit::AssertionFailedError) do
        assert_data_intact handler.pinned, strings_in(handler.events)
      end

      # Sanity: without the fault the same checks pass.
      assert_clean_recovery expected, expected
      clean = parse_with SOURCE_YAML
      assert_data_intact clean.pinned, strings_in(clean.events)
    end
  end
end
