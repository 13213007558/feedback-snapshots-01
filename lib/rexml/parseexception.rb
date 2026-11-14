# frozen_string_literal: false
module REXML
  # A parse failure, structured so that security event logs can locate the
  # original evidence (raw byte position, parse phase, cause chain) while
  # the default rendering stays safe for ordinary logs: it never contains
  # the input body nor the messages of nested exceptions, both of which may
  # carry tokens, passwords, or other secrets found in the parsed document.
  #
  # The full evidence (including an input excerpt and nested exception
  # details) is available via #full_report and #to_h, and is emitted by
  # #to_s only when controlled diagnostics are explicitly enabled:
  #
  #   REXML::ParseException.diagnostics_enabled = true
  #
  # or by setting the environment variable REXML_DIAGNOSTICS=true.
  class ParseException < RuntimeError
    attr_accessor :source, :parser, :continued_exception
    # The parse phase (a Symbol such as :xml_declaration, :doctype,
    # :element, :text or :entity_expansion) in which the failure occurred,
    # or nil when the parser did not tag one.
    attr_reader :phase
    # The byte offset in the original (undecoded) input that corresponds
    # to the failure, or nil when it could not be determined.  For
    # transcoded inputs (e.g. UTF-16) this is computed back into raw
    # input bytes, so it always addresses the original evidence.
    attr_reader :byte_position

    class << self
      # Controls whether #to_s includes controlled diagnostic details
      # (input excerpt and nested exception messages).  Disabled by
      # default; can also be enabled with REXML_DIAGNOSTICS=true.
      attr_writer :diagnostics_enabled

      def diagnostics_enabled?
        if defined?(@diagnostics_enabled) && !@diagnostics_enabled.nil?
          @diagnostics_enabled
        else
          ENV["REXML_DIAGNOSTICS"] == "true"
        end
      end
    end

    def initialize( message, source=nil, parser=nil, exception=nil, phase: nil )
      super(message)
      @source = source
      @parser = parser
      @continued_exception = exception
      # Snapshot the location information now: formatting the exception
      # later must not perform IO nor consume further input.
      @context = safe_current_line
      @byte_position = safe_raw_byte_position
      @phase = phase
      @phase ||= source.parse_phase if source.respond_to?(:parse_phase)
    end

    # The default rendering: safe for ordinary logs.  It contains the
    # message, the location, and the class names of the cause chain, but
    # never the input body nor nested exception messages.
    def to_s
      return full_report if self.class.diagnostics_enabled?

      err = raw_message.dup
      if @source
        err << "\nLine: #{line}\n"
        err << "Position: #{position}"
      end
      causes.each do |cause|
        err << "\nCaused by: #{cause.class}"
      end
      err
    end

    # The controlled diagnostic rendering: everything in #to_s plus the
    # raw byte position, the parse phase, an excerpt of the unconsumed
    # input, and the full cause chain with messages and backtraces.
    # Only write this to logs that are allowed to contain input data.
    def full_report
      err = +""
      # Quote the original exception, if there was one
      if @continued_exception
        err << @continued_exception.inspect
        err << "\n"
        err << @continued_exception.backtrace.join("\n") if @continued_exception.backtrace
        err << "\n...\n"
      end

      # Get the stack trace and error message
      err << raw_message

      # Add contextual information
      if @source
        err << "\nLine: #{line}\n"
        err << "Position: #{position}\n"
        err << "Byte: #{@byte_position}\n" if @byte_position
        err << "Phase: #{@phase}\n" if @phase
        err << "Last 80 unconsumed characters:\n"
        err.force_encoding("ASCII-8BIT")
        err << @source.buffer[0..80].force_encoding("ASCII-8BIT").gsub(/\n/, ' ')
      end

      err
    end

    # A structured record of the failure, suitable for security event
    # logs.  Note that, like #full_report, the cause messages may echo
    # input content; use #to_s for ordinary logs.
    def to_h
      {
        message: raw_message,
        line: line,
        position: position,
        byte_position: @byte_position,
        phase: @phase,
        causes: causes.map do |cause|
          {class: cause.class.name, message: cause.message}
        end,
      }
    end

    # The exceptions that led to this failure, innermost last.
    def causes
      list = []
      seen = {}
      cause = @continued_exception
      while cause && !seen[cause.object_id]
        seen[cause.object_id] = true
        list << cause
        cause = cause.continued_exception if cause.respond_to?(:continued_exception)
        cause = nil unless cause.is_a?(Exception)
      end
      list
    end

    def position
      @context[0] if @context
    end

    def line
      @context[2] if @context
    end

    def context
      @context
    end

    private

    # The message as passed to the constructor, bypassing our own #to_s
    # (Exception#message would otherwise call the overridden #to_s).
    def raw_message
      Exception.instance_method(:to_s).bind(self).call
    end

    def safe_current_line
      return nil unless @source && @source.respond_to?(:current_line)
      @source.current_line
    rescue StandardError
      nil
    end

    def safe_raw_byte_position
      return nil unless @source && @source.respond_to?(:raw_byte_position)
      @source.raw_byte_position
    rescue StandardError
      nil
    end
  end
end
