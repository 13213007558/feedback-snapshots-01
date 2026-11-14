# frozen_string_literal: true

require "set"

module Net
  class IMAP

    # :call-seq:
    #   DebugLogger.new(config, output: $stderr)
    #
    # Logs the raw bytes sent to and received from the IMAP server while
    # preserving the order and direction of every protocol exchange.
    #
    # Two output modes are selected via Config#debug_mode:
    #
    # +:safe+ (the default) redacts credentials and literal message data before
    # anything is written.  Redaction follows the IMAP protocol state and the
    # actual byte boundaries on the wire, rather than searching the log for
    # secret-looking strings:
    #
    # * The password argument of a +LOGIN+ command is redacted, whether it is
    #   encoded as an atom, a quoted string, or a literal.
    # * The initial response of an +AUTHENTICATE+ command and every client
    #   response of a \SASL continuation exchange are redacted.
    # * The payload of every server continuation challenge issued while a
    #   \SASL exchange is in progress is redacted.
    # * The contents of every literal, in either direction, are redacted.  This
    #   hides message bodies (e.g. from +FETCH+ or +APPEND+) while retaining the
    #   declared literal length.
    #
    # Each redaction preserves the byte length, direction (+C:+ for client bytes
    # and +S:+ for server bytes), and the associated command tag, so connection
    # problems remain diagnosable without exposing secrets.
    #
    # +:raw+ preserves the historical behavior of Config#debug: every byte is
    #   printed verbatim, including passwords, tokens, and message bodies.  Use
    #   Config#debug_mode= or the +debug_mode:+ keyword of Net::IMAP.new to
    #   explicitly select it.
    #
    # This class is internal and its API is not guaranteed to be stable.
    class DebugLogger # :nodoc: all

      # Matches a literal header embedded at the end of a protocol line.
      EMBEDDED_LITERAL_SUFFIX = /(~?)\{(\d+)\+?\}\r\n\z/n

      # Matches the tag and command name at the start of a client command.
      COMMAND_PREFIX = /\A(\S+)[ \t]+(\S+)/n

      REDACTED = '<REDACTED %d bytes>'.freeze

      def initialize(config, output: $stderr)
        @config = config
        @output = output
        @mutex  = Thread::Mutex.new
        # Direction-specific reassembly buffers.
        @client_buffer = String.new.b
        @server_buffer = String.new.b
        # In-progress literal state, per direction.
        @client_literal_active    = false
        @client_literal_remaining = 0
        @client_literal_redact    = false
        @client_literal_size      = nil
        @client_literal_chunks    = String.new.b
        @server_literal_active    = false
        @server_literal_remaining = 0
        @server_literal_redact    = false
        @server_literal_size      = nil
        # Suppresses a bare terminating CRLF after a redacted final literal.
        @suppress_next_client_crlf = false
        @suppress_next_server_crlf = false
        # Redaction decision for each client literal header, in arrival order.
        @client_literal_decisions = []
        # Tags of in-progress SASL exchanges, shared across both directions.
        @sasl_tags = Set.new
        # Beginning-of-line state for the verbatim (+:raw+) mode.  This mirrors
        # the original single shared debug BOL flag used for client writes.
        @raw_bol = true
      end

      # Logs bytes written to the socket by the client.  +bytes+ may be a
      # partial chunk of a command, a literal header, or a literal payload.
      def client_write(bytes)
        return unless @config.debug?
        if @config.debug_mode == :raw
          raw_client_write(bytes)
        else
          @mutex.synchronize do
            @client_buffer << bytes.b
            drain_client
          end
        end
      end

      # Logs a complete response buffer read by the receiver thread.  The
      # buffer is one full response, but may contain multiple lines and
      # multi-line literals.
      def server_read(buffer)
        return unless @config.debug?
        if @config.debug_mode == :raw
          @output.print(buffer.gsub(/^/n, "S: "))
        else
          @mutex.synchronize do
            @server_buffer << buffer.b
            drain_server
          end
        end
      end

      private

      # Verbatim client output, matching the original Config#debug behavior.
      def raw_client_write(bytes)
        @output.print("C: ") if @raw_bol
        @output.print(bytes.gsub(/\n/n) { $'.empty? ? $& : "\nC: " })
        @raw_bol = !/\n\z/n.match?(bytes)
      end

      # Prefixes every physical line of +text+ with the direction marker.
      def emit(prefix, text)
        @output.print(text.gsub(/^/n, "#{prefix}: "))
      end

      # Emits a redaction marker on its own prefixed line.  The marker records
      # the number of redacted bytes; it never ends with the original CRLF, so
      # a following frame always starts on a new prefixed line.
      def emit_redacted(prefix, size)
        @output.print("#{prefix}: #{redacted(size)}\n")
      end

      def redacted(size) REDACTED % size end

      # ---- client direction -------------------------------------------------

      def drain_client
        until @client_buffer.empty?
          if @client_literal_active
            take_client_literal
          elsif (index = @client_buffer.index(CRLF))
            line = @client_buffer.slice!(0, index + 2)
            process_client_line(line)
          else
            break
          end
        end
      end

      def take_client_literal
        if @client_literal_remaining.zero?
          emit_redacted("C", 0) if @client_literal_redact
          @client_literal_active = false
          @client_literal_redact = false
          @suppress_next_client_crlf = true
          return
        end
        chunk = @client_buffer.slice!(0, @client_literal_remaining)
        @client_literal_remaining -= chunk.bytesize
        @client_literal_size = (@client_literal_size || 0) + chunk.bytesize
        @client_literal_chunks << chunk
        if @client_literal_remaining.zero?
          # Reassemble the whole literal so chunked writes log on one line.
          if @client_literal_redact
            emit_redacted("C", @client_literal_size)
          else
            @output.print("C: #{@client_literal_chunks}\n")
          end
          @client_literal_size = nil
          @client_literal_chunks = String.new.b
          @client_literal_active = false
          @client_literal_redact = false
          # The literal was the last frame before the command's terminating
          # CRLF; suppress that bare CRLF if it arrives as its own frame.
          @suppress_next_client_crlf = true
        end
      end

      def process_client_line(line)
        if (suffix = line.match(EMBEDDED_LITERAL_SUFFIX))
          # A command line that ends in a literal header.  Parse the command
          # portion first so the redaction decision for this literal (which may
          # depend on its argument position, e.g. the username of a LOGIN is
          # visible while its password is hidden) is queued before the header
          # is consumed.  The header always retains its declared length.
          prepare_command_literals(line)
          @client_literal_remaining = Integer(suffix[2])
          @client_literal_redact    =
            @client_literal_decisions.empty? ? true : @client_literal_decisions.shift
          @client_literal_active    = true
          emit("C", line)
          take_client_literal if @client_literal_remaining.zero?
        elsif @suppress_next_client_crlf && line == CRLF
          # The bare CRLF that terminates a command whose final literal payload
          # was redacted carries no information of its own.
          @suppress_next_client_crlf = false
        elsif client_continuation?(line)
          # A bare continuation line is a SASL client response.
          @suppress_next_client_crlf = false
          emit("C", redact_continuation_response(line))
        else
          @suppress_next_client_crlf = false
          emit("C", redact_command(line))
        end
      end

      # Queues the payload redaction decision for the literal header at the end
      # of +line+, based on the enclosing command and the argument position of
      # the literal.  Non-authentication commands always hide literals.
      def prepare_command_literals(line)
        header = line.match(COMMAND_PREFIX) or return
        tag, command = header.captures
        region = line.byteslice(header.end(0), line.bytesize - header.end(0))
        index  = -1
        tokenize(region).each do |token|
          next if token[:space] || token[:crlf]
          index += 1
          next unless token[:literal]
          decision =
            case command.upcase
            when "LOGIN"        then index == 1
            when "AUTHENTICATE" then index >= 1
            else                     true
            end
          @client_literal_decisions << decision
        end
        @sasl_tags.add(tag) if command.upcase == "AUTHENTICATE"
      end

      # A line without a tag/command prefix is a continuation response, but
      # only while a SASL exchange is in progress.
      def client_continuation?(line)
        !line.match?(COMMAND_PREFIX) && !@sasl_tags.empty?
      end

      def redact_command(line)
        header = line.match(COMMAND_PREFIX) or return line
        tag, command = header.captures
        case command.upcase
        when "LOGIN"
          @sasl_tags.delete(tag)
          redact_arguments(line, header.end(0)) { |index| index == 1 }
        when "AUTHENTICATE"
          @sasl_tags.add(tag)
          redact_arguments(line, header.end(0)) { |index| index >= 1 }
        else
          # Every literal of an ordinary command (e.g. APPEND) is hidden.
          queue_all_literals(line, header.end(0))
          line
        end
      end

      # Rebuilds a command line after its header, yielding each zero-based
      # argument index to decide whether that argument is redacted.  Decisions
      # about literal payloads are queued in arrival order for later frames.
      def redact_arguments(line, offset)
        head    = line.byteslice(0, offset)
        region  = line.byteslice(offset, line.bytesize - offset)
        index   = -1
        rebuilt = head + tokenize(region).map { |token|
          if token[:space] || token[:crlf]
            token[:source]
          else
            index += 1
            redact = yield(index)
            render_argument_token(token, redact)
          end
        }.join
        rebuilt
      end

      # Queues a redact decision for every literal header that follows the
      # command header of an ordinary (non-authentication) command.
      def queue_all_literals(line, offset)
        tokenize(line.byteslice(offset, line.bytesize - offset)).each do |token|
          @client_literal_decisions << true if token[:literal]
        end
      end

      # A SASL continuation response is a single credential token.
      def redact_continuation_response(line)
        tokens = tokenize(line)
        token  = tokens.reject { _1[:space] || _1[:crlf] }.first
        suffix = tokens.last&.dig(:crlf) ? CRLF : ""
        if token
          render_argument_token(token, true) + suffix
        else
          redacted(0) + CRLF
        end
      end

      def render_argument_token(token, redact)
        if token[:literal]
          # The header keeps its declared length; queue the payload decision.
          @client_literal_decisions << redact
          token[:source]
        elsif redact
          redacted(token[:source].bytesize)
        else
          token[:source]
        end
      end

      # Matches a literal header at the current scanner position, whether it is
      # the whole remaining region or is followed by a trailing CRLF.
      SCANNED_LITERAL = /\A~?\{\d+\+?\}\r\n/n

      # Splits an argument region into whitespace and argument tokens.  A
      # literal token captures only its header; its payload arrives in a later
      # frame and is never part of a command line.  The trailing CRLF is always
      # preserved as its own token.
      def tokenize(string)
        tokens = []
        scanner = string
        until scanner.empty?
          matched =
            scanner.match(/\A[ \t]+/n) ||
            scanner.match(SCANNED_LITERAL) ||
            scanner.match(/\A"(?:[^"\\]|\\.)*"/n) ||
            scanner.match(/\A[^\s"{]+/n) ||
            scanner.match(/\A\r\n/n) ||
            scanner.match(/\A./n)
          tokens << {
            source:  matched[0],
            space:   matched[0].match?(/\A[ \t]+\z/n),
            crlf:    matched[0].match?(/\A\r\n\z/n),
            literal: matched[0].match?(SCANNED_LITERAL),
          }
          scanner = scanner.byteslice(matched.end(0),
                                     scanner.bytesize - matched.end(0))
        end
        tokens
      end

      # ---- server direction -------------------------------------------------

      def drain_server
        until @server_buffer.empty?
          if @server_literal_active
            take_server_literal
          elsif (index = @server_buffer.index(CRLF))
            line = @server_buffer.slice!(0, index + 2)
            process_server_line(line)
          else
            break
          end
        end
      end

      def take_server_literal
        if @server_literal_remaining.zero?
          emit_redacted("S", 0) if @server_literal_redact
          @server_literal_active = false
          @server_literal_redact = false
          @suppress_next_server_crlf = true
          return
        end
        chunk = @server_buffer.slice!(0, @server_literal_remaining)
        @server_literal_remaining -= chunk.bytesize
        if @server_literal_redact
          @server_literal_size = (@server_literal_size || 0) + chunk.bytesize
          if @server_literal_remaining.zero?
            emit_redacted("S", @server_literal_size)
            @server_literal_size = nil
            @server_literal_active = false
            @server_literal_redact = false
            # The redacted payload may itself end in CRLF; suppress a bare
            # terminating CRLF if it follows as its own frame.
            @suppress_next_server_crlf = true
          end
        else
          emit("S", chunk)
          if @server_literal_remaining.zero?
            @server_literal_active = false
            @server_literal_redact = false
          end
        end
      end

      def process_server_line(line)
        if @suppress_next_server_crlf && line == CRLF
          # A bare CRLF consumed as part of a redacted literal's payload.
          @suppress_next_server_crlf = false
          return
        end
        @suppress_next_server_crlf = false
        if (suffix = line.match(EMBEDDED_LITERAL_SUFFIX))
          # A response line that ends in a literal header.  The literal
          # payload in the response is redacted, while the header retains its
          # declared length.  The payload is consumed by #drain_server.
          @server_literal_remaining = Integer(suffix[2])
          @server_literal_redact    = true
          @server_literal_active    = true
          emit("S", line)
          take_server_literal if @server_literal_remaining.zero?
        elsif line.start_with?("+")
          process_server_continuation(line)
        else
          process_server_tagged_or_untagged(line)
        end
      end

      def process_server_continuation(line)
        if @sasl_tags.empty?
          # Not a SASL challenge (e.g. a literal continuation request).
          emit("S", line)
          return
        end
        # The challenge text is credential material.  An empty challenge is
        # redacted as zero bytes.
        header  = line.start_with?("+ ") ? "+ " : "+"
        payload = line.delete_prefix(header).delete_suffix(CRLF)
        emit("S", header + redacted(payload.bytesize) + CRLF)
      end

      def process_server_tagged_or_untagged(line)
        # A tagged response ends the SASL exchange for its tag, whether it
        # reports success or failure.  The response text is emitted verbatim:
        # a server may place pseudo-command text (e.g. the word "LOGIN") in an
        # error message, and that text is response data, not a command.
        if (tag = line[/\A(\S+)[ \t]/, 1])
          @sasl_tags.delete(tag)
        end
        emit("S", line)
      end

    end
  end
end
