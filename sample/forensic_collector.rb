# frozen_string_literal: true

# Minimal, read-only IMAP evidence-collection prototype.
#
# What this demonstrates
# ----------------------
# * Fetch the raw RFC5322/MIME message by UID, with no body parsing and no
#   re-serialization.
# * Request the body with BODY.PEEK[], so the request itself cannot set \Seen.
# * Select the mailbox with EXAMINE (read-only), as a second safeguard.
# * Read the message in explicit byte ranges.  Standard IMAP supports only the
#   "from origin to end" form: BODY.PEEK[]<origin>.  A server may return that
#   suffix in full or truncate it; the client verifies the echoed origin,
#   requires forward progress, and continues at the next origin.  Each received
#   chunk is hashed immediately.
# * Keep the mailbox identity, UIDVALIDITY, UID, requested section and origins,
#   actual received byte counts, per-chunk SHA-256, and the whole command log.
# * Re-fetch each recorded origin and compare the prefix digest, so a content
#   change during collection is reported even when the server does not bump
#   MODSEQ.
# * On a missing section, wrong origin, stalled/overrunning response, short
#   verification, changed metadata, or changed chunk digest: report an
#   incomplete result and do NOT expose a stitched "source" that could be
#   mistaken for intact evidence.
#
# What this cannot prove
# ----------------------
# A read-only client can prove which commands *it* sent.  That is useful
# negative evidence: no STORE, no EXPUNGE, no CLOSE, no APPEND, no COPY/MOVE,
# and no non-PEEK body fetch.  It cannot prove the remote mailbox was unchanged
# during collection.  Another client, server-side rules, or an administrator
# may change it concurrently; a server may also fail to report its own changes.
# UIDVALIDITY + UID identify the message, but UIDVALIDITY does not change when
# a message is modified.  CONDSTORE MODSEQ comparison can detect changes the
# server reports.  Treat "complete" as evidence about the bytes this session
# received and verified, not as a guarantee about remote state or chain of
# custody.
#
# Run: ruby -Ilib sample/forensic_collector.rb

require "digest"
require "net/imap"

module ForensicIMAP
  SECTION = "BODY.PEEK[]"

  # A pure in-memory, full-duplex byte stream implementing the small IO surface
  # used by Net::IMAP (#gets, #read, #print, #close, #to_io).  It never opens a
  # socket or listens on a port.  Client and server run in separate threads.
  class MemoryDuplex
    def initialize
      @buffer = +"".b
      @eof = false
      @closed = false
      @mutex = Mutex.new
      @cv = ConditionVariable.new
      @peer = nil
    end

    attr_accessor :peer

    def write(bytes)
      data = bytes.to_s.b
      @mutex.synchronize do
        raise IOError, "closed stream" if @closed
        @peer.__send__(:enqueue, data)
      end
      data.bytesize
    end
    alias print write

    def gets(separator = $/, limit = nil)
      raise ArgumentError, "separator is required" if separator.nil?
      @mutex.synchronize do
        loop do
          if (index = @buffer.index(separator))
            length = index + separator.bytesize
            length = [length, limit].min if limit
            return take(length)
          end
          return take(limit) if limit && @buffer.bytesize >= limit
          return nil if @eof && @buffer.empty?
          return take(@buffer.bytesize) if @eof
          @cv.wait(@mutex)
        end
      end
    end

    def read(length, outbuf = nil)
      @mutex.synchronize do
        @cv.wait(@mutex) while @buffer.bytesize < length && !@eof
        return nil if @eof && @buffer.empty?
        data = take([length, @buffer.bytesize].min)
        outbuf ? outbuf.replace(data) : data
      end
    end

    def eof?
      @mutex.synchronize { @eof && @buffer.empty? }
    end

    def closed? = @closed

    def close
      notify_peer = false
      @mutex.synchronize do
        unless @closed
          @closed = true
          @eof = true
          @cv.broadcast
          notify_peer = true
        end
      end
      @peer.__send__(:mark_eof) if notify_peer
    end

    def to_io = self

    def shutdown(*)
      # No kernel socket to shut down.
    end

    private

    def enqueue(data)
      @mutex.synchronize do
        @buffer << data
        @cv.broadcast
      end
    end

    def mark_eof
      @mutex.synchronize do
        @eof = true
        @cv.broadcast
      end
    end

    def take(length)
      data = @buffer.byteslice(0, length)
      @buffer = @buffer.byteslice(length..) || +"".b
      data
    end
  end

  # Net::IMAP normally creates a TCP socket.  This subclass injects an
  # already-connected MemoryDuplex endpoint instead, so the real Net::IMAP
  # command encoder and response parser are still exercised end to end.
  #
  # #sent_commands is a wire log of outgoing command bytes.  It is safe only
  # because this prototype never sends a literal (no LOGIN and no APPEND).  Do
  # not reuse it as a general-purpose credential logger.
  class MemoryClient < Net::IMAP
    def initialize(endpoint, **options)
      @forensic_endpoint = endpoint
      @sent_bytes = +"".b
      super("memory.invalid", port: 0, ssl: false, **options)
    end

    def sent_commands
      @sent_bytes.split("\r\n").reject(&:empty?)
    end

    private

    def tcp_socket(_host, _port)
      @forensic_endpoint
    end

    def put_string(str)
      @sent_bytes << str.to_s.b
      super
    end
  end

  # One server-side message.  +source+ is the exact raw message octet stream.
  Message = Struct.new(:uid, :source, :flags, :modseq, keyword_init: true)

  # Small IMAP server sufficient for the prototype: PREAUTH, CAPABILITY,
  # EXAMINE, UID FETCH of BODY.PEEK[], NOOP, LOGOUT.  It records every command.
  #
  # +chunk_bytes+ is a server-side response policy: each BODY[] response is
  # truncated to at most that many bytes.  Partial fetches are allowed to be
  # truncated, so the collector must resume at the echoed origin.  A real server
  # may instead return the entire remaining suffix; the collector handles both.
  class MemoryServer
    Command = Struct.new(:raw, :tag, :verb, :args, keyword_init: true)

    attr_reader :mailbox, :uidvalidity, :messages, :chunk_bytes

    def initialize(endpoint, mailbox:, uidvalidity:, messages:, chunk_bytes: 64)
      @endpoint = endpoint
      @mailbox = mailbox
      @uidvalidity = Integer(uidvalidity)
      @messages = messages.to_h { |message| [message.uid, message] }
      @chunk_bytes = Integer(chunk_bytes)
      raise ArgumentError, "chunk_bytes must be positive" unless @chunk_bytes > 0
      @commands = []
      @mutex = Mutex.new
      @selected = false
      @body_fetches = 0
      reset_faults
    end

    # --- test/demo fault injection; all default to no fault -----------------
    # Omit the UIDVALIDITY response code from EXAMINE.
    attr_accessor :omit_uidvalidity
    # Omit the BODY section from the Nth body response (1-based).  The FETCH
    # metadata is still present, so the client sees a missing section.
    attr_accessor :omit_section_at
    # Echo a different origin than the one requested.
    attr_accessor :wrong_offset_next
    # Declare a literal size but send fewer octets, then close the connection.
    attr_accessor :truncate_literal_at
    # Replace the message after the Nth body response.  Bump MODSEQ only when
    # asked, so the verification pass can be tested independently of CONDSTORE.
    # A nil +mutation_after+ means all body responses, including the re-reads,
    # unless +mutation_after+ caps the final affected body response.
    attr_accessor :mutate_after_fetches
    attr_accessor :mutation
    attr_accessor :bump_modseq_on_mutation
    attr_accessor :mutation_after

    def reset_faults
      @omit_section_at = nil
      @omit_uidvalidity = false
      @wrong_offset_next = false
      @truncate_literal_at = nil
      @mutate_after_fetches = nil
      @mutation = nil
      @bump_modseq_on_mutation = true
      @mutation_after = nil
    end

    def run
      send_line("* PREAUTH [CAPABILITY IMAP4rev1 CONDSTORE] in-memory forensic server")
      begin
        while (line = @endpoint.gets("\r\n"))
          command = parse_command(line)
          @mutex.synchronize { @commands << command }
          dispatch(command)
        end
      rescue IOError, Errno::EPIPE, Errno::ECONNRESET
        # Expected when the client logs out or the test shuts down.
      end
    ensure
      @endpoint.close
    end

    # Audit snapshot.  It records flags/modseq/hash, never a second copy of the
    # body, so comparing it with the collector does not leak another source.
    def snapshot
      @mutex.synchronize do
        {
          mailbox: mailbox,
          uidvalidity: uidvalidity,
          messages: messages.transform_values {
            { flags: _1.flags.dup, modseq: _1.modseq,
              sha256: Digest::SHA256.hexdigest(_1.source),
              bytes: _1.source.bytesize }
          },
          commands: commands.map { |command| command.raw.chomp },
        }
      end
    end

    private

    attr_reader :endpoint, :commands

    def parse_command(line)
      raw = line.end_with?("\r\n") ? line : line + "\r\n"
      tag, rest = raw.split(" ", 2)
      first, args = rest.to_s.chomp("\r\n").split(" ", 2)
      verb = first
      if verb&.casecmp?("UID")
        sub, args = args.to_s.split(" ", 2)
        verb = "UID #{sub}"
      end
      Command.new(raw: raw, tag: tag, verb: verb, args: args)
    end

    def dispatch(command)
      case command.verb
      when "CAPABILITY"
        send_line("* CAPABILITY IMAP4rev1 CONDSTORE")
        send_line("#{command.tag} OK CAPABILITY completed")
      when "NOOP"
        send_line("#{command.tag} OK NOOP completed")
      when "EXAMINE"
        examine(command)
      when "UID FETCH"
        uid_fetch(command)
      when "LOGOUT"
        send_line("* BYE logging out")
        send_line("#{command.tag} OK LOGOUT completed")
        endpoint.close
      else
        send_line("#{command.tag} BAD command not supported by prototype")
      end
    end

    def examine(command)
      candidate = command.args.to_s.split(" ").first
      unless candidate == mailbox
        return send_line("#{command.tag} NO [NONEXISTENT] unknown mailbox")
      end
      @selected = true
      send_line("* #{messages.size} EXISTS")
      send_line("* 0 RECENT")
      send_line("* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)")
      send_line("* OK [PERMANENTFLAGS ()] read-only prototype")
      send_line("* OK [UIDVALIDITY #{uidvalidity}] UIDs valid") unless
        omit_uidvalidity
      send_line("* OK [UIDNEXT #{messages.keys.max.to_i + 1}] predicted next UID")
      send_line("#{command.tag} OK [READ-ONLY] EXAMINE completed")
    end

    def uid_fetch(command)
      return send_line("#{command.tag} BAD no mailbox selected") unless @selected
      set, spec = command.args.to_s.split(" ", 2)
      uid = Integer(set.split(",").first)
      message = messages[uid] or
        return send_line("#{command.tag} OK no matching message")
      if spec.start_with?("(")
        return metadata_fetch(command.tag, message, spec)
      end
      unless spec.start_with?("BODY.PEEK[]")
        return send_line("#{command.tag} BAD prototype only supports #{SECTION}")
      end
      body_fetch(command.tag, message, spec)
    end

    def metadata_fetch(tag, message, spec)
      items = spec.delete_prefix("(").delete_suffix(")").split(" ")
      values = {
        "UID" => message.uid,
        "RFC822.SIZE" => message.source.bytesize,
        "FLAGS" => "(#{message.flags.join(" ")})",
        "MODSEQ" => "(#{message.modseq})",
      }
      rendered, unknown = items.partition { values.key?(_1) }
      return send_line("#{tag} BAD unsupported item #{unknown.first}") if
        unknown.any?
      body = rendered.map { |item| "#{item} #{values[item]}" }.join(" ")
      send_line("* 1 FETCH (#{body})")
      send_line("#{tag} OK UID FETCH completed")
    end

    def body_fetch(tag, message, spec)
      match = spec.match(/\ABODY\.PEEK\[\]<(\d+)>\z/)
      return send_line("#{tag} BAD invalid partial fetch") unless match
      origin = Integer(match[1])
      @body_fetches += 1
      if mutate_after_fetches && mutate_after_fetches <= @body_fetches &&
         (mutation_after.nil? || @body_fetches <= mutation_after)
        apply_mutation
      end
      remainder = message.source.byteslice(origin..) || +"".b
      payload = remainder.byteslice(0, chunk_bytes) || +"".b
      omit = omit_section_at == @body_fetches
      echoed_origin = wrong_offset_next ? origin + 1 : origin
      # One-shot faults; verification fetches must be clean unless the test
      # explicitly configured a mutation.
      self.wrong_offset_next = false
      self.omit_section_at = nil if omit

      items = [
        "UID #{message.uid}",
        "RFC822.SIZE #{message.source.bytesize}",
        "FLAGS (#{message.flags.join(" ")})",
        "MODSEQ (#{message.modseq})",
      ]
      if omit
        send_line("* 1 FETCH (#{items.join(" ")})")
      elsif truncate_literal_at == @body_fetches
        self.truncate_literal_at = nil
        # Declare the full payload, send half, then close: a wire-level short
        # literal, not a legal truncation.
        send_line(
          "* 1 FETCH (#{items.join(" ")} " \
          "BODY[]<#{echoed_origin}> {#{payload.bytesize}}"
        )
        send_bytes(payload.byteslice(0, payload.bytesize / 2))
        endpoint.close
        return
      else
        # A literal must be the last item on its response line.
        send_line(
          "* 1 FETCH (#{items.join(" ")} " \
          "BODY[]<#{echoed_origin}> {#{payload.bytesize}}"
        )
        send_bytes(payload)
        send_line(")")
      end
      send_line("#{tag} OK UID FETCH completed")
    end

    def apply_mutation
      return unless mutation
      message = messages.values.first
      message.source = mutation.call(message.source)
      message.modseq += 1 if bump_modseq_on_mutation
      self.mutation = nil
    end

    def send_line(line)
      send_bytes(line + "\r\n")
    end

    def send_bytes(bytes)
      endpoint.print(bytes)
    end
  end

  # Collects raw message bytes and produces a verifiable summary.
  class Collector
    # +request+ is the exact data item sent.  +origin+ is the byte offset the
    # server echoed.  +received+ is the actual chunk length; it may be shorter
    # than the remaining suffix when the server truncates a partial response.
    Chunk = Struct.new(
      :request, :origin, :received, :response_attr, :sha256,
      keyword_init: true
    )

    Result = Struct.new(
      :status, :mailbox, :uid, :uidvalidity, :section, :source, :chunks,
      :rfc822_size, :received_bytes, :sha256,
      :initial_flags, :final_flags, :modseq, :error,
      keyword_init: true
    ) do
      def complete? = status == :complete

      # Manifest suitable for handing the raw file to a signature verifier.
      # Only a complete result may produce one.
      def manifest
        raise "incomplete collection has no manifest" unless complete?
        {
          mailbox: mailbox, uidvalidity: uidvalidity, uid: uid,
          section: section, bytes: source.bytesize, sha256: sha256,
          rfc822_size: rfc822_size,
          chunks: chunks.map {
            { request: _1.request, origin: _1.origin,
              received: _1.received, sha256: _1.sha256 }
          },
        }
      end

      # Writes the raw MIME bytes exactly as received.  Re-reads the file and
      # verifies length and digest before returning the manifest.
      def write_raw(path)
        raise "incomplete collection cannot be saved as evidence" unless
          complete?
        File.binwrite(path, source)
        written = File.binread(path)
        unless written.bytesize == source.bytesize &&
               Digest::SHA256.hexdigest(written) == sha256
          raise "written file failed integrity verification"
        end
        manifest.merge(path: path)
      end
    end

    def initialize(imap, mailbox:, uid:)
      @imap = imap
      @mailbox = mailbox
      @uid = Integer(uid)
    end

    def collect
      uidvalidity = nil
      baseline = nil
      final = nil
      chunks = []
      source = +"".b
      begin
        @imap.examine(@mailbox, condstore: true)
        uidvalidity = @imap.responses("UIDVALIDITY") { |values| values.last }
        unless uidvalidity
          return failure(:missing_uidvalidity,
                         "server did not return UIDVALIDITY", nil, nil,
                         chunks, final)
        end
        baseline = fetch_metadata
        return failure(:no_message, "UID not present", uidvalidity, baseline,
                       chunks, final) unless baseline&.uid == @uid

        size = baseline.rfc822_size
        origin = 0
        while origin < size
          response_attr = "BODY[]<#{origin}>"
          request = "BODY.PEEK[]<#{origin}>"
          fetched = @imap.uid_fetch(@uid, request)
            .find { |item| item.uid == @uid }
          return failure(:missing_response, "no FETCH response for UID",
                         uidvalidity, baseline, chunks, final) unless fetched

          unless fetched.attr.key?(response_attr)
            others = fetched.attr.keys.grep(/\ABODY\[/)
            status = others.empty? ? :missing_section : :offset_mismatch
            detail = others.empty? ?
              "response contained no BODY section for #{response_attr}" :
              "requested #{response_attr}, response contained #{others.inspect}"
            return failure(status, detail, uidvalidity, baseline, chunks, final)
          end
          bytes = fetched.attr[response_attr]
          unless bytes
            return failure(:missing_section, "response section was NIL",
                           uidvalidity, baseline, chunks, final)
          end
          if bytes.empty?
            return failure(:stalled, "empty chunk at origin #{origin}",
                           uidvalidity, baseline, chunks, final)
          end
          if bytes.bytesize > size - origin
            return failure(
              :overrun,
              "chunk at #{origin} exceeds RFC822.SIZE #{size}",
              uidvalidity, baseline, chunks, final
            )
          end

          chunks << Chunk.new(
            request: request, origin: origin, received: bytes.bytesize,
            response_attr: response_attr,
            sha256: Digest::SHA256.hexdigest(bytes)
          )
          source << bytes
          origin += bytes.bytesize
        end

        return failure(:size_mismatch,
                       "assembled #{source.bytesize}, expected #{size}",
                       uidvalidity, baseline, chunks, final) unless
          source.bytesize == size

        final = fetch_metadata
        return failure(:missing_metadata, "final metadata fetch failed",
                       uidvalidity, baseline, chunks, final) unless final
        changes = []
        changes << :uid      unless baseline.uid == final.uid
        changes << :size     unless baseline.rfc822_size == final.rfc822_size
        changes << :flags    unless baseline.flags == final.flags
        changes << :modseq   unless baseline.modseq == final.modseq
        unless changes.empty?
          return failure(:changed_during_fetch,
                         "message metadata changed: #{changes.join(", ")}",
                         uidvalidity, baseline, chunks, final)
        end

        # Re-read each recorded origin and compare the prefix digest.  This can
        # detect content changes even when the server does not bump MODSEQ.
        chunks.each do |chunk|
          fetched = @imap.uid_fetch(@uid, chunk.request)
            .find { |item| item.uid == @uid }
          return failure(:verification_missing, "no response re-reading " \
                         "#{chunk.request}", uidvalidity, baseline,
                         chunks, final) unless fetched
          bytes = fetched.attr[chunk.response_attr]
          return failure(:verification_missing, "no section re-reading " \
                         "#{chunk.request}", uidvalidity, baseline,
                         chunks, final) unless bytes
          if bytes.bytesize < chunk.received
            return failure(:verification_short,
                           "re-read #{chunk.request} returned " \
                           "#{bytes.bytesize}, expected at least " \
                           "#{chunk.received}", uidvalidity, baseline,
                           chunks, final)
          end
          digest = Digest::SHA256.hexdigest(
            bytes.byteslice(0, chunk.received)
          )
          unless digest == chunk.sha256
            return failure(:changed_during_fetch,
                           "chunk at origin #{chunk.origin} changed " \
                           "between reads", uidvalidity, baseline,
                           chunks, final)
          end
        end

        Result.new(
          status: :complete, mailbox: @mailbox, uid: @uid,
          uidvalidity: uidvalidity, section: SECTION, source: source,
          chunks: chunks, rfc822_size: size, received_bytes: source.bytesize,
          sha256: Digest::SHA256.hexdigest(source),
          initial_flags: baseline.flags, final_flags: final.flags,
          modseq: baseline.modseq, error: nil
        )
      rescue EOFError, IOError, Net::IMAP::Error => error
        failure(:connection_error, "#{error.class}: #{error.message}",
                uidvalidity, baseline, chunks, final)
      end
    end

    private

    def fetch_metadata
      @imap.uid_fetch(@uid, %w[UID RFC822.SIZE FLAGS MODSEQ])
        .find { |item| item.uid == @uid }
    end

    # Incomplete results deliberately have source=nil and sha256=nil.  Chunks
    # that passed their per-response checks remain in the summary so an
    # investigator can see how far collection got, but they are never joined
    # into a pseudo-complete message.
    def failure(status, error, uidvalidity, baseline, chunks, final)
      Result.new(
        status: status, mailbox: @mailbox, uid: @uid,
        uidvalidity: uidvalidity, section: SECTION, source: nil,
        chunks: chunks, rfc822_size: baseline&.rfc822_size,
        received_bytes: chunks.sum(&:received), sha256: nil,
        initial_flags: baseline&.flags, final_flags: final&.flags,
        modseq: baseline&.modseq, error: error
      )
    end
  end

  # Commands that would mutate mailbox state, expunge mail, or close a
  # read-write mailbox.  The collector must never send these.
  FORBIDDEN_COMMANDS = %w[
    STORE EXPUNGE COPY MOVE APPEND CLOSE DELETE RENAME CREATE
    SUBSCRIBE UNSUBSCRIBE SETACL DELETEACL
  ].freeze

  # Parses "TAG [UID] VERB ..." into an upper-case verb.  Used only for the
  # audit report, never to make protocol decisions.
  def self.command_verb(line)
    parts = line.to_s.split(" ")
    parts.shift # tag
    verb = parts.shift.to_s.upcase
    if verb == "UID"
      verb = "UID #{parts.shift.to_s.upcase}"
    end
    verb
  end

  # Negative evidence from the command log.  This proves what *this session*
  # sent.  It does not prove the remote mailbox was unchanged by anyone else.
  #
  # Unsafe body fetches are also reported: BODY[]/BINARY[] without .PEEK may
  # set \Seen, and RFC822/RFC822.TEXT/RFC822.HEADER are legacy synonyms that
  # may do the same.  RFC822.SIZE is not a body fetch and is allowed.
  def self.read_only_audit(lines)
    verbs = lines.map { |line| command_verb(line) }
    forbidden = verbs.select { |verb|
      FORBIDDEN_COMMANDS.include?(verb.delete_prefix("UID "))
    }
    unsafe_fetches = lines.select { |line|
      verb = command_verb(line)
      next false unless ["FETCH", "UID FETCH"].include?(verb)
      line.match?(/\bBODY\[/n) && !line.match?(/\bBODY\.PEEK\[/n) ||
        line.match?(/\bBINARY\[/n) && !line.match?(/\bBINARY\.PEEK\[/n) ||
        line.match?(/\bRFC822(?:\.TEXT|\.HEADER)?\b(?!\.SIZE)/n)
    }
    {
      commands: verbs,
      forbidden: (forbidden + unsafe_fetches.map { |line| command_verb(line) }).uniq,
      unsafe_fetches: unsafe_fetches,
      ok: forbidden.empty? && unsafe_fetches.empty?,
      note: "This proves only which commands this client sent. " \
            "It cannot prove the mailbox was unchanged during collection.",
    }
  end

  # Builds the exact standard UID FETCH data item this prototype sends.  There
  # is no byte-count form in IMAP; the server returns the suffix from +origin+,
  # possibly truncated, and the collector resumes at the next origin.
  def self.partial_fetch(uid, origin)
    "UID FETCH #{uid} BODY.PEEK[]<#{origin}>"
  end

  # A short, deliberately awkward source message:
  # * UTF-8 outside ASCII in the body,
  # * a mix of CRLF and bare LF line endings,
  # * a base64-encoded binary attachment and a raw binary MIME part.
  # The bytes are authored once.  Nothing here parses and re-serializes them.
  def self.demo_message
    binary = [0x00, 0x01, 0x02, 0x7F, 0x80, 0xFE, 0xFF].pack("C*") +
             "raw-bytes".b
    encoded = [binary].pack("m0")
    [
      "Date: Tue, 14 Nov 2026 09:00:00 +0000",
      "From: Evidence Bot <evidence@example.invalid>",
      "To: Case Handler <handler@example.invalid>",
      "Subject: forensic sample",
      "Message-ID: <forensic-demo-1@example.invalid>",
      "MIME-Version: 1.0",
      "Content-Type: multipart/mixed; boundary=\"forensic-boundary\"",
      "",
      "This paragraph has a bare LF\nending in the middle.",
      "--forensic-boundary",
      "Content-Type: text/plain; charset=utf-8",
      "Content-Transfer-Encoding: 8bit",
      "",
      "正文包含非 ASCII：证据采集。",
      "This line ends with CRLF.",
      "--forensic-boundary",
      "Content-Type: application/octet-stream; name=\"probe.bin\"",
      "Content-Disposition: attachment; filename=\"probe.bin\"",
      "Content-Transfer-Encoding: base64",
      "",
      encoded,
      "--forensic-boundary",
      "Content-Type: application/octet-stream; name=\"raw.bin\"",
      "Content-Disposition: attachment; filename=\"raw.bin\"",
      "Content-Transfer-Encoding: binary",
      "",
      binary,
      "--forensic-boundary--",
      "",
    ].map(&:b).join("\r\n").b
  end

  # Run the in-memory demonstration.  Returns the result, an audit hash with
  # both client-sent and server-received commands, and the original source.
  def self.run_demo(chunk_bytes: 64, faults: {})
    client_endpoint = MemoryDuplex.new
    server_endpoint = MemoryDuplex.new
    client_endpoint.peer = server_endpoint
    server_endpoint.peer = client_endpoint

    source = demo_message
    server = MemoryServer.new(
      server_endpoint, mailbox: "INBOX", uidvalidity: 2026111401,
      messages: [Message.new(uid: 42, source: source, flags: [], modseq: 7)],
      chunk_bytes: chunk_bytes
    )
    faults.each { |name, value| server.public_send(:"#{name}=", value) }
    server_thread = Thread.new { server.run }
    imap = MemoryClient.new(client_endpoint)
    begin
      result = Collector.new(imap, mailbox: "INBOX", uid: 42).collect
    ensure
      imap.logout! unless imap.disconnected?
      server_thread.join(5)
      client_endpoint.close
      server_endpoint.close
    end
    audit = server.snapshot.merge(client_commands: imap.sent_commands)
    [result, audit, source]
  end
end

if $0 == __FILE__
  result, audit, original = ForensicIMAP.run_demo
  puts "status:        #{result.status}"
  puts "mailbox:       #{result.mailbox}"
  puts "uidvalidity:   #{result.uidvalidity}"
  puts "uid:           #{result.uid}"
  puts "section:       #{result.section}"
  puts "RFC822.SIZE:   #{result.rfc822_size}"
  puts "received:      #{result.received_bytes} bytes"
  puts "SHA-256:       #{result.sha256}"
  puts "chunks:        #{result.chunks.length}"
  puts "source equal:  #{result.source == original}"
  puts "flags:         #{result.initial_flags.inspect} -> #{result.final_flags.inspect}"
  puts "error:         #{result.error.inspect}"
  puts
  puts "chunk requests:"
  result.chunks.each do |chunk|
    puts "  #{chunk.request} -> origin #{chunk.origin}, " \
         "#{chunk.received} bytes, #{chunk.sha256[0, 16]}..."
  end
  puts
  puts "client-sent commands:"
  audit[:client_commands].each { |line| puts "  #{line}" }
  puts "server-received commands:"
  audit[:commands].each { |line| puts "  #{line}" }
  puts
  report = ForensicIMAP.read_only_audit(audit[:client_commands])
  puts "read-only audit: ok=#{report[:ok]} forbidden=#{report[:forbidden].inspect}"
  puts report[:note]
end
