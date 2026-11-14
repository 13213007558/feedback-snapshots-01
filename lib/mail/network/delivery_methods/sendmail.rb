# frozen_string_literal: true
require 'open3'
require 'mail/smtp_envelope'

module Mail
  # A delivery method implementation which sends via sendmail.
  #
  # To use this, first find out where the sendmail binary is on your computer,
  # if you are on a mac or unix box, it is usually in /usr/sbin/sendmail, this will
  # be your sendmail location.
  #
  #   Mail.defaults do
  #     delivery_method :sendmail
  #   end
  #
  # Or if your sendmail binary is not at '/usr/sbin/sendmail'
  #
  #   Mail.defaults do
  #     delivery_method :sendmail, :location => '/absolute/path/to/your/sendmail'
  #   end
  #
  # Then just deliver the email as normal:
  #
  #   Mail.deliver do
  #     to 'mikel@test.lindsaar.net'
  #     from 'ada@test.lindsaar.net'
  #     subject 'testing sendmail'
  #     body 'testing sendmail'
  #   end
  #
  # Or by calling deliver on a Mail message
  #
  #   mail = Mail.new do
  #     to 'mikel@test.lindsaar.net'
  #     from 'ada@test.lindsaar.net'
  #     subject 'testing sendmail'
  #     body 'testing sendmail'
  #   end
  #
  #   mail.deliver!
  #
  # == Process and resource handling
  #
  # The message body is streamed to the child over a dedicated stdin pipe while
  # the child's combined stdout and stderr are drained concurrently over a second
  # pipe. Keeping the two directions separate prevents either end from blocking
  # on a full pipe and deadlocking the worker:
  #
  # - the body is written in non-blocking segments, so a child that reads slowly
  #   (or not at all) can never wedge the parent on a blocked write;
  # - diagnostics are drained continuously and capped at
  #   <tt>:max_stderr_bytesize</tt> bytes, so a child that emits unbounded output
  #   on bad input can never wedge the parent on a blocked read or exhaust memory;
  # - <tt>:read_timeout</tt> bounds how long the child may go without making
  #   progress, after which it is terminated and reaped;
  # - every exit path (success, early exit, timeout, failed parent write) closes
  #   the pipes and waits on the child, so no process or file descriptor leaks.
  class Sendmail
    # Largest amount of a child's stdout/stderr retained for an error message.
    # Output beyond this is still read (to keep the child unblocked) but dropped.
    DEFAULT_MAX_STDERR_BYTESIZE = 4096

    # Maximum idle time, in seconds, waiting for the child to make progress.
    # Set to +nil+ to disable the timeout.
    DEFAULT_READ_TIMEOUT = 60

    # Bytes offered to the child in a single non-blocking write.
    WRITE_CHUNK_BYTESIZE = 64 * 1024

    DEFAULTS = {
      :location            => '/usr/sbin/sendmail',
      :arguments           => %w[ -i ],
      :read_timeout        => DEFAULT_READ_TIMEOUT,
      :max_stderr_bytesize => DEFAULT_MAX_STDERR_BYTESIZE
    }

    attr_accessor :settings

    # Raised when local transport to the sendmail process is known to have
    # failed. A non-zero exit after the whole message was handed off is a
    # definite local failure: delivery to the final recipients did not happen.
    class DeliveryError < StandardError
    end

    # Raised when the local transfer could not be confirmed. The child may or
    # may not have accepted and delivered the message, so the result is unknown
    # and the caller may safely retry.
    class DeliveryUnknownError < DeliveryError
    end

    def initialize(values)
      self.settings = self.class::DEFAULTS.merge(values)
      raise ArgumentError, ":arguments expected to be an Array of individual string args" if settings[:arguments].is_a?(String)
    end

    def destinations_for(envelope)
      envelope.to
    end

    def deliver!(mail)
      envelope = Mail::SmtpEnvelope.new(mail)

      command = [settings[:location]]
      command.concat Array(settings[:arguments])
      command.concat [ '-f', envelope.from ] if envelope.from

      if destinations = destinations_for(envelope)
        command.push '--'
        command.concat destinations
      end

      message = ::Mail::Utilities.binary_unsafe_to_lf(envelope.message)

      popen(command) do |stream|
        stream.write_all(message)
      end
    end

    private
      # Spawns +command+ with separate pipes for the message (stdin) and the
      # child's combined diagnostics (stdout + stderr), then yields a writer for
      # the message. Reclaims the child and handles on every exit path.
      def popen(command, &block)
        stdin, diagnostics, wait_thread = Open3.popen2e(*command)
        writer = MessageWriter.new(
          stdin,
          diagnostics,
          settings[:read_timeout],
          settings[:max_stderr_bytesize]
        )

        begin
          block.call(writer)
          writer.close_stdin
          status = reap(wait_thread, writer)
          handle_status(status, writer, command)
        rescue DeliveryUnknownError
          # Timeout or other indeterminate failure raised inside the pump.
          abandon(writer, wait_thread)
          raise
        rescue StandardError => error
          # A blocked/broken write because the child exited early, an IO error,
          # etc. Reap the child and classify the outcome. The original message
          # and recipient list are never interpolated into the error.
          status = abandon(writer, wait_thread)
          raise classify_failure(error, status, writer, command)
        ensure
          writer.close
        end
      end

      # Closes stdin, drains remaining diagnostics and waits for the child,
      # returning its Process::Status.
      def reap(wait_thread, writer)
        writer.close_stdin
        writer.drain_remaining
        wait_thread.value
      end

      # Reclaims a child after a failed/aborted write, forcing it down if it is
      # still running (e.g. an idle or hung transport). Returns the observed
      # Process::Status when available, otherwise nil. Does not block waiting
      # for further diagnostics: the transport has already failed and a hung
      # child must not be able to extend the timeout a second time.
      def abandon(writer, wait_thread)
        writer.close_stdin
        writer.drain
        terminate(wait_thread)
        joined_status(wait_thread)
      end

      # Joins the thread and returns the Process::Status captured at join time.
      # Thread#status reports a thread state symbol (or false), never a
      # Process::Status, so it must not be used as the child's exit status.
      def joined_status(wait_thread)
        wait_thread.join
        wait_thread.value
      rescue StandardError
        nil
      end

      # Defensive backstop guaranteeing the child cannot outlive this call.
      def terminate(wait_thread)
        return unless wait_thread.alive?

        grace = settings[:read_timeout] || DEFAULT_READ_TIMEOUT
        Process.kill(:TERM, wait_thread.pid)
        wait_thread.join(grace)
        Process.kill(:KILL, wait_thread.pid) if wait_thread.alive?
        wait_thread.join
      rescue Errno::ESRCH, Errno::ECHILD
        # Already gone; nothing to reclaim.
      end

      def handle_status(status, writer, command)
        return self if status.success?

        if writer.fully_written?
          # The entire message reached the process, which then reported a
          # definite local failure.
          raise DeliveryError.new(
            "Delivery failed with exitstatus #{status.exitstatus}: #{command.first}#{writer.diagnostics_suffix}"
          )
        end

        raise DeliveryUnknownError.new(
          "Local mail transport exited with status #{status.exitstatus} before the full message was written: #{command.first} (delivery result unknown)"
        )
      end

      def classify_failure(error, status, writer, command)
        if writer.fully_written? && status && !status.signaled? && !status.success?
          DeliveryError.new(
            "Delivery failed with exitstatus #{status.exitstatus}: #{command.first}#{writer.diagnostics_suffix}"
          )
        elsif status&.signaled?
          DeliveryUnknownError.new(
            "Local mail transport was terminated by signal #{status.termsig}: #{command.first} (delivery result unknown)"
          )
        else
          DeliveryUnknownError.new(
            "Could not finish writing message to local mail transport: #{command.first} (#{error.class}: delivery result unknown)"
          )
        end
      end

      # Streams the message to the child in non-blocking segments while draining
      # the child's diagnostics on every wait, so neither pipe can fill and
      # deadlock the other end.
      class MessageWriter
        def initialize(stdin, diagnostics, timeout, max_diagnostics_bytesize)
          @stdin = stdin
          @diagnostics = diagnostics
          @timeout = timeout
          @max_diagnostics_bytesize = max_diagnostics_bytesize
          @diagnostics_buffer = +''.b
          @diagnostics_truncated = false
          @fully_written = false
        end

        def fully_written?
          @fully_written
        end

        def write_all(data)
          payload = data.to_s.dup.force_encoding(Encoding::BINARY)
          offset = 0

          # Advance an offset into the single, untouched payload rather than
          # repeatedly re-slicing it. A slice shares the parent's buffer, and
          # feeding a shared slice back into a non-blocking write can corrupt
          # the parent string and lose everything beyond the first segment.
          while offset < payload.bytesize
            drain

            _readable, writable = IO.select([@diagnostics], [@stdin], nil, @timeout)
            raise DeliveryUnknownError, "Timed out writing message to local mail transport" if writable.nil?

            result = @stdin.write_nonblock(
              payload.byteslice(offset, [WRITE_CHUNK_BYTESIZE, payload.bytesize - offset].min),
              :exception => false
            )
            case result
            when :wait_writable, :wait_readable
              # Pipe is full; loop, drain diagnostics, and wait for the child.
            when nil
              raise Errno::EPIPE
            else
              offset += result
            end
          end

          @fully_written = true
          self
        rescue IOError, Errno::EPIPE, Errno::ECONNRESET
          # The child closed its end (early exit) or the pipe was reset.
          raise
        end

        # Non-blocking drain of everything currently readable, retaining at most
        # the configured number of diagnostic bytes.
        def drain
          loop do
            chunk = @diagnostics.read_nonblock(WRITE_CHUNK_BYTESIZE, exception: false)
            case chunk
            when :wait_readable
              break
            when nil
              break
            else
              retain(chunk)
            end
          end
        rescue IOError
          # Diagnostics pipe already closed.
        end

        # Blocking drain used after stdin is closed while we wait for the child
        # to finish emitting output.
        def drain_remaining
          loop do
            readable, = IO.select([@diagnostics], nil, nil, @timeout)
            raise DeliveryUnknownError, "Timed out reading diagnostics from local mail transport" if readable.nil?

            chunk = @diagnostics.read_nonblock(WRITE_CHUNK_BYTESIZE, exception: false)
            case chunk
            when :wait_readable
              next
            when nil
              break
            else
              retain(chunk)
            end
          end
        rescue IOError
          # Diagnostics pipe already closed.
        end

        def close_stdin
          @stdin.close unless @stdin.closed?
        rescue IOError
          # Already closed.
        end

        def close
          close_stdin
          @diagnostics.close unless @diagnostics.closed?
        rescue IOError
          # Already closed.
        end

        def diagnostics_suffix
          return '' if @diagnostics_buffer.empty?

          detail = @diagnostics_truncated ? "#{@diagnostics_buffer}..." : @diagnostics_buffer
          " (#{detail.strip})"
        end

        private
          def retain(chunk)
            return if @diagnostics_truncated

            available = @max_diagnostics_bytesize - @diagnostics_buffer.bytesize
            if available <= 0
              @diagnostics_truncated = true
            elsif chunk.bytesize <= available
              @diagnostics_buffer << chunk
            else
              @diagnostics_buffer << chunk.byteslice(0, available)
              @diagnostics_truncated = true
            end
          end
      end
  end
end
