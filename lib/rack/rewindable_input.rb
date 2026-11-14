# -*- encoding: binary -*-
# frozen_string_literal: true

require 'tempfile'

require_relative 'constants'

module Rack
  # Class which can make any IO object rewindable, including non-rewindable ones. It does
  # this by buffering the data into a tempfile, which is rewindable.
  #
  # Don't forget to call #close when you're done. This frees up temporary resources that
  # RewindableInput uses, though it does *not* close the original IO object.
  class RewindableInput
    # Makes rack.input rewindable, for compatibility with applications and middleware
    # designed for earlier versions of Rack (where rack.input was required to be
    # rewindable).
    class Middleware
      def initialize(app)
        @app = app
      end

      def call(env)
        if (input = env[RACK_INPUT])
          env[RACK_INPUT] = RewindableInput.new(input)
        end

        @app.call(env)
      end
    end

    def initialize(io)
      @io = io
      @rewindable_io = nil
      @unlinked = false
      @closed = false
      @staging_error = nil
    end

    def gets
      rewindable_io.gets
    end

    def read(*args)
      rewindable_io.read(*args)
    end

    def each(&block)
      rewindable_io.each(&block)
    end

    def rewind
      rewindable_io.rewind
    end

    def size
      rewindable_io.size
    end

    # Closes this RewindableInput object without closing the originally
    # wrapped IO object. Cleans up any temporary resources that this RewindableInput
    # has created.
    #
    # This method may be called multiple times. It does nothing on subsequent calls.
    # Once closed, any further attempt to read, iterate, or rewind raises IOError.
    def close
      @closed = true
      if @rewindable_io
        if @unlinked
          @rewindable_io.close
        else
          @rewindable_io.close!
        end
        @rewindable_io = nil
      end
      nil
    end

    private

    # Returns the fully buffered tempfile, staging the contents of the wrapped
    # IO on first use. If a previous staging attempt failed, the same error is
    # raised again so that no caller ever mistakes a partially copied prefix
    # for the complete body.
    def rewindable_io
      raise @staging_error if @staging_error
      raise IOError, 'closed stream' if @closed
      make_rewindable unless @rewindable_io
      @rewindable_io
    end

    def make_rewindable
      # Buffer all data into a tempfile. Since this tempfile is private to this
      # RewindableInput object, we chmod it so that nobody else can read or write
      # it. On POSIX filesystems we also unlink the file so that it doesn't
      # even have a file entry on the filesystem anymore, though we can still
      # access it because we have the file handle open.
      @rewindable_io = Tempfile.new('RackRewindableInput')
      @rewindable_io.chmod(0000)
      @rewindable_io.set_encoding(Encoding::BINARY)
      @rewindable_io.binmode
      # simplecov:disable
      if filesystem_has_posix_semantics?
        raise 'Unlink failed. IO closed.' if @rewindable_io.closed?
        @unlinked = true
      end
      # simplecov:enable

      buffer = "".dup
      while @io.read(1024 * 4, buffer)
        until buffer.empty?
          written = @rewindable_io.write(buffer)
          unless written.is_a?(Integer) && written > 0 && written <= buffer.bytesize
            raise IOError, 'short write while buffering rack.input'
          end
          buffer.slice!(0, written)
        end
      end
      @rewindable_io.rewind
    rescue Exception => error
      # Staging failed partway through: remember the failure so every entry
      # point keeps raising it, and release the tempfile right away instead
      # of leaving a partially written file behind. The wrapped IO is left
      # alone; it is still owned by whoever passed it in.
      @staging_error = error
      release_rewindable_io
      raise
    end

    def release_rewindable_io
      return unless @rewindable_io

      begin
        @rewindable_io.close!
      rescue Exception
        nil
      end
      @rewindable_io = nil
    end

    def filesystem_has_posix_semantics?
      RUBY_PLATFORM !~ /(mswin|mingw|cygwin|java)/
    end
  end
end
