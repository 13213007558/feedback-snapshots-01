# frozen_string_literal: true

module Grape
  # Tracks the multipart tempfiles of one request so that every upload has
  # exactly one owner at any moment: Grape until the endpoint takes a file
  # over with +take_over_upload+, the endpoint afterwards. Whatever the
  # endpoint leaves behind -- a file it rejected, or every file when
  # validation fails or the endpoint halts -- Grape closes once the request
  # is answered. Each transition is appended to the audit trail, which keeps
  # the original client filenames for internal diagnostics even where the
  # endpoint itself only sees a placeholder (see
  # +Grape::DSL::UploadHandover#internal_upload_names+).
  class UploadRegistry
    Entry = Struct.new(:param, :filename, :tempfile, :file_hash, :handed_over, keyword_init: true)

    attr_reader :audit_trail

    def initialize(internal_names: [])
      @internal_names = internal_names
      @entries = []
      @audit_trail = []
    end

    def track_request(request)
      walk_uploads(request.POST) { |param, file_hash| track(param, file_hash) }
      self
    end

    def entries
      @entries.dup
    end

    def hand_over(name)
      matches = @entries.select { |entry| entry.param == name.to_s }
      raise KeyError, "no upload tracked for #{name.inspect}" if matches.empty?

      matches.each do |entry|
        entry.handed_over = true
        record(:handed_over, entry)
      end
      matches.map(&:file_hash)
    end

    def close_retained!
      @entries.each do |entry|
        next if entry.handed_over || entry.tempfile.closed?

        entry.tempfile.close!
        record(:closed, entry)
      end
      nil
    end

    private

    def track(param, file_hash)
      filename = file_hash[:filename]
      file_hash[:filename] = redacted_filename(param) if @internal_names.include?(param)
      entry = Entry.new(param:, filename:, tempfile: file_hash[:tempfile], file_hash:, handed_over: false)
      @entries << entry
      record(:tracked, entry)
    end

    def record(event, entry)
      @audit_trail << { event:, param: entry.param, filename: entry.filename }
    end

    def redacted_filename(param)
      "#{param}.internal"
    end

    def walk_uploads(value, param = nil, &)
      case value
      when Hash
        if upload_file?(value)
          yield param, value
        else
          value.each_pair { |key, nested| walk_uploads(nested, key, &) }
        end
      when Array
        value.each { |nested| walk_uploads(nested, param, &) }
      end
    end

    def upload_file?(value)
      value.key?(:tempfile) && value[:tempfile].is_a?(Tempfile)
    end
  end
end
