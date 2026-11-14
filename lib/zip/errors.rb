# frozen_string_literal: true

module Zip
  # The superclass for all rubyzip error types. Simply rescue this one if
  # you don't need to know what sort of error has been raised.
  class Error < StandardError; end

  # Error raised if an unsupported compression method is used.
  class CompressionMethodError < Error
    # The compression method that has caused this error.
    attr_reader :compression_method

    # Create a new CompressionMethodError with the specified incorrect
    # compression method.
    def initialize(method)
      super()
      @compression_method = method
    end

    # The message returned by this error.
    def message
      "Unsupported compression method: #{COMPRESSION_METHODS[@compression_method]}."
    end
  end

  # Error raised if there is a problem while decompressing an archive entry.
  class DecompressionError < Error
    # The error from the underlying Zlib library that caused this error.
    attr_reader :zlib_error

    # Create a new DecompressionError with the specified underlying Zlib
    # error.
    def initialize(zlib_error)
      super()
      @zlib_error = zlib_error
    end

    # The message returned by this error.
    def message
      "Zlib error ('#{@zlib_error.message}') while inflating."
    end
  end

  # Error raised when trying to extract an archive entry over an
  # existing file.
  class DestinationExistsError < Error
    # Create a new DestinationExistsError with the clashing destination.
    def initialize(destination)
      super()
      @destination = destination
    end

    # The message returned by this error.
    def message
      "Cannot create file or directory '#{@destination}'. " \
        'A file already exists with that name.'
    end
  end

  # Error raised when trying to add an entry to an archive where the
  # entry name already exists.
  class EntryExistsError < Error
    # Create a new EntryExistsError with the specified source and name.
    def initialize(source, name)
      super()
      @source = source
      @name = name
    end

    # The message returned by this error.
    def message
      "'#{@source}' failed. Entry #{@name} already exists."
    end
  end

  # Error raised when an entry name is invalid.
  class EntryNameError < Error
    # Create a new EntryNameError with the specified name.
    def initialize(name = nil)
      super()
      @name = name
    end

    # The message returned by this error.
    def message
      if @name.nil?
        'Illegal entry name. Names must have fewer than 65,536 characters.'
      else
        "Illegal entry name '#{@name}'. Names must not start with '/'."
      end
    end
  end

  # Error raised if an entry's CRC-32 checksum does not match the value
  # declared in the archive once the whole entry has been decompressed.
  class EntryCrcError < Error
    # The entry that has caused this error.
    attr_reader :entry

    # The CRC-32 computed from the decompressed entry data.
    attr_reader :computed_crc

    # Create a new EntryCrcError for +entry+, whose checksum was expected
    # to be +expected_crc+ but was computed as +computed_crc+.
    def initialize(entry, expected_crc, computed_crc)
      super()
      @entry = entry
      @expected_crc = expected_crc
      @computed_crc = computed_crc
    end

    # The message returned by this error.
    def message
      "Entry '#{@entry.name}' failed the CRC check. " \
        "Expected 0x#{format('%08x', @expected_crc)}, " \
        "computed 0x#{format('%08x', @computed_crc)}."
    end
  end

  # Error raised if an entry is larger on extraction than it is advertised
  # to be.
  class EntrySizeError < Error
    # The entry that has caused this error.
    attr_reader :entry

    # The number of bytes actually decompressed, if known.
    attr_reader :actual_size

    # Create a new EntrySizeError with the specified entry. +actual_size+
    # is the number of bytes that were actually read, when it is known
    # (e.g. after a complete read produced fewer bytes than advertised).
    def initialize(entry, actual_size = nil)
      super()
      @entry = entry
      @actual_size = actual_size
    end

    # The message returned by this error.
    def message
      if @actual_size.nil?
        "Entry '#{@entry.name}' should be #{@entry.size}B, but is larger when inflated."
      else
        "Entry '#{@entry.name}' should be #{@entry.size}B, " \
          "but inflated to #{@actual_size}B."
      end
    end
  end

  class EntryNumberMismatchError < Error
    # Create a new EntryNumberMismatchError with the specified size and size in bytes.
    def initialize(size, size_in_bytes)
      super()
      @size = size
      @size_in_bytes = size_in_bytes
    end

    # The message returned by this error.
    def message
      "Zip consistency problem: an impossibly high number of entries (#{@size}) " \
        'is declared in this file, compared to the size of the central directory ' \
        "(#{@size_in_bytes} bytes)."
    end
  end

  # Error raised if a split archive is read. Rubyzip does not support reading
  # split archives.
  class SplitArchiveError < Error
    # The message returned by this error.
    def message
      'Rubyzip cannot extract from split archives at this time.'
    end
  end

  # Error raised if there is not enough metadata for the entry to be streamed.
  class StreamingError < Error
    # The entry that has caused this error.
    attr_reader :entry

    # Create a new StreamingError with the specified entry.
    def initialize(entry)
      super()
      @entry = entry
    end

    # The message returned by this error.
    def message
      "The local header of this entry ('#{@entry.name}') does not contain " \
        'the correct metadata for `Zip::InputStream` to be able to ' \
        'uncompress it. Please use `Zip::File` instead of `Zip::InputStream`.'
    end
  end

  # Error raised when a transactional extraction cannot use its staging
  # area because it does not live on the same filesystem as the
  # destination. Committing each entry is atomic only when the staged file
  # can be renamed onto the destination in place, which requires both to
  # reside on the same filesystem.
  class CrossFilesystemError < Error
    # Create a new CrossFilesystemError naming the two mismatching paths.
    def initialize(destination, staging)
      super()
      @destination = destination
      @staging = staging
    end

    # The message returned by this error.
    def message
      "The staging directory '#{@staging}' is on a different filesystem " \
        "from the destination '#{@destination}'. Transactional extraction " \
        'requires them to be on the same filesystem so entries can be ' \
        'committed atomically with rename(2).'
    end
  end

  # Error raised when a transactional extraction is aborted before commit
  # because the caller-supplied cancellation predicate returned true. No
  # destination files are changed.
  class TransactionCancelled < Error
    # Create a new TransactionCancelledError for the given entry name, if
    # the cancellation was triggered while processing a particular entry.
    def initialize(entry_name = nil)
      super()
      @entry_name = entry_name
    end

    # The message returned by this error.
    def message
      if @entry_name
        "Transactional extraction was cancelled while processing '#{@entry_name}'."
      else
        'Transactional extraction was cancelled.'
      end
    end
  end

  # Error raised when the commit phase of a transactional extraction fails
  # partway through. The validated staging area and its manifest are left in
  # place so the operation can be retried with
  # `Zip::TransactionalExtractor.resume`; entries committed before the failure
  # are already on the destination.
  class TransactionCommitError < Error
    # The path to the manifest that records the recoverable state.
    attr_reader :manifest_path

    # Create a new TransactionCommitError wrapping the underlying +cause+
    # and pointing at the +manifest_path+ that records the state.
    def initialize(cause, manifest_path)
      super()
      @cause = cause
      @manifest_path = manifest_path
    end

    # The message returned by this error.
    def message
      "Transactional extraction failed while committing the staged entries " \
        "(#{@cause.class}: #{@cause.message}). The validated staging area was " \
        "kept so the commit can be resumed via Zip::TransactionalExtractor.resume " \
        "using the manifest at '#{@manifest_path}'."
    end
  end
end
