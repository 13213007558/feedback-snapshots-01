# frozen_string_literal: true

require 'English'
require 'delegate'
require 'singleton'
require 'tempfile'
require 'fileutils'
require 'stringio'
require 'zlib'
require 'zip/version'
require 'zip/constants'
require 'zip/dos_time'
require 'zip/ioextras'
require 'rbconfig'
require 'zip/archive_policy'
require 'zip/entry'
require 'zip/extra_field'
require 'zip/entry_set'
require 'zip/central_directory'
require 'zip/file'
require 'zip/input_stream'
require 'zip/output_stream'
require 'zip/decompressor'
require 'zip/compressor'
require 'zip/null_decompressor'
require 'zip/null_compressor'
require 'zip/null_input_stream'
require 'zip/pass_thru_compressor'
require 'zip/pass_thru_decompressor'
require 'zip/crypto/decrypted_io'
require 'zip/crypto/encryption'
require 'zip/crypto/null_encryption'
require 'zip/crypto/traditional_encryption'
require 'zip/crypto/aes_encryption'
require 'zip/inflater'
require 'zip/deflater'
require 'zip/streamable_stream'
require 'zip/streamable_directory'
require 'zip/errors'

# Rubyzip is a ruby module for reading and writing zip files.
#
# The main entry points are File, InputStream and OutputStream. For a
# file/directory interface in the style of the standard ruby ::File and
# ::Dir APIs then `require 'zip/filesystem'` and see FileSystem.
#
# The settings below are process-wide defaults. They are snapshotted into an
# immutable ArchivePolicy when an archive is opened; later changes do not
# affect archives that are already open. To give one archive a different
# policy (for example, to read an untrusted upload with stricter checks),
# pass `policy: Zip::ArchivePolicy.strict` (or a Hash of overrides) to
# `Zip::File.open`, `Zip::File.open_buffer`, `Zip::InputStream.open` or
# `Zip::OutputStream.open`. See ArchivePolicy for details.
module Zip
  extend self

  attr_accessor :unicode_names,
                :on_exists_proc,
                :continue_on_exists_proc,
                :sort_entries,
                :default_compression,
                :write_zip64_support,
                :warn_invalid_date,
                :case_insensitive_match,
                :allow_duplicate_entry_names,
                :force_entry_names_encoding,
                :validate_entry_sizes,
                :validate_declared_number_of_entries,
                :inflater_chunk_size

  # Settings that are captured per archive when it is opened. Changing any
  # of these only affects archives opened afterwards.
  PER_ARCHIVE_SETTINGS = %i[
    unicode_names
    on_exists_proc
    continue_on_exists_proc
    sort_entries
    default_compression
    write_zip64_support
    warn_invalid_date
    case_insensitive_match
    allow_duplicate_entry_names
    force_entry_names_encoding
    validate_entry_sizes
    validate_declared_number_of_entries
    inflater_chunk_size
  ].freeze # :nodoc:

  # Retained for backwards compatibility; ArchivePolicy holds the defaults
  # used when opening a new archive.
  DEFAULT_RESTORE_OPTIONS = ::Zip::ArchivePolicy::DEFAULT_RESTORE_OPTIONS

  # :nodoc:
  # Remove this when JRuby#3962 is fixed.
  ZLIB_FLUSHING_STRATEGY = defined?(JRUBY_VERSION) ? Zlib::SYNC_FLUSH : Zlib::NO_FLUSH

  def reset! # :nodoc:
    @_ran_once = false
    @unicode_names = false
    @on_exists_proc = false
    @continue_on_exists_proc = false
    @sort_entries = false
    @default_compression = Zlib::DEFAULT_COMPRESSION
    @write_zip64_support = true
    @warn_invalid_date = true
    @case_insensitive_match = false
    @allow_duplicate_entry_names = false
    @force_entry_names_encoding = nil
    @validate_entry_sizes = true
    @validate_declared_number_of_entries = false # Set this to `true` in v4.0.0?
    @inflater_chunk_size = 4096
  end

  # Set options for RubyZip in one block.
  def setup
    yield self unless @_ran_once
    @_ran_once = true
  end

  reset!
end

# Copyright (C) 2002, 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
