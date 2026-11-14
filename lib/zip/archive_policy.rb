# frozen_string_literal: true

module Zip
  # Immutable security and extraction policy for a single archive.
  #
  # A policy snapshots every process-wide +Zip+ setting that affects how an
  # archive is read or extracted. An archive captures its policy once, when
  # it is opened, and passes it down to its central directory, entry set,
  # entries and input streams. Changing a global +Zip+ setting afterwards
  # therefore has no effect on an archive that is already open, and two
  # archives using different policies can be read concurrently without any
  # global locking.
  #
  # Old callers that configured the +Zip+ globals keep working: those
  # globals are used as the defaults when a new policy (and therefore a new
  # archive) is created. To use a different policy for one archive, pass a
  # policy (or a Hash of overrides) to that archive:
  #
  #   strict = Zip::ArchivePolicy.new(
  #     validate_entry_sizes: true,
  #     allow_duplicate_entry_names: false,
  #     case_insensitive_match: false,
  #     restore_permissions: false
  #   )
  #   Zip::File.open('untrusted.zip', policy: strict) { |zip| ... }
  #
  # A policy is frozen on creation; use {#merge} (or its alias {#with}) to
  # derive a modified copy.
  class ArchivePolicy
    # Defaults used when a policy is constructed without explicit restore
    # options. Defined here so this file can be loaded before +Zip+ itself.
    DEFAULT_RESTORE_OPTIONS = {
      restore_ownership:   false,
      restore_permissions: true,
      restore_times:       true
    }.freeze # :nodoc:

    ATTRIBUTES = %i[
      validate_entry_sizes
      validate_declared_number_of_entries
      allow_duplicate_entry_names
      case_insensitive_match
      sort_entries
      force_entry_names_encoding
      restore_ownership
      restore_permissions
      restore_times
      on_exists_proc
      continue_on_exists_proc
      warn_invalid_date
      inflater_chunk_size
      write_zip64_support
      default_compression
      unicode_names
    ].freeze

    attr_reader(*ATTRIBUTES)

    class << self
      # Snapshots the current process-wide +Zip+ settings. Any +overrides+
      # are applied on top of that snapshot.
      def from_global(overrides = {})
        new(
          validate_entry_sizes:              ::Zip.validate_entry_sizes,
          validate_declared_number_of_entries:
            ::Zip.validate_declared_number_of_entries,
          allow_duplicate_entry_names:       ::Zip.allow_duplicate_entry_names,
          case_insensitive_match:            ::Zip.case_insensitive_match,
          sort_entries:                      ::Zip.sort_entries,
          force_entry_names_encoding:        ::Zip.force_entry_names_encoding,
          restore_ownership:                 DEFAULT_RESTORE_OPTIONS[:restore_ownership],
          restore_permissions:               DEFAULT_RESTORE_OPTIONS[:restore_permissions],
          restore_times:                     DEFAULT_RESTORE_OPTIONS[:restore_times],
          on_exists_proc:                    ::Zip.on_exists_proc,
          continue_on_exists_proc:           ::Zip.continue_on_exists_proc,
          warn_invalid_date:                 ::Zip.warn_invalid_date,
          inflater_chunk_size:               ::Zip.inflater_chunk_size,
          write_zip64_support:               ::Zip.write_zip64_support,
          default_compression:               ::Zip.default_compression,
          unicode_names:                     ::Zip.unicode_names
        ).merge(overrides)
      end

      # Accepts a policy, a Hash of overrides, or +nil+ (meaning "snapshot
      # the globals now"). Anything else is a programming error.
      def coerce(value)
        case value
        when nil
          from_global
        when self
          value
        when Hash
          from_global(value)
        else
          raise ArgumentError,
                "expected a Zip::ArchivePolicy, Hash or nil, got #{value.class}"
        end
      end

      # A conservative policy for untrusted archives: reject physically
      # inconsistent archives and entries, keep duplicate and case-variant
      # names distinct (case-sensitive lookup), and never apply archive
      # ownership/permission/timestamp metadata to extracted files.
      def strict
        from_global(
          validate_entry_sizes: true,
          validate_declared_number_of_entries: true,
          allow_duplicate_entry_names: false,
          case_insensitive_match: false,
          restore_ownership: false,
          restore_permissions: false,
          restore_times: false
        )
      end

      # A permissive policy for trusted archives: tolerate mismatched
      # declared sizes, retain duplicate names, match names case
      # insensitively, and restore permissions and times. Ownership is still
      # not restored, matching the process default.
      def compatible
        from_global(
          validate_entry_sizes: false,
          validate_declared_number_of_entries: false,
          allow_duplicate_entry_names: true,
          case_insensitive_match: true,
          restore_ownership: false,
          restore_permissions: true,
          restore_times: true
        )
      end
    end

    def initialize(
      validate_entry_sizes:              ::Zip.validate_entry_sizes,
      validate_declared_number_of_entries:
        ::Zip.validate_declared_number_of_entries,
      allow_duplicate_entry_names:       ::Zip.allow_duplicate_entry_names,
      case_insensitive_match:            ::Zip.case_insensitive_match,
      sort_entries:                      ::Zip.sort_entries,
      force_entry_names_encoding:        ::Zip.force_entry_names_encoding,
      restore_ownership:                 DEFAULT_RESTORE_OPTIONS[:restore_ownership],
      restore_permissions:               DEFAULT_RESTORE_OPTIONS[:restore_permissions],
      restore_times:                     DEFAULT_RESTORE_OPTIONS[:restore_times],
      on_exists_proc:                    ::Zip.on_exists_proc,
      continue_on_exists_proc:           ::Zip.continue_on_exists_proc,
      warn_invalid_date:                 ::Zip.warn_invalid_date,
      inflater_chunk_size:               ::Zip.inflater_chunk_size,
      write_zip64_support:               ::Zip.write_zip64_support,
      default_compression:               ::Zip.default_compression,
      unicode_names:                     ::Zip.unicode_names
    )
      @validate_entry_sizes              = validate_entry_sizes ? true : false
      @validate_declared_number_of_entries =
        validate_declared_number_of_entries ? true : false
      @allow_duplicate_entry_names       = allow_duplicate_entry_names ? true : false
      @case_insensitive_match            = case_insensitive_match ? true : false
      @sort_entries                      = sort_entries ? true : false
      @force_entry_names_encoding        = force_entry_names_encoding&.dup&.freeze
      @restore_ownership                 = restore_ownership ? true : false
      @restore_permissions               = restore_permissions ? true : false
      @restore_times                     = restore_times ? true : false
      @on_exists_proc                    = on_exists_proc ? true : false
      @continue_on_exists_proc           = continue_on_exists_proc ? true : false
      @warn_invalid_date                 = warn_invalid_date ? true : false
      @inflater_chunk_size               = Integer(inflater_chunk_size)
      @write_zip64_support               = write_zip64_support ? true : false
      @default_compression               = Integer(default_compression)
      @unicode_names                     = unicode_names ? true : false
      freeze
    end

    # Returns a new frozen policy with the given attributes replaced.
    def merge(overrides)
      unknown = overrides.keys.map(&:to_sym) - ATTRIBUTES
      unless unknown.empty?
        raise ArgumentError, "unknown archive policy attribute(s): #{unknown.join(', ')}"
      end

      self.class.new(**to_h.merge(overrides.transform_keys(&:to_sym)))
    end

    alias with merge

    # Returns the policy's attributes as a new Hash.
    def to_h
      ATTRIBUTES.to_h { |attribute| [attribute, public_send(attribute)] }
    end

    def ==(other)
      other.kind_of?(self.class) && to_h == other.to_h
    end

    alias eql? ==

    def hash
      to_h.hash
    end

    def inspect
      "#<#{self.class} #{to_h.map { |key, value| "#{key}=#{value.inspect}" }.join(' ')}>"
    end
  end
end
