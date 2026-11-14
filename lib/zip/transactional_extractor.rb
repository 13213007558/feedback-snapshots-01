# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'securerandom'
require 'time'
require 'zlib'

module Zip
  # Performs an all-or-nothing extraction of a set of Zip::Entry objects.
  #
  # Every entry is first decompressed and validated into a private staging
  # directory. Nothing in the destination directory is touched until every
  # entry has passed its integrity and policy checks, at which point the
  # staged files are committed into place one at a time with atomic
  # +rename(2)+ operations.
  #
  # == Guarantees
  #
  # * Single entry: an entry is staged to completion - all of its bytes read,
  #   its CRC-32 verified, its decompressed size verified and its compression
  #   method supported - before it can appear at the destination. A failed
  #   entry never creates or replaces a destination file.
  # * Whole batch: a commit only starts once *every* entry has passed. If any
  #   entry fails, or the operation is cancelled, the whole batch is aborted
  #   and the destination is left byte-for-byte untouched.
  # * Pre-existing files: a destination file that already exists is not
  #   opened, truncated or deleted until its replacement has been fully
  #   validated. On Unix the replacement is atomic (+rename+). On platforms
  #   where +rename+ cannot replace an existing file, the original is moved
  #   aside and restored if the replacement move fails.
  #
  # == Filesystem restriction
  #
  # The staging directory must be on the same filesystem as the destination
  # so each commit is a rename rather than a copy. By default the staging
  #   directory is created *inside* the destination, which always satisfies
  # this. A custom +staging_directory+ is checked with +File::Stat#dev+ and a
  # Zip::CrossFilesystemError is raised before any entry is processed if the
  # two paths reside on different filesystems.
  #
  # == Cancellation
  #
  # Supply +cancel_if+: a proc called with each entry before it is staged.
  # Returning a truthy value aborts the run with Zip::TransactionCancelled
  # during the staging phase; the staging area is removed and the destination
  # is untouched.
  #
  # == Commit failures and recovery
  #
  # If an I/O error occurs while committing, the validated staging area and a
  # JSON manifest are deliberately kept. The error is re-raised wrapped in a
  # Zip::TransactionCommitError whose +manifest_path+ records exactly which
  # entries remain to be committed. Call ::resume (or #resume) to finish the
  # commit from that manifest; entries already committed are not reprocessed.
  class TransactionalExtractor
    # The prefix used for the per-run staging directory.
    STAGING_PREFIX = '.rubyzip-txn-'

    # The name of the manifest written inside the staging directory.
    MANIFEST_NAME = 'manifest.json'

    # Extracts +entries+ into +destination_directory+ transactionally.
    #
    # +entries+ is an Enumerable of Zip::Entry (as returned by
    # Zip::File#entries). +on_exists+ is the same overwrite-decision proc used
    # by Zip::File#extract_all and receives +[entry, absolute_destination]+.
    def self.extract(entries, destination_directory,
                     on_exists: nil, staging_directory: nil,
                     ledger_path: nil, cancel_if: nil)
      new(entries, destination_directory,
          on_exists: on_exists, staging_directory: staging_directory,
          ledger_path: ledger_path, cancel_if: cancel_if).extract
    end

    # Resumes a previously interrupted commit from the manifest written at
    # +manifest_path+. The staging area must still be present. Returns the
    # extractor once every remaining entry has been committed.
    def self.resume(manifest_path)
      new(nil, nil).resume(manifest_path)
    end

    def initialize(entries, destination_directory,
                   on_exists: nil, staging_directory: nil,
                   ledger_path: nil, cancel_if: nil)
      @entries = entries
      @destination_directory = destination_directory
      @on_exists = on_exists || proc { ::Zip.on_exists_proc }
      @custom_staging_directory = staging_directory
      @ledger_path = ledger_path
      @cancel_if = cancel_if
      @run_id = "run-#{Time.now.utc.strftime('%Y%m%d%H%M%S')}-#{SecureRandom.hex(6)}"
      @ledger_recorded = false
    end

    # Runs the full stage-then-commit extraction.
    def extract
      @destination = ::File.absolute_path(@destination_directory || '.')
      ::FileUtils.mkdir_p(@destination)

      prepare_staging_directory
      verify_same_filesystem!
      @plan = build_plan
      write_manifest('staging')

      begin
        stage_all_entries
      rescue StandardError
        abort_with_cleanup!($ERROR_INFO)
      end
      write_manifest('committing')
      commit_all_entries

      cleanup!
      self
    end

    # Finishes a commit that failed partway through, using a saved manifest.
    # The manifest is self-contained: staged files already carry their
    # restored attributes, so no Zip::Entry objects are needed to finish the
    # commit.
    def resume(manifest_path)
      manifest = load_manifest(manifest_path)
      @run_id = manifest.fetch('run_id')
      @staging_root = manifest.fetch('staging_dir')
      @destination = manifest.fetch('destination')
      @plan = manifest.fetch('entries').map { |record| record.transform_keys(&:to_sym) }
      @entries = []

      write_manifest('committing')
      commit_all_entries
      cleanup!
      self
    end

    private

    # Resolves where every entry will land and partitions directories from
    # files so directories are committed before their contents. Symlink
    # entries are skipped with a warning, mirroring Zip::File#extract_all.
    def build_plan
      dirs, files = @entries.partition(&:directory?)

      (dirs + files).filter_map do |entry|
        if entry.symlink?
          warn "WARNING: skipped symlink '#{entry.name}' during transactional extract_all."
          next
        end

        target = entry.resolve_extract_path(entry.name, @destination)
        next if target.nil?

        {
          name: entry.name,
          type: entry.directory? ? 'directory' : 'file',
          target: target,
          staged: entry.directory? ? nil : staged_path_for(entry),
          committed: false
        }
      end
    end

    def stage_all_entries
      @plan.each do |record|
        entry = find_entry(record[:name])

        if @cancel_if&.call(entry)
          abort_with_cleanup!(TransactionCancelled.new(entry.name))
        end

        case record[:type]
        when 'directory' then stage_directory(entry, record)
        else stage_file(entry, record)
        end
      end
    end

    def stage_directory(entry, record)
      ::FileUtils.mkdir_p(staged_directory_for(record))
      entry.restore_attributes_to_path(staged_directory_for(record))
    end

    def stage_file(entry, record)
      ensure_parent_staged(record)
      ensure_destination_allowed(entry, record[:target])

      computed_crc = Zlib.crc32
      bytes_written = 0

      ::File.open(record[:staged], 'wb') do |os|
        entry.get_input_stream do |is|
          while (buf = is.sysread(Zip::Decompressor::CHUNK_SIZE))
            os.write(buf)
            bytes_written += buf.bytesize
            computed_crc = Zlib.crc32(buf, computed_crc)

            next unless bytes_written > entry.size

            error = EntrySizeError.new(entry)
            raise error if ::Zip.validate_entry_sizes

            warn "WARNING: #{error.message}"
          end
        end
      end

      verify_integrity!(entry, computed_crc, bytes_written)
      entry.restore_attributes_to_path(record[:staged])
    end

    def verify_integrity!(entry, computed_crc, bytes_written)
      raise EntryCrcError.new(entry, entry.crc, computed_crc) unless entry.crc == computed_crc
      raise EntrySizeError.new(entry, bytes_written) if ::Zip.validate_entry_sizes &&
                                                        bytes_written != entry.size
    end

    def ensure_parent_staged(record)
      ::FileUtils.mkdir_p(::File.dirname(record[:staged]))
    end

    def ensure_destination_allowed(entry, target)
      return unless ::File.exist?(target)
      return if @on_exists.call(entry, target)

      raise DestinationExistsError, target
    end

    def commit_all_entries
      @plan.each do |record|
        next if record[:committed]

        case record[:type]
        when 'directory' then commit_directory(record)
        else commit_file(record)
        end
        record[:committed] = true
        write_manifest('committing')
      end
    rescue StandardError => e
      write_manifest('commit_failed')
      raise TransactionCommitError.new(e, manifest_path)
    end

    def commit_directory(record)
      ::FileUtils.mkdir_p(record[:target])
      entry = find_entry(record[:name])
      entry&.restore_attributes_to_path(record[:target])
    end

    def commit_file(record)
      ::FileUtils.mkdir_p(::File.dirname(record[:target]))
      atomic_replace(record[:staged], record[:target])
    end

    # Renames +source+ onto +destination+. On Unix rename(2) replaces an
    # existing destination atomically. Where that is not permitted, move the
    # original aside first and restore it if the replacement move fails, so a
    # failed commit never destroys the previous version.
    def atomic_replace(source, destination)
      ::File.rename(source, destination)
    rescue Errno::EEXIST, Errno::EACCES
      backup = "#{destination}.#{@run_id}.bak"
      ::File.rename(destination, backup)
      begin
        ::File.rename(source, destination)
        FileUtils.rm_f(backup)
      rescue StandardError
        ::File.rename(backup, destination) if ::File.exist?(backup)
        raise
      end
    end

    def prepare_staging_directory
      base = @custom_staging_directory || @destination
      @staging_root = ::File.absolute_path(
        ::File.join(base, "#{STAGING_PREFIX}#{@run_id}")
      )
      ::FileUtils.mkdir_p(@staging_root)
    end

    def verify_same_filesystem!
      return if ::File.stat(@staging_root).dev == ::File.stat(@destination).dev

      abort_with_cleanup!(CrossFilesystemError.new(@destination, @staging_root))
    end

    def staged_path_for(entry)
      ::File.join(@staging_root, 'files', staged_relative(entry.name))
    end

    def staged_directory_for(record)
      ::File.join(@staging_root, 'files', staged_relative(record[:name]))
    end

    def staged_relative(name)
      name.sub(%r{\A/}, '')
    end

    def find_entry(name)
      @entries.find { |entry| entry.name == name }
    end

    def manifest_path
      ::File.join(@staging_root, MANIFEST_NAME)
    end

    def write_manifest(status)
      manifest = {
        run_id: @run_id,
        status: status,
        destination: @destination,
        staging_dir: @staging_root,
        created_at: Time.now.utc.iso8601,
        entries: @plan
      }
      ::File.binwrite(manifest_path, JSON.pretty_generate(manifest))
      append_to_ledger(manifest_path)
    end

    def load_manifest(path)
      JSON.parse(::File.binread(path))
    end

    # The ledger is an optional caller-owned record of the staging area
    # created by this run, so cleanup tooling can identify *this* task's
    # temporary resources without touching files belonging to anything else.
    def append_to_ledger(path)
      return if @ledger_path.nil? || @ledger_recorded

      @ledger_recorded = true
      ::File.open(@ledger_path, 'a') { |file| file.puts(path) }
    end

    def abort_with_cleanup!(error)
      remove_ledger_entry
      FileUtils.rm_rf(@staging_root)
      raise error
    end

    def cleanup!
      remove_ledger_entry
      FileUtils.rm_rf(@staging_root)
    end

    def remove_ledger_entry
      return if @ledger_path.nil? || !::File.exist?(@ledger_path)

      remaining = ::File.readlines(@ledger_path, chomp: true).reject do |path|
        path == manifest_path
      end
      ::File.binwrite(@ledger_path, remaining.empty? ? '' : "#{remaining.join("\n")}\n")
    end
  end
end
