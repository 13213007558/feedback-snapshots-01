# frozen_string_literal: true

require_relative 'test_helper'

class TransactionalExtractTest < Minitest::Test
  def setup
    @tmp = Dir.mktmpdir('rubyzip-txn-test')
    @zip_path = File.join(@tmp, 'archive.zip')
    @dest = File.join(@tmp, 'dest')
    Dir.mkdir(@dest)
    build_archive
  end

  def teardown
    FileUtils.rm_rf(@tmp)
    Zip.reset!
  end

  def test_commits_the_whole_tree_when_every_entry_is_valid
    Zip::File.open(@zip_path) do |zf|
      zf.extract_all(@dest, transactional: true)
    end

    assert_equal 'one' * 10, File.read(File.join(@dest, 'one.txt'))
    assert_equal 'two' * 20, File.read(File.join(@dest, 'sub', 'two.txt'))
    assert File.directory?(File.join(@dest, 'sub'))
    assert_empty staging_leftovers
  end

  def test_class_method_supports_transactional_mode
    Zip::File.extract_all(@zip_path, @dest, transactional: true)

    assert_equal 'one' * 10, File.read(File.join(@dest, 'one.txt'))
    assert_empty staging_leftovers
  end

  def test_pre_existing_files_are_kept_when_a_later_entry_fails_crc
    File.write(File.join(@dest, 'one.txt'), 'ORIGINAL-ONE')
    File.write(File.join(@dest, 'sub-two-placeholder'), 'keep')
    corrupt_entry_crc('sub/two.txt')

    error = assert_raises(Zip::Error) do
      Zip::File.open(@zip_path) do |zf|
        zf.extract_all(@dest, transactional: true) { true }
      end
    end
    assert_kind_of Zip::EntryCrcError, error

    assert_equal 'ORIGINAL-ONE', File.read(File.join(@dest, 'one.txt'))
    assert_equal 'keep', File.read(File.join(@dest, 'sub-two-placeholder'))
    refute File.exist?(File.join(@dest, 'sub', 'two.txt'))
    assert_empty staging_leftovers
  end

  def test_crc_error_is_raised_even_when_the_size_is_correct
    corrupt_declared_crc_only('one.txt')

    assert_raises(Zip::EntryCrcError) do
      Zip::File.open(@zip_path) do |zf|
        zf.extract_all(@dest, transactional: true)
      end
    end
    refute File.exist?(File.join(@dest, 'one.txt'))
    assert_empty staging_leftovers
  end

  def test_size_mismatch_aborts_the_batch
    corrupt_entry_size('one.txt')

    assert_raises(Zip::EntrySizeError) do
      Zip::File.open(@zip_path) do |zf|
        zf.extract_all(@dest, transactional: true)
      end
    end
    refute File.exist?(File.join(@dest, 'one.txt'))
    assert_empty staging_leftovers
  end

  def test_unsupported_compression_aborts_before_touching_destination
    File.write(File.join(@dest, 'one.txt'), 'ORIGINAL')
    mark_unsupported_compression('one.txt')

    assert_raises(Zip::CompressionMethodError) do
      Zip::File.open(@zip_path) do |zf|
        zf.extract_all(@dest, transactional: true) { true }
      end
    end
    assert_equal 'ORIGINAL', File.read(File.join(@dest, 'one.txt'))
    assert_empty staging_leftovers
  end

  def test_destination_exists_policy_is_enforced
    File.write(File.join(@dest, 'one.txt'), 'blocked')

    assert_raises(Zip::DestinationExistsError) do
      Zip::File.open(@zip_path) do |zf|
        zf.extract_all(@dest, transactional: true)
      end
    end
    assert_equal 'blocked', File.read(File.join(@dest, 'one.txt'))
    assert_empty staging_leftovers
  end

  def test_destination_exists_can_be_overridden_by_the_block
    File.write(File.join(@dest, 'one.txt'), 'blocked')

    Zip::File.open(@zip_path) do |zf|
      zf.extract_all(@dest, transactional: true) { true }
    end

    assert_equal 'one' * 10, File.read(File.join(@dest, 'one.txt'))
  end

  def test_cancellation_leaves_the_destination_untouched
    File.write(File.join(@dest, 'old.txt'), 'untouched')

    assert_raises(Zip::TransactionCancelled) do
      Zip::File.open(@zip_path) do |zf|
        zf.extract_all(@dest, transactional: true,
                       cancel_if: ->(entry) { entry.name == 'sub/two.txt' })
      end
    end

    assert_equal ['old.txt'], Dir.children(@dest).sort
    assert_empty staging_leftovers
  end

  def test_cross_filesystem_staging_is_rejected_upfront
    other = File.join(@tmp, 'other-fs')
    Dir.mkdir(other)
    entries = nil
    Zip::File.open(@zip_path) { |zf| entries = zf.entries }

    original_stat = File.method(:stat)
    stat_stub = lambda do |path|
      real = original_stat.call(path)
      next Struct.new(:dev).new(real.dev + 1000) if path.to_s.start_with?(other)

      real
    end

    File.stub(:stat, stat_stub) do
      assert_raises(Zip::CrossFilesystemError) do
        Zip::TransactionalExtractor.new(entries, @dest,
                                        staging_directory: other).extract
      end
    end

    assert_empty Dir.children(@dest)
    assert_empty staging_leftovers(other)
  end

  def test_commit_failure_keeps_a_recoverable_manifest_and_resumes
    entries = nil
    Zip::File.open(@zip_path) { |zf| entries = zf.entries }

    failing = Class.new(Zip::TransactionalExtractor) do
      def commit_file(record)
        raise Errno::EIO, 'simulated' if record[:name] == 'sub/two.txt'

        super
      end
    end

    manifest_path = nil
    assert_raises(Zip::TransactionCommitError) do
      failing.new(entries, @dest).extract
    rescue Zip::TransactionCommitError => e
      manifest_path = e.manifest_path
      raise
    end

    assert File.exist?(manifest_path)
    assert File.exist?(File.join(@dest, 'one.txt'))
    refute File.exist?(File.join(@dest, 'sub', 'two.txt'))

    Zip::TransactionalExtractor.resume(manifest_path)

    assert_equal 'two' * 20, File.read(File.join(@dest, 'sub', 'two.txt'))
    assert_empty staging_leftovers
  end

  def test_restored_permissions_survive_the_staging_and_commit
    src = File.join(@tmp, 'src')
    Dir.mkdir(src)
    File.write(File.join(src, 'script.sh'), '#!/bin/sh')
    File.chmod(0o755, File.join(src, 'script.sh'))
    perm_zip = File.join(@tmp, 'perm.zip')
    Zip::File.open(perm_zip, create: true) { |zf| zf.add_recursive(src) }

    Zip::File.open(perm_zip) do |zf|
      zf.extract_all(@dest, transactional: true)
    end

    target = File.join(@dest, 'script.sh')
    assert File.exist?(target)
    assert_equal 0o100755, File.stat(target).mode
  end

  def test_ledger_records_this_runs_staging_area_only
    ledger = File.join(@tmp, 'ledger.txt')
    unrelated = File.join(@dest, '.rubyzip-txn-run-OTHERKEEPME')
    Dir.mkdir(unrelated)

    Zip::File.open(@zip_path) do |zf|
      zf.extract_all(@dest, transactional: true, ledger_path: ledger)
    end

    # The unrelated staging directory belonging to another task is preserved.
    assert File.directory?(unrelated)
    assert_empty staging_leftovers
    assert_equal '', File.binread(ledger)
  ensure
    FileUtils.rm_rf(unrelated)
  end

  private

  def build_archive
    Zip::OutputStream.open(@zip_path) do |out|
      out.put_next_entry('one.txt')
      out.write('one' * 10)
      out.put_next_entry('sub/')
      out.put_next_entry('sub/two.txt')
      out.write('two' * 20)
    end
  end

  def entry_record(name)
    entry = nil
    Zip::File.open(@zip_path) { |zf| entry = zf.find_entry(name) }
    entry
  end

  def data_region(name)
    entry = entry_record(name)
    start = entry.local_header_offset + 30 +
            entry.name.bytesize + entry.extra.local_size
    [start, entry.compressed_size]
  end

  def rewrite
    data = File.binread(@zip_path)
    yield data
    File.binwrite(@zip_path, data)
  end

  def corrupt_entry_crc(name)
    start, = data_region(name)
    rewrite do |data|
      data.setbyte(start + 2, data.getbyte(start + 2) ^ 0xFF)
    end
  end

  def corrupt_declared_crc_only(name)
    entry = entry_record(name)
    rewrite do |data|
      data.gsub!([entry.crc].pack('V'), [entry.crc ^ 0xDEAD_BEEF].pack('V'))
    end
  end

  def corrupt_entry_size(name)
    entry = entry_record(name)
    rewrite do |data|
      data.gsub!([entry.size].pack('V'), [(entry.size / 2)].pack('V'))
    end
  end

  def mark_unsupported_compression(name)
    entry = entry_record(name)
    start = entry.local_header_offset
    rewrite do |data|
      # Compression method is at offset 8 in the local file header.
      data.setbyte(start + 8, 12) # BZIP2, which rubyzip cannot decompress.
    end
  end

  def staging_leftovers(root = @dest)
    Dir.glob(File.join(root, Zip::TransactionalExtractor::STAGING_PREFIX + '*'))
       .reject { |path| path.end_with?('OTHERKEEPME') }
  end
end
