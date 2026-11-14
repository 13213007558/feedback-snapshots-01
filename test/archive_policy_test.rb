# frozen_string_literal: true

require 'fileutils'

require_relative 'test_helper'
require_relative 'helpers/assert_entry'

# The security-relevant read/extract settings must belong to each archive,
# not to process-wide state. These tests interleave two archives opened with
# different policies and prove that (a) neither sees the other's settings,
# and (b) changing a global setting after opening has no effect.
class ArchivePolicyTest < Minitest::Test
  include AssertEntry

  def setup
    super
    @tmp = Dir.mktmpdir
  end

  def teardown
    FileUtils.rm_rf(@tmp)
    ::Zip.reset!
  end

  # Builds an archive containing two entries with the same name, each with
  # different contents, and returns its path.
  def build_duplicate_archive(name = 'dup.zip')
    path = ::File.join(@tmp, name)
    first = ::File.join(@tmp, 'first.txt')
    second = ::File.join(@tmp, 'second.txt')
    ::File.write(first, 'first contents')
    ::File.write(second, 'second contents')

    ::Zip.allow_duplicate_entry_names = true
    ::Zip::OutputStream.open(path) do |zos|
      zos.put_next_entry('same.txt')
      zos.write(::File.read(first))
      zos.put_next_entry('same.txt')
      zos.write(::File.read(second))
    end
    path
  end

  # Builds an archive whose payload is larger than its declared size, and
  # returns [path, real_size, declared_size].
  def build_bomb_archive(name = 'bomb.zip', true_size: 500_000, declared_size: 1)
    real = ::File.join(@tmp, 'real.zip')
    fake = ::File.join(@tmp, name)
    # Disable Zip64 for the source archive so the (fixed-width) size fields
    # below are the ones actually stored.
    ::Zip::File.open(real, create: true, policy: { write_zip64_support: false }) do |zf|
      zf.get_output_stream('a') { |os| os.write('a' * true_size) }
    end

    compressed_size = nil
    ::Zip::File.open(real) { |zf| compressed_size = zf.find_entry('a').compressed_size }

    data = ::File.binread(real)
    data.gsub!(
      [compressed_size, true_size, 1].pack('VVv'),
      [compressed_size, declared_size, 1].pack('VVv')
    )
    ::File.binwrite(fake, data)
    [fake, true_size, declared_size]
  end

  # Builds an archive with an entry whose Unix permissions are 0600.
  def build_permissions_archive(name = 'perm.zip')
    path = ::File.join(@tmp, name)
    src = ::File.join(@tmp, 'secret.sh')
    ::File.write(src, 'echo secret')
    ::File.chmod(0o600, src)
    ::Zip::File.open(path, create: true) { |zf| zf.add('secret.sh', src) }
    path
  end

  def test_declared_size_validation_is_per_archive
    bomb, true_size, declared_size = build_bomb_archive

    # Open both archives before reading either, to prove policy is captured
    # per archive rather than sampled per read.
    permissive = ::Zip::File.new(bomb, policy: { validate_entry_sizes: false })
    strict     = ::Zip::File.new(bomb, policy: { validate_entry_sizes: true })

    # Flip the global after both are open; neither should change behaviour.
    ::Zip.validate_entry_sizes = true
    assert_output('', /should be #{declared_size}B/) do
      permissive.extract('a', 'permissive.bin', destination_directory: @tmp)
    end
    assert_equal(true_size, ::File.size(::File.join(@tmp, 'permissive.bin')))

    ::Zip.validate_entry_sizes = false
    error = assert_raises(::Zip::EntrySizeError) do
      strict.extract('a', 'strict.bin', destination_directory: @tmp)
    end
    assert_match(/should be #{declared_size}B/, error.message)
    # Extraction aborts as soon as the declared size is exceeded; the
    # (partial) destination is left behind for the caller to clean up.
    assert_operator(::File.size(::File.join(@tmp, 'strict.bin')), :<, true_size)

    permissive.close
    strict.close
  end

  def test_duplicate_entry_names_are_per_archive
    dup = build_duplicate_archive

    ::Zip.allow_duplicate_entry_names = false
    compatible = ::Zip::File.new(dup, policy: ::Zip::ArchivePolicy.compatible)
    ::Zip.allow_duplicate_entry_names = false
    strict = ::Zip::File.new(dup, policy: ::Zip::ArchivePolicy.strict)

    # Set the global after both are open, to prove it has no effect.
    ::Zip.allow_duplicate_entry_names = true
    assert_equal(2, compatible.size)
    assert_equal(2, compatible.find_entry('same.txt').size)
    assert_equal('second contents', compatible.read(compatible.find_entry('same.txt').last))

    assert_equal(1, strict.size)
    assert_kind_of(::Zip::Entry, strict.find_entry('same.txt'))
    # With duplicates disallowed the later entry overwrites the earlier one's
    # key, so the single retained entry holds the second payload.
    assert_equal('second contents', strict.read('same.txt'))

    compatible.close
    strict.close
  end

  def test_case_insensitive_match_is_per_archive
    path = ::File.join(@tmp, 'case.zip')
    ::Zip::File.open(path, create: true) do |zf|
      zf.get_output_stream('MiXeD.TXT') { |os| os.write('payload') }
    end

    compatible = ::Zip::File.new(path, policy: { case_insensitive_match: true })
    strict     = ::Zip::File.new(path, policy: { case_insensitive_match: false })

    refute_nil(compatible.find_entry('mixed.txt'))
    assert_equal('payload', compatible.read('mixed.txt'))

    assert_nil(strict.find_entry('mixed.txt'))
    assert_raises(Errno::ENOENT) { strict.read('mixed.txt') }

    compatible.close
    strict.close
  end

  def test_restore_permissions_is_per_archive
    perm = build_permissions_archive
    strict_dir = ::File.join(@tmp, 'strict')
    compatible_dir = ::File.join(@tmp, 'compatible')
    Dir.mkdir(strict_dir)
    Dir.mkdir(compatible_dir)

    # Both archives open; globals deliberately contradict both policies.
    ::Zip.allow_duplicate_entry_names = true
    strict = ::Zip::File.new(perm, policy: { restore_permissions: false })
    ::Zip.allow_duplicate_entry_names = false
    compatible = ::Zip::File.new(perm, policy: { restore_permissions: true })

    strict.extract('secret.sh', 'secret.sh', destination_directory: strict_dir)
    compatible.extract('secret.sh', 'secret.sh', destination_directory: compatible_dir)

    strict_mode = ::File.stat(::File.join(strict_dir, 'secret.sh')).mode & 0o777
    compatible_mode = ::File.stat(::File.join(compatible_dir, 'secret.sh')).mode & 0o777

    assert_equal((0o666 - ::File.umask) & 0o777, strict_mode)
    assert_equal(0o600, compatible_mode)
    refute_equal(strict_mode, compatible_mode)

    strict.close
    compatible.close
  end

  # Exercises all three policies' signatures at once, with the archives
  # interleaved at entry granularity rather than merely opened together.
  def test_interleaved_archives_do_not_share_policy
    bomb, true_size, declared_size = build_bomb_archive('bomb.zip')
    dup = build_duplicate_archive
    perm = build_permissions_archive

    dest = ::File.join(@tmp, 'out')
    ::Dir.mkdir(dest)

    strict_bomb = ::Zip::File.new(bomb, policy: ::Zip::ArchivePolicy.strict)
    compatible_dup = ::Zip::File.new(dup, policy: ::Zip::ArchivePolicy.compatible)
    strict_dup = ::Zip::File.new(dup, policy: ::Zip::ArchivePolicy.strict)
    compatible_perm = ::Zip::File.new(perm, policy: ::Zip::ArchivePolicy.compatible)

    # Interleave operations across archives. If any setting leaked between
    # archives, one of these would come out with the other's behaviour.
    assert_equal(2, compatible_dup.find_entry('same.txt').size)

    assert_raises(::Zip::EntrySizeError) do
      strict_bomb.extract('a', 'bomb-out', destination_directory: dest)
    end

    assert_equal(1, strict_dup.size)
    refute(strict_dup.find_entry('same.txt').kind_of?(Array))

    compatible_perm.extract('secret.sh', 'secret.sh', destination_directory: dest)
    assert_equal(0o600, ::File.stat(::File.join(dest, 'secret.sh')).mode & 0o777)

    # Back to the first archive: its policy is still the strict one.
    assert_raises(::Zip::EntrySizeError) do
      strict_bomb.extract('a', 'bomb-out-2', destination_directory: dest)
    end
    # ...and the compatible duplicate view is still duplicate-aware.
    assert_equal(2, compatible_dup.find_entry('same.txt').size)

    strict_bomb.close
    compatible_dup.close
    strict_dup.close
    compatible_perm.close
  end

  def test_global_changes_after_open_do_not_affect_open_archive
    dup = build_duplicate_archive
    zip = ::Zip::File.new(dup, policy: { allow_duplicate_entry_names: false })

    ::Zip.allow_duplicate_entry_names = true
    ::Zip.case_insensitive_match = true
    ::Zip.validate_entry_sizes = false

    assert_equal(1, zip.size)
    refute(zip.find_entry('same.txt').kind_of?(Array))

    zip.close
  end

  def test_global_defaults_apply_to_new_archives
    @path = ::File.join(@tmp, 'defaults.zip')
    ::Zip::File.open(@path, create: true) do |zf|
      zf.get_output_stream('a.txt') { |os| os.write('a') }
    end

    ::Zip.allow_duplicate_entry_names = true
    first = ::Zip::File.new(@path)
    assert_equal(true, first.policy.allow_duplicate_entry_names)

    ::Zip.allow_duplicate_entry_names = false
    second = ::Zip::File.new(@path)
    assert_equal(false, second.policy.allow_duplicate_entry_names)

    first.close
    second.close
  end

  def test_declared_entry_count_validation_is_per_archive
    fixture = ::File.join(__dir__, 'data', 'zipWithTooBigCDirSizeField.zip')

    permissive = nil
    assert_output('', /Zip consistency problem:/) do
      permissive = ::Zip::File.count_entries(
        fixture, policy: { validate_declared_number_of_entries: false }
      )
    end
    assert_kind_of(Integer, permissive)

    assert_raises(::Zip::EntryNumberMismatchError) do
      ::Zip::File.count_entries(
        fixture, policy: { validate_declared_number_of_entries: true }
      )
    end

    # The global is untouched by either call.
    assert_equal(false, ::Zip.validate_declared_number_of_entries)
  end

  def test_on_exists_proc_is_per_archive
    perm = build_permissions_archive
    dest = ::File.join(@tmp, 'dest')
    ::Dir.mkdir(dest)
    ::File.write(::File.join(dest, 'secret.sh'), 'already here')

    overwrite = ::Zip::File.new(perm, policy: { on_exists_proc: true })
    overwrite.extract('secret.sh', 'secret.sh', destination_directory: dest)
    assert_equal('echo secret', ::File.read(::File.join(dest, 'secret.sh')))
    overwrite.close

    ::File.write(::File.join(dest, 'secret.sh'), 'already here')
    refuse = ::Zip::File.new(perm, policy: { on_exists_proc: false })
    assert_raises(::Zip::DestinationExistsError) do
      refuse.extract('secret.sh', 'secret.sh', destination_directory: dest)
    end
    refuse.close
  end

  def test_policy_is_frozen
    policy = ::Zip::ArchivePolicy.new
    assert(policy.frozen?)
    # No writers are exposed; +merge+ returns a new object.
    refute_respond_to(policy, :validate_entry_sizes=)
    refute_same(policy, policy.merge(validate_entry_sizes: false))
  end

  def test_policy_merge_copies
    strict = ::Zip::ArchivePolicy.strict
    relaxed = strict.merge(validate_entry_sizes: false)

    refute_equal(strict, relaxed)
    assert_equal(true, strict.validate_entry_sizes)
    assert_equal(false, relaxed.validate_entry_sizes)
    assert_equal(strict.case_insensitive_match, relaxed.case_insensitive_match)
  end

  def test_unknown_policy_attribute_is_rejected
    assert_raises(ArgumentError) do
      ::Zip::ArchivePolicy.new(no_such_option: true)
    end
    assert_raises(ArgumentError) do
      ::Zip::File.open(@tmp, policy: { no_such_option: true })
    end
  end

  def test_policy_reaches_entry_set_and_input_stream
    perm = build_permissions_archive
    zip = ::Zip::File.new(perm, policy: { restore_permissions: false })
    entry = zip.find_entry('secret.sh')

    assert_same(zip.policy, entry.policy)
    stream = entry.get_input_stream
    assert_same(zip.policy, stream.instance_variable_get(:@policy))
    decompressor = stream.instance_variable_get(:@decompressor)
    assert_same(zip.policy, decompressor.policy)
    stream.close
    zip.close
  end

  def test_concurrent_archives_do_not_share_policy
    bomb, = build_bomb_archive
    dup = build_duplicate_archive

    strict = ::Zip::ArchivePolicy.strict
    compatible = ::Zip::ArchivePolicy.compatible

    strict_thread = Thread.new do
      ::Zip::File.open(bomb, policy: strict) do |zf|
        50.times do |i|
          zf.extract('a', "strict-#{i}", destination_directory: @tmp)
        rescue ::Zip::EntrySizeError
          # Expected: the strict archive keeps refusing.
        end
        :ok
      end
    end

    compatible_thread = Thread.new do
      ::Zip::File.open(dup, policy: compatible) do |zf|
        50.times do
          raise 'lost duplicate entries' unless zf.find_entry('same.txt').size == 2
          raise 'lost case-insensitive lookup' unless zf.find_entry('SAME.TXT').size == 2
        end
        :ok
      end
    end

    assert_equal(:ok, strict_thread.value)
    assert_equal(:ok, compatible_thread.value)

    # Every strict extraction aborted at the declared size; nothing was
    # written in full, and the compatible archive was never affected.
    assert_operator(::File.size(::File.join(@tmp, 'strict-0')), :<, 500_000)
  end

  def test_input_stream_accepts_policy
    path = ::File.join(@tmp, 'stream.zip')
    ::Zip::File.open(path, create: true) do |zf|
      zf.get_output_stream('MiXeD.TXT') { |os| os.write('payload') }
    end

    names = []
    ::Zip::InputStream.open(
      path, policy: { force_entry_names_encoding: 'UTF-8' }
    ) do |io|
      while (entry = io.get_next_entry)
        names << entry.name
      end
    end
    assert_equal(['MiXeD.TXT'], names)
  end

  def test_file_restore_accessors_derive_new_policy
    perm = build_permissions_archive
    zip = ::Zip::File.new(perm)
    zip.restore_permissions = false
    assert_equal(false, zip.policy.restore_permissions)
    assert_equal(false, zip.restore_permissions)
    zip.close

    fresh = ::Zip::File.new(perm)
    assert_equal(true, fresh.policy.restore_permissions)
    fresh.close
  end
end
