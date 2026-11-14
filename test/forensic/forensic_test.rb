# frozen_string_literal: true

require_relative '../test_helper'
require 'zip/forensic'
require 'digest'

class ZipForensicTest < Minitest::Test
  def setup
    @tmp = Dir.mktmpdir('zip-forensic')
    @duplicate_path = File.join(@tmp, 'duplicate.zip')
    @misaligned_path = File.join(@tmp, 'misaligned.zip')
    File.binwrite(@duplicate_path, build_duplicate_archive)
    File.binwrite(@misaligned_path, build_misaligned_archive)
  end

  def teardown
    FileUtils.remove_entry(@tmp)
    ::Zip.reset!
  end

  def test_inspects_a_well_formed_archive_without_anomalies
    report = ::Zip::Forensic.inspect(normal_archive_io)
    refute(report.anomaly?)
    assert_equal(2, report.central_records.size)
    assert_equal(2, report.local_headers.size)
    assert_empty(report.regions)
    assert(report.central_records.all? { |record| record.link_status == :linked })
  end

  def test_preserves_central_directory_order_and_duplicate_names
    report = ::Zip::Forensic.inspect(@duplicate_path)
    names = report.central_records.map { |record| record.name.value }
    assert_equal(%w[dup.txt dup.txt], names)
    assert_equal(1, report.duplicate_names.size)
    assert_equal([0, 1], report.duplicate_names.first[:central_record_indexes])
    assert_includes(report.anomalies.map(&:type), :duplicate_entry_name)
  end

  def test_keeps_raw_name_bytes_and_field_provenance
    report = ::Zip::Forensic.inspect(@duplicate_path)
    record = report.central_records.first
    assert_equal('dup.txt'.b, record.name.raw)
    assert_equal(114, record.record_offset)
    offset_field = record.fields[:local_header_offset]
    assert_equal(0, offset_field.value)
    assert_equal([0, 0, 0, 0], offset_field.raw.bytes)
    assert_equal(156, offset_field.offset)
    assert_match(/central directory record #1/, offset_field.source)
  end

  def test_flags_suspicious_trailing_bytes_as_unparsed_region
    report = ::Zip::Forensic.inspect(@duplicate_path)
    trailing = report.regions.find { |region| region.kind == :trailing }
    refute_nil(trailing)
    assert_equal(242, trailing.offset)
    assert_equal(25, trailing.length)
    assert(trailing.preview.start_with?('SUSPICIOUS'.b))
  end

  def test_reports_dangling_offsets_orphans_and_overlaps
    report = ::Zip::Forensic.inspect(@misaligned_path)
    types = report.anomalies.map(&:type)
    assert_includes(types, :dangling_local_header_offset)
    assert_includes(types, :orphan_local_header)
    assert_includes(types, :overlapping_data_ranges)
    assert_includes(types, :local_central_name_mismatch)

    orphans = report.local_headers.select(&:orphan?).map { |h| h.name.value }
    assert_equal(%w[orphan.bin a.txt], orphans)
    dangling = report.anomalies.find { |a| a.type == :dangling_local_header_offset }
    assert_includes(dangling.offsets, 58)
  end

  def test_does_not_synthesize_entries_for_unresolvable_records
    report = ::Zip::Forensic.inspect(@misaligned_path)
    ghost = report.central_records.find { |record| record.name.value == 'ghost.txt' }
    assert_equal(:dangling_offset, ghost.link_status)
    assert_nil(ghost.local_header)
    assert_equal(3, report.central_records.size)
    assert_equal(3, report.local_headers.size)
  end

  def test_never_modifies_the_source_file
    paths = [@duplicate_path, @misaligned_path]
    hashes = paths.to_h { |path| [path, Digest::SHA256.file(path).hexdigest] }
    mtimes = paths.to_h { |path| [path, File.stat(path).mtime] }

    paths.each { |path| ::Zip::Forensic.inspect(path) }

    paths.each do |path|
      assert_equal(hashes[path], Digest::SHA256.file(path).hexdigest)
      assert_equal(mtimes[path], File.stat(path).mtime)
      assert_equal(hashes[path], ::Zip::Forensic.inspect(path).sha256)
    end
  end

  def test_restores_io_position_and_reads_from_io
    io = ::File.open(@duplicate_path, 'rb')
    io.seek(7)
    report = ::Zip::Forensic.inspect(io)
    assert_equal(7, io.tell)
    assert_equal(2, report.central_records.size)
  ensure
    io&.close
  end

  def test_text_report_carries_offsets_and_raw_bytes
    report = ::Zip::Forensic.inspect(@duplicate_path)
    text = report.to_text
    assert_match(/read-only/, text)
    assert_match(/@0x002f/, text) # second local header offset
    assert_match(/64 75 70 2E 74 78 74/, text) # 'dup.txt'
    assert_match(/Unparsed byte regions/, text)
  end

  def test_hash_report_is_serializable_plain_data
    report = ::Zip::Forensic.inspect(@misaligned_path)
    hash = report.to_h
    assert_kind_of(Integer, hash[:file_size])
    assert_kind_of(Array, hash[:anomalies])
    assert_kind_of(Array, hash[:unparsed_regions])
    assert(hash[:central_records].all? { |record| record.key?(:fields) })
  end

  def test_resolves_streamed_data_and_16_byte_data_descriptor
    report = ::Zip::Forensic.inspect(build_streamed_archive)
    refute(report.anomaly?)
    assert_empty(report.regions)
    header = report.local_headers.first
    assert(header.data_descriptor?)
    assert_equal(header.data_end, header.data_descriptor_range.first)
    assert_equal(16, header.data_descriptor_range.last - header.data_descriptor_range.first)
  end

  def test_reports_preamble_bytes_without_treating_them_as_entries
    preamble = 'PRE'.b
    shifted = shift_archive_offsets(build_duplicate_archive, preamble.bytesize)
    report = ::Zip::Forensic.inspect(preamble + shifted)
    region = report.regions.find { |candidate| candidate.kind == :preamble }
    refute_nil(region)
    assert_equal(0, region.offset)
    assert_equal(preamble.bytesize, region.length)
    assert_equal(2, report.central_records.size)
  end

  def test_degrades_safely_when_no_eocd_is_present
    report = ::Zip::Forensic.inspect('plain bytes, no zip structure'.b)
    assert_nil(report.eocd)
    assert_includes(report.anomalies.map(&:type), :eocd_not_found)
    assert_empty(report.central_records)
    assert_empty(report.local_headers)
  end

  def test_forensic_view_is_independent_of_entry_set_duplicate_handling
    ordinary = ::Zip::File.open(@duplicate_path)
    assert_equal(1, ordinary.size) # EntrySet collapses the duplicate

    ::Zip.allow_duplicate_entry_names = true
    ::Zip::File.open(@duplicate_path) do |zip|
      assert_equal(2, zip.size)
    end

    report = ::Zip::Forensic.inspect(@duplicate_path)
    assert_equal(2, report.central_records.size)
  ensure
    ordinary&.close
  end

  private

  def normal_archive_io
    io = ::StringIO.new
    ::Zip::File.open_buffer(io, create: true) do |zip|
      zip.get_output_stream('one.txt') { |out| out.write('one') }
      zip.get_output_stream('two.txt') { |out| out.write('two') }
    end
    io.rewind
    io
  end

  def build_duplicate_archive
    name = 'dup.txt'.b
    first = 'first body'.b
    second = 'second body, different content'.b
    first_local = local(name, first)
    second_local = local(name, second)
    central = central(name, first, 0) +
              central(name, second, first_local.bytesize)
    first_local + second_local + central +
      eocd(2, central.bytesize, first_local.bytesize + second_local.bytesize) +
      'SUSPICIOUS-TRAILING-BYTES'.b
  end

  def build_misaligned_archive
    orphan = local('orphan.bin'.b, 'orphan payload'.b)
    a_local = local('a.txt'.b, 'payload A'.b)
    b_local = local('b.txt'.b, 'payload B, a little longer'.b)
    b_offset = orphan.bytesize + a_local.bytesize
    dangling = orphan.bytesize + 4
    central = central('a.txt'.b, 'payload B, a little longer'.b, b_offset) +
              central('b.txt'.b, 'payload B, a little longer'.b, b_offset) +
              central('ghost.txt'.b, ''.b, dangling, crc: 0, size: 0)
    central_offset = orphan.bytesize + a_local.bytesize + b_local.bytesize
    orphan + a_local + b_local + central + eocd(3, central.bytesize, central_offset)
  end

  def build_streamed_archive
    name = 'stream.txt'.b
    data = 'streamed body'.b
    crc = Zlib.crc32(data)
    # GP bit 3 set and zero sizes in the local header: sizes only become known
    # via the trailing data descriptor and the central directory record.
    local = [0x04034b50, 20, 8, 0, 0, 0, 0, 0, 0, name.bytesize, 0]
            .pack('VvvvvvVVVvv') + name + data
    descriptor = [0x08074b50, crc, data.bytesize, data.bytesize].pack('VVVV')
    central = central(name, data, 0, crc: crc)
    central_offset = local.bytesize + descriptor.bytesize
    local + descriptor + central + eocd(1, central.bytesize, central_offset)
  end

  def local(name, data)
    [0x04034b50, 20, 0, 0, 0, 0, Zlib.crc32(data),
     data.bytesize, data.bytesize, name.bytesize, 0]
      .pack('VvvvvvVVVvv') + name + data
  end

  def central(name, data, offset, crc: Zlib.crc32(data), size: data.bytesize)
    [0x02014b50, 20, 0, 20, 0, 0, 0, 0, crc, size, size,
     name.bytesize, 0, 0, 0, 0, 0, offset]
      .pack('VCCvvvvvVVVvvvvvVV') + name
  end

  def eocd(total, central_size, central_offset)
    [0x06054b50, 0, 0, total, total, central_size, central_offset, 0]
      .pack('VvvvvVVv')
  end

  # Rebuilds the hand-crafted duplicate archive after every absolute offset
  # (two central local-header offsets and the EOCD central-directory offset)
  # is shifted by `delta`, simulating bytes prepended before the first header.
  def shift_archive_offsets(archive, delta)
    rebuilt = archive.dup
    # The two central records' local-header-offset fields (absolute positions).
    [114 + 42, 167 + 42].each do |field_offset|
      rebuilt[field_offset, 4] = [rebuilt.byteslice(field_offset, 4).unpack1('V') + delta].pack('V')
    end
    # Locate the EOCD by signature; its central-directory-offset field is 16
    # bytes in. This stays correct even though the archive has trailing bytes.
    eocd_start = rebuilt.rindex([0x06054b50].pack('V'))
    eocd_field = eocd_start + 16
    rebuilt[eocd_field, 4] = [rebuilt.byteslice(eocd_field, 4).unpack1('V') + delta].pack('V')
    rebuilt
  end
end
