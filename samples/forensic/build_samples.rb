# frozen_string_literal: true

# Builds the two hand-crafted, deliberately malformed ZIP archives used to
# demonstrate the read-only forensic inspection. Every byte is assembled
# explicitly (rather than through Zip::File) so that the central directory
# offsets, duplicate names and trailing bytes are exactly where the
# accompanying evidence report says they are.
#
# Usage: ruby samples/forensic/build_samples.rb [output_directory]
module ForensicSampleBuilder
  LOCAL_SIG   = 0x04034b50
  CENTRAL_SIG = 0x02014b50
  EOCD_SIG    = 0x06054b50

  module_function

  def local_header(name, crc, compressed_data, extra = ''.b)
    [
      LOCAL_SIG, 20, 0, 0, 0, 0, crc,
      compressed_data.bytesize, compressed_data.bytesize,
      name.bytesize, extra.bytesize
    ].pack('VvvvvvVVVvv') + name + extra + compressed_data
  end

  def central_record(name, crc, compressed_size, local_offset, extra = ''.b,
                     comment = ''.b)
    [
      CENTRAL_SIG, 20, 0, 20, 0, 0, 0, 0, crc,
      compressed_size, compressed_size,
      name.bytesize, extra.bytesize, comment.bytesize, 0, 0, 0,
      local_offset
    ].pack('VCCvvvvvVVVvvvvvVV') + name + extra + comment
  end

  def eocd(total_entries, central_size, central_offset, comment = ''.b)
    [
      EOCD_SIG, 0, 0, total_entries, total_entries,
      central_size, central_offset, comment.bytesize
    ].pack('VvvvvVVv') + comment
  end

  # Sample 1: two central records with identical raw name bytes (the second
  # would be silently dropped by a name-keyed EntrySet), plus bytes appended
  # after the EOCD. Both local headers are valid and distinct.
  def build_duplicate_names
    name = 'dup.txt'.b
    first_data = 'first body'.b
    second_data = 'second body, different content'.b
    first_crc = Zlib.crc32(first_data)
    second_crc = Zlib.crc32(second_data)

    first_local = local_header(name, first_crc, first_data)
    second_local = local_header(name, second_crc, second_data)
    first_offset = 0
    second_offset = first_local.bytesize

    central = central_record(name, first_crc, first_data.bytesize, first_offset) +
              central_record(name, second_crc, second_data.bytesize, second_offset)
    central_offset = first_local.bytesize + second_local.bytesize
    archive = first_local + second_local + central +
              eocd(2, central.bytesize, central_offset)
    [archive + 'SUSPICIOUS-TRAILING-BYTES'.b, {
      first_local: first_offset, second_local: second_offset,
      central_offset: central_offset, trailing_size: 25
    }]
  end

  # Sample 2: three local headers but three central records with broken links.
  # - central record #1 ('a.txt') points at the last local header ('b.txt'):
  #   a misaligned offset, name mismatch and an overlap with record #2.
  # - central record #2 ('b.txt') points at the same header, so its data range
  #   overlaps record #1's.
  # - central record #3 ('ghost.txt') points inside the orphan's data region,
  #   where no local header signature exists: a dangling offset.
  # - the first two local headers ('orphan.bin' and the real 'a.txt') are
  #   referenced by no central record.
  def build_misaligned_offsets
    orphan_data = 'orphan payload'.b
    a_data = 'payload A'.b
    b_data = 'payload B, a little longer'.b

    orphan_local = local_header('orphan.bin'.b, Zlib.crc32(orphan_data), orphan_data)
    a_local = local_header('a.txt'.b, Zlib.crc32(a_data), a_data)
    b_local = local_header('b.txt'.b, Zlib.crc32(b_data), b_data)

    orphan_offset = 0
    a_offset = orphan_local.bytesize
    b_offset = a_offset + a_local.bytesize
    # Inside the orphan's data region: no local header signature lives there.
    dangling_offset = orphan_offset + orphan_local.bytesize + 4

    # Record #1 claims the name 'a.txt' but deliberately points at b's header.
    central = central_record('a.txt'.b, Zlib.crc32(b_data), b_data.bytesize, b_offset) +
              central_record('b.txt'.b, Zlib.crc32(b_data), b_data.bytesize, b_offset) +
              central_record('ghost.txt'.b, 0, 0, dangling_offset)
    central_offset = orphan_offset + orphan_local.bytesize +
                     a_local.bytesize + b_local.bytesize
    archive = orphan_local + a_local + b_local + central +
              eocd(3, central.bytesize, central_offset)
    [archive, {
      orphan_local: orphan_offset, a_local: a_offset, b_local: b_offset,
      dangling_offset: dangling_offset, central_offset: central_offset
    }]
  end

  def write(path, bytes)
    File.binwrite(path, bytes)
  end
end

if __FILE__ == $PROGRAM_NAME
  require 'zlib'
  output_dir = ARGV[0] || File.expand_path('..', __dir__)
  dup_bytes, dup_meta = ForensicSampleBuilder.build_duplicate_names
  mis_bytes, mis_meta = ForensicSampleBuilder.build_misaligned_offsets
  ForensicSampleBuilder.write(File.join(output_dir, 'forensic_duplicate_names.zip'), dup_bytes)
  ForensicSampleBuilder.write(File.join(output_dir, 'forensic_misaligned_offsets.zip'), mis_bytes)
  puts "duplicate-names sample: #{dup_bytes.bytesize} bytes, #{dup_meta.inspect}"
  puts "misaligned sample:      #{mis_bytes.bytesize} bytes, #{mis_meta.inspect}"
end
