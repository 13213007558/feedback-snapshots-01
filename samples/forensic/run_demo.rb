# frozen_string_literal: true

# End-to-end demonstration of the read-only forensic inspection.
#
# It (re)builds the two malformed micro-samples, snapshots their SHA256 and
# mtime, runs the inspection, snapshots them again, and prints both the
# immutability proof and the offset-based findings. Run it from the repo root:
#
#   ruby -Ilib samples/forensic/run_demo.rb
require 'digest'
require 'fileutils'
require_relative 'build_samples'
require 'zip/forensic'

module ForensicDemo
  module_function

  SAMPLES = {
    'forensic_duplicate_names.zip' => :build_duplicate_names,
    'forensic_misaligned_offsets.zip' => :build_misaligned_offsets
  }.freeze

  def run(output_dir)
    FileUtils.mkdir_p(output_dir)
    SAMPLES.each do |filename, builder|
      bytes, = ForensicSampleBuilder.public_send(builder)
      ForensicSampleBuilder.write(File.join(output_dir, filename), bytes)
    end
    SAMPLES.each_key { |filename| demonstrate(output_dir, filename) }
  end

  def demonstrate(output_dir, filename)
    path = File.join(output_dir, filename)
    before = snapshot(path)
    report = Zip::Forensic.inspect(path)
    after = snapshot(path)

    puts '=' * 78
    puts "SAMPLE: #{filename}"
    puts "report sha256 : #{report.sha256}"
    puts "before sha256 : #{before[:sha256]}"
    puts "after sha256  : #{after[:sha256]}"
    puts "source bytes identical before/after inspection: #{before[:sha256] == after[:sha256]}"
    puts "mtime identical before/after inspection:       #{before[:mtime] == after[:mtime]}"
    puts '-' * 78
    puts report.to_text
    puts
  end

  def snapshot(path)
    { sha256: Digest::SHA256.file(path).hexdigest, mtime: File.stat(path).mtime }
  end
end

if __FILE__ == $PROGRAM_NAME
  target = ARGV[0] || File.expand_path('..', __dir__)
  ForensicDemo.run(target)
end
