# frozen_string_literal: true

# Demonstrates transactional (all-or-nothing) extraction with
# Zip::File#extract_all(transactional: true).
#
# It creates its own scratch directory under $TMPDIR, names every temporary
# resource with a unique run id and records each staging area in a ledger so
# the accompanying `transactional_extract_cleanup.rb` can identify and remove
# *this* run's resources without touching files belonging to anything else.
#
# Run with:
#   bundle exec ruby samples/transactional_extract_demo.rb

require 'fileutils'
require 'json'
require 'securerandom'
require 'tmpdir'

$LOAD_PATH.unshift File.expand_path('../lib', __dir__)
require 'zip'

RUN_ID = "rubyzip-txn-demo-#{Time.now.utc.strftime('%Y%m%d%H%M%S')}-#{SecureRandom.hex(4)}"
ROOT = File.join(Dir.tmpdir, RUN_ID)
LEDGER = File.join(ROOT, 'staging-ledger.txt')

def banner(title)
  puts
  puts "=" * 72
  puts title
  puts "=" * 72
end

def snapshot(dest)
  Dir.glob(File.join(dest, '**', '*'))
     .reject { |path| File.basename(path).start_with?(Zip::TransactionalExtractor::STAGING_PREFIX) }
     .sort
     .map { |path| path.sub(dest + File::SEPARATOR, '') }
end

def make_archive(path)
  Zip::OutputStream.open(path) do |out|
    out.put_next_entry('config/app.txt')
    out.write('application configuration')
    out.put_next_entry('data/early.txt')
    out.write('early entry - valid')
    out.put_next_entry('data/late.txt')
    out.write('late entry - this one will be corrupted')
  end
end

def entry_data_offset(zip_path, name)
  entry = nil
  Zip::File.open(zip_path) { |zf| entry = zf.find_entry(name) }
  entry.local_header_offset + 30 + entry.name.bytesize + entry.extra.local_size
end

# Flip a byte inside the *deflate stream* of the last entry so its CRC-32 no
# longer matches while the central directory stays parseable.
def corrupt_last_entry(good_path, bad_path)
  data = File.binread(good_path).b
  offset = entry_data_offset(good_path, 'data/late.txt')
  data.setbyte(offset + 2, data.getbyte(offset + 2) ^ 0xFF)
  File.binwrite(bad_path, data)
end

FileUtils.mkdir_p(ROOT)
FileUtils.touch(LEDGER)
puts "Run id:      #{RUN_ID}"
puts "Scratch dir: #{ROOT}"
puts "Ledger:      #{LEDGER}"

# ---------------------------------------------------------------------------
banner '1. Corrupted archive: a CRC error in the LAST entry leaves the old version intact'
# ---------------------------------------------------------------------------
good_zip = File.join(ROOT, 'good.zip')
bad_zip = File.join(ROOT, 'corrupted.zip')
make_archive(good_zip)
corrupt_last_entry(good_zip, bad_zip)

dest_one = File.join(ROOT, 'dest-corrupt')
FileUtils.mkdir_p(File.join(dest_one, 'data'))
# Pre-existing business files, including one with the same name as an entry.
File.write(File.join(dest_one, 'data', 'late.txt'), 'PREVIOUS GOOD VERSION')
File.write(File.join(dest_one, 'unrelated.txt'), 'belongs to another task')

puts "before: #{snapshot(dest_one).inspect}"
begin
  Zip::File.open(bad_zip) do |zf|
    zf.extract_all(dest_one, transactional: true, ledger_path: LEDGER) { true }
  end
rescue Zip::EntryCrcError => e
  puts "aborted with: #{e.class}: #{e.message}"
end
puts "after:  #{snapshot(dest_one).inspect}"
puts "late.txt still holds: #{File.read(File.join(dest_one, 'data', 'late.txt')).inspect}"
puts "staging leftovers:    #{Dir.glob(File.join(dest_one, '.rubyzip-txn-*')).inspect}"

# ---------------------------------------------------------------------------
banner '2. Healthy archive: the whole validated batch commits atomically'
# ---------------------------------------------------------------------------
dest_two = File.join(ROOT, 'dest-good')
FileUtils.mkdir_p(dest_two)
File.write(File.join(dest_two, 'unrelated.txt'), 'belongs to another task')

Zip::File.open(good_zip) do |zf|
  zf.extract_all(dest_two, transactional: true, ledger_path: LEDGER)
end
puts "committed: #{snapshot(dest_two).inspect}"
puts "staging leftovers: #{Dir.glob(File.join(dest_two, '.rubyzip-txn-*')).inspect}"

# ---------------------------------------------------------------------------
banner '3. Commit-phase I/O failure: recoverable state, then resume'
# ---------------------------------------------------------------------------
dest_three = File.join(ROOT, 'dest-recover')
FileUtils.mkdir_p(dest_three)
entries = nil
Zip::File.open(good_zip) { |zf| entries = zf.entries }

# Inject an I/O error while committing the second file.
failing_extractor = Class.new(Zip::TransactionalExtractor) do
  def commit_file(record)
    raise Errno::EIO, 'simulated disk failure during rename' if record[:name] == 'data/early.txt'

    super
  end
end

manifest_path = nil
begin
  failing_extractor.new(entries, dest_three, ledger_path: LEDGER).extract
rescue Zip::TransactionCommitError => e
  manifest_path = e.manifest_path
  puts "commit failed: #{e.class}"
  puts "manifest kept: #{manifest_path}"
  state = JSON.parse(File.binread(manifest_path))
  puts "manifest status: #{state['status']}"
  puts "committed so far: #{state['entries'].select { |r| r['committed'] }.map { |r| r['name'] }.inspect}"
end
puts "destination after failure: #{snapshot(dest_three).inspect}"

puts
puts 'Resuming the commit from the manifest...'
Zip::TransactionalExtractor.resume(manifest_path)
puts "destination after resume:  #{snapshot(dest_three).inspect}"
puts "staging leftovers: #{Dir.glob(File.join(dest_three, '.rubyzip-txn-*')).inspect}"

# ---------------------------------------------------------------------------
banner '4. A failed commit that is NOT resumed: staging retained and ledger-identified'
# ---------------------------------------------------------------------------
dest_four = File.join(ROOT, 'dest-orphan')
FileUtils.mkdir_p(dest_four)

orphan_manifest = nil
begin
  failing_extractor.new(entries, dest_four, ledger_path: LEDGER).extract
rescue Zip::TransactionCommitError => e
  orphan_manifest = e.manifest_path
  puts "commit failed again; staging deliberately retained at:"
  puts "  #{File.dirname(orphan_manifest)}"
end
puts "ledger now records the retained resource:"
puts File.binread(LEDGER)
puts "Clean it (and only ledger-listed resources) with:"
puts "  bundle exec ruby samples/transactional_extract_cleanup.rb #{LEDGER}"

# ---------------------------------------------------------------------------
banner 'Ledger contents (identifies this run'"'"'s temporary resources)'
# ---------------------------------------------------------------------------
ledger_text = File.binread(LEDGER)
puts(ledger_text.empty? ? '(empty - every staging area was cleaned up or resumed)' : ledger_text)
puts
puts "All scratch data for this run lives under: #{ROOT}"
puts 'Remove it safely with:'
puts "  bundle exec ruby samples/transactional_extract_cleanup.rb #{LEDGER}"
