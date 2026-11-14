# frozen_string_literal: true

# Removes only the staging directories recorded in a transactional-extraction
# ledger, so temporary resources from one run can be reclaimed without
# touching files belonging to any other task.
#
# A ledger is produced by passing `ledger_path:` to
# Zip::File#extract_all(transactional: true) (or to
# Zip::TransactionalExtractor). Each line is the absolute path to a
# `manifest.json` inside a `.rubyzip-txn-*` staging directory.
#
# Run with:
#   bundle exec ruby samples/transactional_extract_cleanup.rb /path/to/staging-ledger.txt
#
# Pass `--dry-run` to list what would be removed without deleting anything.

require 'fileutils'

dry_run = ARGV.delete('--dry-run')
ledger_path = ARGV.first

if ledger_path.nil?
  warn 'usage: transactional_extract_cleanup.rb [--dry-run] LEDGER_PATH'
  exit 1
end

unless File.file?(ledger_path)
  warn "ledger not found: #{ledger_path}"
  exit 1
end

# Must stay in sync with Zip::TransactionalExtractor::STAGING_PREFIX. The
# script intentionally does not load rubyzip so it can run against a ledger
# produced by any application version.
STAGING_PREFIX = '.rubyzip-txn-'.freeze

removed = 0
File.readlines(ledger_path, chomp: true).each do |manifest|
  next if manifest.empty?

  staging_dir = File.dirname(manifest)
  unless File.basename(staging_dir).start_with?(STAGING_PREFIX)
    warn "skipping unrecognised entry (not a #{STAGING_PREFIX}* path): #{staging_dir}"
    next
  end

  if File.directory?(staging_dir)
    if dry_run
      puts "would remove #{staging_dir}"
    else
      FileUtils.rm_rf(staging_dir)
      puts "removed #{staging_dir}"
    end
    removed += 1
  else
    puts "already gone: #{staging_dir}"
  end
end

# The ledger only ever lists this run's staging areas, so truncate it once
# the referenced directories are gone.
File.binwrite(ledger_path, '') unless dry_run
puts "#{dry_run ? 'matched' : 'cleaned'} #{removed} staging director#{removed == 1 ? 'y' : 'ies'}."
