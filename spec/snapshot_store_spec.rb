require 'spec_helper'
require 'bundler/audit/database'
require 'bundler/audit/snapshot/store'

require 'fileutils'
require 'tmpdir'

describe Bundler::Audit::Snapshot::Store do
  let(:store_dir) { Dir.mktmpdir('snapshot-store',ENV['TMPDIR']) }
  let(:db_dir)    { Dir.mktmpdir('snapshot-db',ENV['TMPDIR']) }
  let(:vm_root)   { File.expand_path('../fixtures/snapshot_demo',__FILE__) }

  let(:store)    { described_class.new(store_dir) }
  let(:database) { Bundler::Audit::Database.new(db_dir, store: store) }

  def install(version)
    FileUtils.rm_rf(Dir[File.join(db_dir,'gems')])
    FileUtils.cp_r(File.join(vm_root,version,'gems'),db_dir)
  end

  after do
    FileUtils.remove_entry(store_dir) if File.directory?(store_dir)
    FileUtils.remove_entry(db_dir) if File.directory?(db_dir)
  end

  it "materializes a snapshot under its content digest" do
    install('v1')

    snapshot = database.snapshot
    entry    = store.materialize(snapshot,
                                 [['gems/demo-gem/CVE-2026-0001.yml',
                                   File.binread(File.join(db_dir,'gems','demo-gem','CVE-2026-0001.yml'))]])

    expect(entry.path).to eq(store.path_for(snapshot))
    expect(File.file?(File.join(entry.path,'manifest.json'))).to be(true)

    entry.close
  end

  it "reloads a stored snapshot with the same digest and advisories" do
    install('v2')

    snapshot = database.snapshot
    store.materialize(snapshot, snapshot.advisories.map { |advisory|
      relative = advisory.path.delete_prefix(db_dir + File::SEPARATOR)
      [relative, File.binread(advisory.path)]
    }).close

    reloaded = store.load(snapshot.digest)

    expect(reloaded.content_digest).to eq(snapshot.content_digest)
    expect(reloaded.advisories.map(&:id)).to eq(snapshot.advisories.map(&:id))
    expect(reloaded.advisories.map(&:title)).to eq(snapshot.advisories.map(&:title))
  end

  it "uses the store to verify a report after the live database changed" do
    install('v1')

    snapshot = database.snapshot
    store.materialize(snapshot, snapshot.advisories.map { |advisory|
      relative = advisory.path.delete_prefix(db_dir + File::SEPARATOR)
      [relative, File.binread(advisory.path)]
    }).close

    install('v3')

    reloaded = database.snapshot_with_digest(snapshot.digest)

    expect(reloaded.content_digest).to eq(snapshot.content_digest)
    expect(reloaded.advisories.map(&:id)).to eq(['CVE-2026-0001'])
  end

  it "rejects a digest the database no longer matches" do
    install('v1')

    digest = database.snapshot.digest

    # Remove the stored archive as well, so verification must fall back to
    # reading the live database.
    FileUtils.rm_rf(store.snapshots_dir)

    install('v3')

    expect {
      database.snapshot_with_digest(digest)
    }.to raise_error(Bundler::Audit::Snapshot::Unavailable,
                     /does not contain/)
  end

  it "prunes unreferenced snapshots but keeps leased ones" do
    install('v1')

    snapshot = database.snapshot
    entry    = store.materialize(snapshot, snapshot.advisories.map { |advisory|
      relative = advisory.path.delete_prefix(db_dir + File::SEPARATOR)
      [relative, File.binread(advisory.path)]
    })

    expect(store.prune).to be_empty
    expect(File.directory?(entry.path)).to be(true)

    entry.close

    expect(store.prune).to eq([snapshot.content_digest])
    expect(File.directory?(store.path_for(snapshot))).to be(false)
  end

  it "prunes leased snapshots when forced, without breaking the scan" do
    install('v2')

    snapshot = database.snapshot
    entry    = store.materialize(snapshot, snapshot.advisories.map { |advisory|
      relative = advisory.path.delete_prefix(db_dir + File::SEPARATOR)
      [relative, File.binread(advisory.path)]
    })

    expect(store.prune(force: true)).to eq([snapshot.content_digest])
    expect(File.directory?(entry.path)).to be(false)

    # The snapshot holds its parsed advisories in memory, so deleting the
    # stored files does not change what a running scan sees.
    expect(snapshot.advisories.map(&:id)).to match_array(
      ['CVE-2026-0001','CVE-2026-0002']
    )
    expect(snapshot.advisories.first.title).to eq(
      'Demo vulnerability one (revised)'
    )

    entry.close
  end

  it "detects a corrupted stored snapshot" do
    install('v1')

    snapshot = database.snapshot
    store.materialize(snapshot, snapshot.advisories.map { |advisory|
      relative = advisory.path.delete_prefix(db_dir + File::SEPARATOR)
      [relative, File.binread(advisory.path)]
    }).close

    File.write(
      File.join(store.path_for(snapshot),'gems','demo-gem','CVE-2026-0001.yml'),
      "---\ngem: demo-gem\ncve: 2026-0001\ntitle: tampered\n"
    )

    expect {
      store.load(snapshot.digest)
    }.to raise_error(Bundler::Audit::Snapshot::Corrupt)
  end

  it "prunes only snapshots older than the given time" do
    install('v1')

    snapshot = database.snapshot
    store.materialize(snapshot, snapshot.advisories.map { |advisory|
      relative = advisory.path.delete_prefix(db_dir + File::SEPARATOR)
      [relative, File.binread(advisory.path)]
    }).close

    expect(store.prune(older_than: Time.now + 60)).to eq([snapshot.content_digest])
  end
end
