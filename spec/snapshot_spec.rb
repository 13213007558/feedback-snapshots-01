require 'spec_helper'
require 'bundler/audit/database'
require 'bundler/audit/scanner'
require 'bundler/audit/report'

require 'fileutils'
require 'tmpdir'

#
# End-to-end demonstration of database snapshot semantics.
#
# Two local database versions are used.  The "database" is a scratch git
# repository with a local bare remote, so version one and version two are
# real commits and updates are real fast-forwards.
#
describe "database snapshots" do
  let(:vm_root) { File.expand_path('../fixtures/snapshot_demo',__FILE__) }
  let(:bundle)  { File.expand_path('../bundle/snapshot_demo',__FILE__) }

  let(:db_dir)     { Dir.mktmpdir('snapshot-db',ENV['TMPDIR']) }
  let(:remote_dir) { Dir.mktmpdir('snapshot-remote',ENV['TMPDIR']) }

  let(:snapshot_store_dir) { Dir.mktmpdir('snapshot-store',ENV['TMPDIR']) }

  let(:database) { Bundler::Audit::Database.new(db_dir) }

  #
  # Runs git against the scratch database.
  #
  def git(*args, chdir: db_dir)
    system(
      'git', *args,
      chdir: chdir,
      exception: true,
      out: File::NULL,
      err: File::NULL
    )
  end

  #
  # Commits the current contents of the scratch database.
  #
  def commit(message)
    git('add','-A')
    git('-c','user.name=Spec','-c','user.email=spec@example.com',
        'commit','--quiet','--allow-empty','-m',message)

    head
  end

  #
  # The current scratch database commit.
  #
  def head
    `git -C #{db_dir.inspect} rev-parse HEAD`.chomp
  end

  #
  # Replaces the database contents with one of the fixture versions.
  #
  def install(version)
    FileUtils.rm_rf(Dir[File.join(db_dir,'gems')])
    FileUtils.cp_r(File.join(vm_root,version,'gems'),db_dir)
  end

  #
  # Runs a complete scan against the scratch database.
  #
  def scan
    Bundler::Audit::Scanner.new(
      bundle,'Gemfile.lock',Bundler::Audit::Database.new(db_dir)
    ).report
  end

  #
  # Runs a complete scan that archives its snapshot in `snapshot_store_dir`.
  #
  def scan_with_store(_commit=nil)
    database = Bundler::Audit::Database.new(
      db_dir,
      store: Bundler::Audit::Snapshot::Store.new(snapshot_store_dir)
    )

    Bundler::Audit::Scanner.new(bundle,'Gemfile.lock',database).report
  end

  before do
    install('v1')
    system('git','init','--quiet','--bare','--template=',remote_dir,
           exception: true, out: File::NULL, err: File::NULL)
    git('init','--quiet','--template=',db_dir)

    # Guard against `git init` silently falling back to an enclosing
    # repository if the scratch directory could not be created.
    toplevel = `git -C #{db_dir.inspect} rev-parse --show-toplevel 2>/dev/null`.chomp
    expect(toplevel).to eq(File.realpath(db_dir))

    git('remote','add','origin',remote_dir)
  end

  after do
    FileUtils.remove_entry(db_dir) if File.directory?(db_dir)
    FileUtils.remove_entry(remote_dir) if File.directory?(remote_dir)
    FileUtils.remove_entry(snapshot_store_dir) if File.directory?(snapshot_store_dir)
  end

  it "binds each report to the version current at scan start" do
    v1 = commit('version one')

    old_report = scan

    install('v2')
    v2 = commit('version two')

    expect(v2).not_to eq(v1)

    new_report = scan

    expect(old_report.database_commit).to eq(v1)
    expect(new_report.database_commit).to eq(v2)
    expect(old_report.database_digest).not_to eq(new_report.database_digest)

    expect(old_report.advisories.map(&:id)).to eq(['CVE-2026-0001'])
    expect(new_report.advisories.map(&:id)).to match_array(
      ['CVE-2026-0001','CVE-2026-0002']
    )

    # The old report still describes version one's file contents, not only
    # its file names: the title of CVE-2026-0001 was edited in version two.
    old_advisory = old_report.advisories.first
    new_advisory = new_report.advisories.find { |a| a.id == 'CVE-2026-0001' }

    expect(old_advisory.title).to eq('Demo vulnerability one')
    expect(new_advisory.title).to eq('Demo vulnerability one (revised)')
  end

  it "finishes a paused scan on its snapshot while an update and a new scan complete" do
    v1 = commit('version one')
    publish = -> { git('push','--quiet','-u','origin','HEAD:master') }
    publish.call

    store = Bundler::Audit::Snapshot::Store.new(snapshot_store_dir)

    started = Queue.new
    resume  = Queue.new
    results = nil
    report  = nil
    error   = nil

    paused_scan = Thread.new do
      scanner = Bundler::Audit::Scanner.new(
        bundle,'Gemfile.lock',
        Bundler::Audit::Database.new(db_dir, store: store)
      )

      scanner.scan do |result|
        started << true
        resume.pop
        results ||= []
        results << result
      end

      report = Bundler::Audit::Report.new(results, snapshot: scanner.snapshot)
    rescue => exception
      error = exception
    end

    # Wait until the paused scan has captured its snapshot and produced
    # its first finding.
    started.pop

    # Now update the database for real and run a second, complete scan.
    install('v2')
    v2 = commit('version two')
    publish.call

    expect(database.update!).to be(true)
    expect(head).to eq(v2)

    fresh_report = scan
    expect(fresh_report.advisories.map(&:id)).to match_array(
      ['CVE-2026-0001','CVE-2026-0002']
    )

    # Remove the paused scan's archived snapshot while it is still running.
    # The scan must not be affected: its advisories live in memory.
    paused_manifest = Dir[File.join(store.snapshots_dir,'*','manifest.json')]
    expect(paused_manifest).not_to be_empty
    store.prune(force: true)
    expect(Dir[File.join(store.snapshots_dir,'*','manifest.json')]).to be_empty

    # Let the paused scan finish; it must only ever see version one.
    resume << true
    paused_scan.join(30)

    expect(error).to be_nil
    expect(paused_scan.alive?).to be(false)
    expect(report).to be_a(Bundler::Audit::Report)

    seen = report.advisories.map(&:id)
    expect(seen).to eq(['CVE-2026-0001'])
    expect(report.advisories.first.title).to eq('Demo vulnerability one')
    expect(report.database_commit).to eq(v1)
    expect(report.database_digest).not_to eq(fresh_report.database_digest)
  end

  it "keeps the old database usable when an update fails outright" do
    v1 = commit('version one')

    # Break the remote so the real `git pull` fails.
    git('remote','set-url','origin',File.join(remote_dir,'missing'))

    expect {
      database.update!
    }.to raise_error(Bundler::Audit::Database::UpdateFailed,
                     /failed to update/)

    expect(database.commit_id).to eq(v1)
    expect(database.update_state).to eq(:none)

    snapshot = database.snapshot
    expect(snapshot.commit).to eq(v1)
    expect(snapshot.advisories.map(&:id)).to eq(['CVE-2026-0001'])

    # A subsequent scan still works and is bound to the old version.
    report = scan
    expect(report.database_commit).to eq(v1)
    expect(report.advisories.map(&:id)).to eq(['CVE-2026-0001'])
  end

  it "recovers an interrupted update without losing the old database" do
    v1 = commit('version one')

    # Put version two into the remote, then leave the local repository as
    # if an update had been killed after fetching but before merging.
    install('v2')
    v2 = commit('version two')
    git('push','--quiet','origin','HEAD:master')
    git('reset','--hard',v1)
    install('v1')

    File.write(File.join(db_dir,'.git',Bundler::Audit::Database::UPDATE_MARKER),
               "from=#{v1}\npid=999999\nto=#{v2}\n")

    expect(database.update_state).to eq(:interrupted)

    snapshot = database.snapshot

    expect(snapshot.commit).to eq(v1)
    expect(snapshot.update_state).to eq(:interrupted)
    expect(snapshot.digest).not_to eq(
      Bundler::Audit::Database.new(db_dir).snapshot_at(v2).digest
    )

    # A later update recovers the interrupted state and cleanly advances
    # to version two.
    expect(database.update!).to be(true)

    expect(File.exist?(File.join(db_dir,'.git',
                                 Bundler::Audit::Database::UPDATE_MARKER))).to be(false)
    expect(database.commit_id).to eq(v2)
    expect(database.snapshot.digest).to eq(
      Bundler::Audit::Database.new(db_dir).snapshot_at(v2).digest
    )
  end

  it "refuses to scan a dirty worktree unless the caller opts in" do
    v1 = commit('version one')

    File.write(File.join(db_dir,'gems','demo-gem','UNCOMMITTED.yml'),
               "---\ngem: demo-gem\ncve: 2026-9999\n")

    expect {
      database.snapshot
    }.to raise_error(Bundler::Audit::Snapshot::DirtyWorktree)

    snapshot = database.snapshot(ignore_dirty: true)

    expect(snapshot.dirty).to be(true)
    expect(snapshot.commit).to eq(v1)
    expect(snapshot.advisories.map(&:id)).to eq(['CVE-2026-0001'])
  end

  it "does not destroy local uncommitted edits when recovering an update marker" do
    v1 = commit('version one')

    File.write(File.join(db_dir,'gems','demo-gem','CVE-2026-0001.yml'),
               "---\ngem: demo-gem\ncve: 2026-0001\ntitle: local edit\n")

    # A marker for a dead update whose HEAD never moved must not cause the
    # user's own dirty files to be discarded.
    File.write(File.join(db_dir,'.git',Bundler::Audit::Database::UPDATE_MARKER),
               "from=#{v1}\npid=999999\n")

    expect(database.update_state).to eq(:interrupted)

    expect {
      database.update!
    }.to raise_error(Bundler::Audit::Database::UpdateFailed,
                     /uncommitted changes/)

    expect(File.read(File.join(db_dir,'gems','demo-gem','CVE-2026-0001.yml'))
            .include?('local edit')).to be(true)
    expect(database.commit_id).to eq(v1)
  end

  it "refuses to update a dirty worktree without touching the old database" do
    v1 = commit('version one')

    File.write(File.join(db_dir,'gems','demo-gem','CVE-2026-0001.yml'),
               "---\ngem: demo-gem\ncve: 2026-0001\ntitle: local edit\n")

    expect {
      database.update!
    }.to raise_error(Bundler::Audit::Database::UpdateFailed,
                     /uncommitted changes/)

    # The old, committed database is still fully usable.
    snapshot = database.snapshot(ignore_dirty: true)
    expect(snapshot.commit).to eq(v1)
    expect(snapshot.advisories.map(&:id)).to eq(['CVE-2026-0001'])
  end

  it "re-verifies a report from the stored snapshot after the advisory was deleted" do
    install('v2')
    v2 = commit('version two')
    scan = scan_with_store(v2)

    store = Bundler::Audit::Snapshot::Store.new(snapshot_store_dir)

    expect(Dir[File.join(store.snapshots_dir,'*')]).not_to be_empty

    # Delete CVE-2026-0002 entirely, so the report cannot be reproduced
    # from the live database any more.
    install('v3')
    commit('remove advisory')

    expect {
      database.snapshot_with_digest(scan.database_digest)
    }.to raise_error(Bundler::Audit::Snapshot::Unavailable)

    # The stored, content-addressed snapshot still verifies the report.
    reloaded = store.load(scan.database_digest)

    expect(reloaded.advisories.map(&:id)).to match_array(
      ['CVE-2026-0001','CVE-2026-0002']
    )
    expect(reloaded.content_digest).to eq(scan.database_digest)
  end

  it "rejects a report whose database version was deleted" do
    v1 = commit('version one')

    snapshot_from_scan = database.snapshot
    ids                = snapshot_from_scan.advisories.map(&:id)

    # Rebuild the repository from only version two, making v1 unreachable.
    install('v2')
    commit('version two')
    FileUtils.rm_rf(File.join(db_dir,'.git'))
    git('init','--quiet','--template=',db_dir)
    git('add','-A')
    git('-c','user.name=Spec','-c','user.email=spec@example.com',
        'commit','--quiet','-m','version two only')

    expect {
      database.snapshot_at(v1)
    }.to raise_error(Bundler::Audit::Snapshot::Unavailable)

    # Re-verifying that report is intentionally impossible.  The already
    # captured snapshot itself is unaffected, because it holds the parsed
    # advisories rather than paths into the mutable database.
    expect(snapshot_from_scan.commit).to eq(v1)
    expect(snapshot_from_scan.advisories.map(&:id)).to eq(ids)
    expect(database.snapshot_at(head).digest).not_to eq(snapshot_from_scan.digest)
  end
end
