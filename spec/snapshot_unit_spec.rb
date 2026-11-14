require 'spec_helper'
require 'bundler/audit/snapshot'
require 'bundler/audit/database'
require 'bundler/audit/report'

describe Bundler::Audit::Snapshot do
  let(:advisory) do
    Bundler::Audit::Advisory.new(
      '/db/gems/demo-gem/CVE-2026-0001.yml',
      'CVE-2026-0001', 'https://example.com/', 'Demo', Date.new(2026,1,1),
      'desc', 4.0, nil, nil, '2026-0001', nil, nil,
      [], [Gem::Requirement.new('>= 2.0.0')]
    )
  end

  let(:other_advisory) do
    Bundler::Audit::Advisory.new(
      '/db/gems/other-gem/CVE-2026-0002.yml',
      'CVE-2026-0002', 'https://example.com/', 'Other', Date.new(2026,1,1),
      'desc', 4.0, nil, nil, '2026-0002', nil, nil,
      [], []
    )
  end

  subject do
    described_class.new(
      database_path: '/db', commit: 'abc123',
      last_updated_at: Time.at(0).utc, digest: 'deadbeef',
      advisories: [advisory,other_advisory]
    )
  end

  it "#content_digest prefixes the algorithm" do
    expect(subject.content_digest).to eq('sha256:deadbeef')
  end

  it "#size counts advisories" do
    expect(subject.size).to eq(2)
  end

  it "#[] looks up an advisory by ID" do
    expect(subject['CVE-2026-0001']).to be(advisory)
    expect(subject['CVE-9999-0000']).to be(nil)
  end

  it "#advisories_for groups by gem directory" do
    expect(subject.advisories_for('demo-gem')).to eq([advisory])
    expect(subject.advisories_for('nope')).to eq([])
  end

  it "#check_gem yields only vulnerable advisories" do
    gem = Gem::Specification.new do |spec|
      spec.name    = 'demo-gem'
      spec.version = '1.0.0'
    end

    expect(subject.check_gem(gem).map(&:id)).to eq(['CVE-2026-0001'])
  end

  it "#to_h exposes the version and content digest" do
    expect(subject.to_h).to include(
      source: :git,
      commit: 'abc123',
      digest: 'sha256:deadbeef',
      advisories: 2,
      update_state: :none,
      dirty: false
    )
  end

  it "is frozen and sorted" do
    expect(subject.advisories).to be_frozen
    expect(subject.advisories.map(&:path)).to eq(
      ['/db/gems/demo-gem/CVE-2026-0001.yml','/db/gems/other-gem/CVE-2026-0002.yml']
    )
  end

  it "decides whether it is a git snapshot" do
    expect(subject.git?).to be(true)

    plain = described_class.new(
      database_path: '/db', commit: nil, last_updated_at: nil,
      digest: 'deadbeef', advisories: []
    )

    expect(plain.git?).to be(false)
    expect(plain.to_h[:source]).to eq(:directory)
  end
end

describe Bundler::Audit::Report do
  let(:snapshot) do
    Bundler::Audit::Snapshot.new(
      database_path: '/db', commit: 'abc123', last_updated_at: nil,
      digest: 'deadbeef', advisories: []
    )
  end

  it "exposes database metadata when built with a snapshot" do
    report = described_class.new([], snapshot: snapshot)

    expect(report.database_commit).to eq('abc123')
    expect(report.database_digest).to eq('sha256:deadbeef')
    expect(report.database).to include(commit: 'abc123')
    expect(report.to_h[:database]).to include(digest: 'sha256:deadbeef')
  end

  it "omits database metadata when no snapshot ran" do
    report = described_class.new

    expect(report.database).to be(nil)
    expect(report.database_commit).to be(nil)
    expect(report.to_h).not_to have_key(:database)
  end

  it "accepts the snapshot after construction" do
    report = described_class.new
    report.snapshot = snapshot

    expect(report.to_h[:database]).to include(commit: 'abc123')
  end
end
