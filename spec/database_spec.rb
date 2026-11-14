require 'spec_helper'
require 'bundler/audit/database'
require 'tmpdir'

describe Bundler::Audit::Database do
  let(:vendored_advisories) do
    Dir[File.join(Fixtures::Database::PATH, 'gems/*/*.yml')].sort
  end

  describe ".path" do
    subject { described_class.path }

    it "it should be a directory" do
      expect(described_class.path).to be_truthy
    end
  end

  describe ".exists?" do
    subject { described_class }

    context "when the directory does not exist" do
      let(:path) { '/does/not/exist' }

      it { expect(subject.exists?(path)).to be(false) }
    end

    context "when the directory does exist" do
      context "but is empty" do
        let(:path) { Fixtures.join('empty_dir') }

        before { FileUtils.mkdir(path) }

        it { expect(subject.exists?(path)).to be(false) }

        after { FileUtils.rmdir(path) }
      end

      context "and there are files within the directory" do
        let(:path) { Fixtures.join('not_empty_dir') }

        before do
          FileUtils.mkdir(path)
          FileUtils.touch(File.join(path,'file.txt'))
        end

        it { expect(subject.exists?(path)).to be(true) }

        after { FileUtils.rm_r(path) }
      end
    end
  end

  describe ".download" do
    subject { described_class }

    let(:url)  { described_class::URL          }
    let(:path) { described_class::DEFAULT_PATH }

    it "should execute `git clone` with URL and DEFAULT_PATH" do
      expect(subject).to receive(:system).with('git', 'clone', url, path).and_return(true)
      expect(subject).to receive(:new)

      subject.download
    end

    context "with :path" do
      let(:url)  { described_class::URL          }
      let(:path) { Fixtures.join('new-database') }

      it "should execute `git clone` with the given output path" do
        expect(subject).to receive(:system).with('git', 'clone', url, path).and_return(true)
        expect(subject).to receive(:new)

        subject.download(path: path)
      end
    end

    context "with :quiet" do
      it "should execute `git clone` with the `--quiet` option" do
        expect(subject).to receive(:system).with('git', 'clone', '--quiet', url, path).and_return(true)
        expect(subject).to receive(:new)

        subject.download(quiet: true)
      end
    end

    context "when the command fails" do
      it do
        expect(subject).to receive(:system).with('git', 'clone', url, path).and_return(false)

        expect {
          subject.download
        }.to raise_error(described_class::DownloadFailed)
      end
    end

    context "with an unknown option" do
      it do
        expect {
          subject.download(foo: true)
        }.to raise_error(ArgumentError)
      end
    end
  end

  describe ".update!" do
    subject { described_class }

    context "when :path does not yet exist" do
      let(:dest_dir) { Fixtures.join('new-ruby-advisory-db') }

      before { stub_const("#{described_class}::DEFAULT_PATH",dest_dir) }

      let(:url)  { described_class::URL          }
      let(:path) { described_class::DEFAULT_PATH }

      it "should execute `git clone` and call .new" do
        expect(subject).to receive(:system).with('git', 'clone', url, path).and_return(true)
        expect(subject).to receive(:new)

        subject.update!(quiet: false)
      end

      context "when the `git clone` fails" do
        before { stub_const("#{described_class}::URL",'https://example.com/') }

        it do
          expect(subject).to receive(:system).with('git', 'clone', url, path).and_return(false)

          expect(subject.update!(quiet: false)).to eq(false)
        end
      end

      after { FileUtils.rm_rf(dest_dir) }
    end

    context "when :path already exists" do
      let(:dest_dir) { Dir.mktmpdir('existing-ruby-advisory-db',ENV['TMPDIR']) }

      before do
        FileUtils.cp_r(
          Dir[File.join(Fixtures::Database::PATH,'gems')],
          dest_dir
        )
        FileUtils.cp(
          File.join(Fixtures::Database::PATH,'Gemfile.lock'),
          dest_dir
        )
        system('git','init','--quiet','--template=',dest_dir)

        # Guard against `git init` silently falling back to an enclosing
        # repository if the scratch directory could not be created.
        expect(File.directory?(File.join(dest_dir,'.git'))).to be(true)
        system('git','-C',dest_dir,'add','.')
        system('git','-C',dest_dir,
               '-c','user.name=Spec','-c','user.email=spec@example.com',
               'commit','--quiet','-m','fixture')
        system('git','-C',dest_dir,'remote','add','origin',Fixtures::Database::PATH)
        system('git','-C',dest_dir,'fetch','--quiet','origin','master')
        system('git','-C',dest_dir,'reset','--hard','FETCH_HEAD')
      end
      before { stub_const("#{described_class}::DEFAULT_PATH",dest_dir) }

      it "should execute `git pull`" do
        expect_any_instance_of(subject).to receive(:system).with('git', 'pull', 'origin', 'master', chdir: dest_dir).and_return(true)

        subject.update!(quiet: false)
      end

      after { FileUtils.rm_rf(dest_dir) }

      context "when the `git pull` fails" do
        it do
          expect_any_instance_of(subject).to receive(:system).with('git', 'pull', 'origin', 'master', chdir: dest_dir).and_return(false)

          expect(subject.update!(quiet: false)).to eq(false)
        end
      end
    end

    context "when given an invalid option" do
      it do
        expect { subject.update!(foo: 1) }.to raise_error(RuntimeError)
      end
    end
  end

  describe "#initialize" do
    context "when given no arguments" do
      subject { described_class.new }

      it "should default path to path" do
        expect(subject.path).to eq(described_class.path)
      end
    end

    context "when given a directory" do
      let(:path) { Dir.tmpdir }

      subject { described_class.new(path) }

      it "should set #path" do
        expect(subject.path).to eq(path)
      end
    end

    context "when given an invalid directory" do
      it "should raise an ArgumentError" do
        expect {
          described_class.new('/foo/bar/baz')
        }.to raise_error(ArgumentError)
      end
    end
  end

  describe "#git?" do
    subject { described_class.new(path) }

    context "when a '.git' directory exists within the database" do
      let(:path) { Fixtures.join('mock-git-database') }

      before do
        FileUtils.mkdir(path)
        FileUtils.mkdir(File.join(path,'.git'))
      end

      it { expect(subject.git?).to be(true) }

      after { FileUtils.rm_rf(path) }
    end

    context "when no '.git' directory exists within the database" do
      let(:path) { Fixtures.join('mock-bare-database') }

      before do
        FileUtils.mkdir(path)
      end

      it { expect(subject.git?).to be(false) }

      after { FileUtils.rm_rf(path) }
    end
  end

  describe "#update!" do
    context "when the database is a git repository" do
      it do
        expect(subject).to receive(:system).with('git', 'pull', 'origin', 'master', chdir: subject.path).and_return(true)

        subject.update!
      end

      context "when the :quiet option is given" do
        it do
          expect(subject).to receive(:system).with('git', 'pull', '--quiet', 'origin', 'master', chdir: subject.path).and_return(true)

          subject.update!(quiet: true)
        end
      end

      context "when the `git pull` command fails" do
        it do
          expect(subject).to receive(:system).with('git', 'pull', 'origin', 'master', chdir: subject.path).and_return(false)

          expect {
            subject.update!
          }.to raise_error(described_class::UpdateFailed)
        end
      end
    end

    context "when the database is a bare directory" do
      let(:path) { Fixtures.join('mock-bare-database') }

      before { FileUtils.mkdir(path) }

      subject { described_class.new(path) }

      it do
        expect(subject.update!).to be(nil)
      end

      after { FileUtils.rmdir(path) }
    end
  end

  describe "#commit_id" do
    context "when the database is a git repository" do
      let(:last_commit) { Fixtures::Database::COMMIT }

      it "should return the last commit ID" do
        expect(subject.commit_id).to be == last_commit
      end
    end

    context "when the database is a bare directory" do
      let(:path) { Fixtures.join('mock-database-dir') }

      before { FileUtils.mkdir(path) }

      subject { described_class.new(path) }

      it "should return the mtime of the directory" do
        expect(subject.commit_id).to be(nil)
      end

      after { FileUtils.rmdir(path) }
    end
  end

  describe "#last_updated_at" do
    context "when the database is a git repository" do
      let(:last_commit) { Fixtures::Database::COMMIT }
      let(:last_commit_timestamp) do
        Dir.chdir(Fixtures::Database::PATH) do
          Time.parse(`git log -n 2 --date=iso8601 --pretty="%cd" #{last_commit}`)
        end
      end

      it "should return the timestamp of the last commit" do
        expect(subject.last_updated_at).to be == last_commit_timestamp
      end
    end

    context "when the database is a bare directory" do
      let(:path) { Fixtures.join('mock-database-dir') }

      before { FileUtils.mkdir(path) }

      subject { described_class.new(path) }

      it "should return the mtime of the directory" do
        expect(subject.last_updated_at).to be == File.mtime(path)
      end

      after { FileUtils.rmdir(path) }
    end
  end

  describe "#advisories" do
    subject { super().advisories }

    it "should return a list of all advisories." do
      expect(subject.map(&:path)).to match_array(vendored_advisories)
    end
  end

  describe "#advisories_for" do
    let(:gem) { 'activesupport' }
    let(:vendored_advisories_for) do
      Dir[File.join(Fixtures::Database::PATH, "gems/#{gem}/*.yml")].sort
    end

    subject { super().advisories_for(gem) }

    it "should return a list of all advisories." do
      expect(subject.map(&:path)).to match_array(vendored_advisories_for)
    end
  end

  describe "#check_gem" do
    let(:gem) do
      Gem::Specification.new do |s|
        s.name    = 'actionpack'
        s.version = '3.1.9'
      end
    end

    context "when given a block" do
      it "should yield every advisory effecting the gem" do
        advisories = []

        subject.check_gem(gem) do |advisory|
          advisories << advisory
        end

        expect(advisories).not_to be_empty
        expect(advisories.all? { |advisory|
          advisory.kind_of?(Bundler::Audit::Advisory)
        }).to be_truthy
      end
    end

    context "when given no block" do
      it "should return an Enumerator" do
        expect(subject.check_gem(gem)).to be_kind_of(Enumerable)
      end
    end
  end

  describe "#size" do
    it { expect(subject.size).to eq vendored_advisories.count }
  end

  describe "#to_s" do
    it "should return the Database path" do
      expect(subject.to_s).to eq(subject.path)
    end
  end

  describe "#inspect" do
    it "should produce a Ruby-ish instance descriptor" do
      expect(subject.inspect).to eq("#<#{described_class}:#{subject.path}>")
    end
  end
end
