require 'bundler/audit/scanner'
require 'bundler/audit/version'

require 'digest'
require 'set'

module Bundler
  module Audit
    #
    # Structurally compares two scan snapshots and explains why findings
    # appeared or disappeared between them. Each snapshot binds the identity
    # of the lockfile, the advisory database and the ignore configuration
    # that produced it, so every difference can be attributed to a concrete
    # cause instead of a textual diff of report output.
    #
    # @since 0.9.1
    #
    class Diff

      # Classifications for appeared findings.
      APPEARED = %i[
        new_dependency
        newly_disclosed
        advisory_revised
        exemption_expired
      ].freeze

      # All classifications, including `fixed` and `unexplained`.
      CLASSIFICATIONS = (APPEARED + %i[fixed unexplained]).freeze

      #
      # One side of the comparison: a scan plus the identities of the
      # inputs that produced it.
      #
      class Snapshot

        # The scanned project root.
        #
        # @return [String]
        attr_reader :root

        # The path of the scanned lockfile.
        #
        # @return [String]
        attr_reader :lockfile_path

        # The SHA-256 digest of the lockfile contents.
        #
        # @return [String]
        attr_reader :lockfile_sha256

        # The advisory database used for the scan.
        #
        # @return [Database]
        attr_reader :database

        # The git commit of the advisory database, if it is a git clone.
        #
        # @return [String, nil]
        attr_reader :database_commit_id

        # The SHA-256 digest over all advisory files in the database.
        #
        # @return [String]
        attr_reader :database_sha256

        # The path of the ignore configuration file, if present.
        #
        # @return [String, nil]
        attr_reader :config_path

        # The SHA-256 digest of the ignore configuration, if present.
        #
        # @return [String, nil]
        attr_reader :config_sha256

        # The locked gems, keyed by `[name, platform]`.
        #
        # @return [Hash{Array => Gem::Specification}]
        attr_reader :specs

        # The advisory identifiers ignored by the configuration.
        #
        # @return [Set<String>]
        attr_reader :ignore

        # The normalized findings of the scan.
        #
        # @return [Array<Finding>]
        attr_reader :findings

        #
        # Scans a project and captures the snapshot.
        #
        # @param [String] root
        #   The project root directory.
        #
        # @param [String] gemfile_lock
        #   The lockfile name within `root`.
        #
        # @param [Database] database
        #   The advisory database to scan against.
        #
        # @param [String] config_dot_file
        #   The ignore configuration file name within `root`.
        #
        # @return [Snapshot]
        #
        def self.capture(root,gemfile_lock: 'Gemfile.lock',
                              database: Database.new,
                              config_dot_file: '.bundler-audit.yml')
          scanner = Scanner.new(root,gemfile_lock,database,config_dot_file)
          new(scanner,gemfile_lock,config_dot_file)
        end

        #
        # Initializes the snapshot from a scanner.
        #
        # @param [Scanner] scanner
        #
        # @param [String] gemfile_lock
        #
        # @param [String] config_dot_file
        #
        # @api semipublic
        #
        def initialize(scanner,gemfile_lock,config_dot_file)
          @root           = scanner.root
          @lockfile_path  = File.join(@root,gemfile_lock)
          @lockfile_sha256 = ::Digest::SHA256.file(@lockfile_path).hexdigest

          @database           = scanner.database
          @database_commit_id = @database.commit_id
          @database_sha256    = self.class.digest_advisories(@database.path)

          config_path = File.absolute_path(config_dot_file,@root)

          if File.file?(config_path)
            @config_path   = config_path
            @config_sha256 = ::Digest::SHA256.file(config_path).hexdigest
          end

          @specs = {}

          scanner.lockfile.specs.each do |spec|
            @specs[[spec.name,spec.platform.to_s]] = spec
          end

          @ignore   = scanner.config.ignore
          @findings = scanner.report.map { |result| Finding.new(result) }
        end

        #
        # Computes a digest over all advisory files of a database, so that
        # databases which are not git clones still have a stable identity.
        #
        # @param [String] path
        #   The database path.
        #
        # @return [String]
        #
        def self.digest_advisories(path)
          digest = ::Digest::SHA256.new

          Dir.glob(File.join(path,'gems','*','*.yml')).sort.each do |file|
            digest.update(File.basename(File.dirname(file)))
            digest.update(File.basename(file))
            digest.update(File.read(file))
          end

          digest.hexdigest
        end

        #
        # Looks up the locked spec for a gem.
        #
        # @param [String] name
        #
        # @param [String] platform
        #
        # @return [Gem::Specification, nil]
        #
        def spec(name,platform)
          @specs[[name,platform]]
        end

        #
        # Finds an advisory in the snapshot's database matching any of the
        # given identifiers (CVE/GHSA/OSVDB or the advisory ID itself), so
        # that renumbered advisories still correspond to each other.
        #
        # @param [String] gem_name
        #
        # @param [Set<String>] identity
        #
        # @return [Advisory, nil]
        #
        def find_advisory(gem_name,identity)
          @database.advisories_for(gem_name).find do |advisory|
            identity.intersect?(Finding.identity_of(advisory))
          end
        end

        #
        # Determines whether the configuration ignores any of the given
        # identifiers.
        #
        # @param [Set<String>] identity
        #
        # @return [Boolean]
        #
        def ignores?(identity)
          @ignore.intersect?(identity)
        end

        #
        # @return [Hash{Symbol => Object}]
        #
        def to_h
          {
            root: @root,
            lockfile: {
              path:   @lockfile_path,
              sha256: @lockfile_sha256
            },
            database: {
              path:      @database.path,
              commit_id: @database_commit_id,
              sha256:    @database_sha256
            },
            config: {
              path:   @config_path,
              sha256: @config_sha256
            },
            findings: @findings.map(&:to_h)
          }
        end

      end

      #
      # A normalized, comparable scan finding.
      #
      class Finding

        # @return [:unpatched_gem, :insecure_source]
        attr_reader :type

        # @return [String, nil]
        attr_reader :gem_name

        # @return [Gem::Version, nil]
        attr_reader :gem_version

        # @return [String, nil]
        attr_reader :gem_platform

        # @return [String, nil]
        attr_reader :source

        # @return [String, nil]
        attr_reader :advisory_id

        # @return [Advisory, nil]
        attr_reader :advisory

        #
        # @param [Results::UnpatchedGem, Results::InsecureSource] result
        #
        def initialize(result)
          case result
          when Results::UnpatchedGem
            @type             = :unpatched_gem
            @gem_name         = result.gem.name
            @gem_version      = result.gem.version
            @gem_platform     = result.gem.platform.to_s
            @advisory         = result.advisory
            @advisory_id      = result.advisory.id
          when Results::InsecureSource
            @type   = :insecure_source
            @source = result.source.to_s
          else
            raise(ArgumentError,"unsupported result: #{result.inspect}")
          end
        end

        #
        # All identifiers naming the advisory of a finding.
        #
        # @param [Advisory] advisory
        #
        # @return [Set<String>]
        #
        def self.identity_of(advisory)
          Set[advisory.id, *advisory.identifiers]
        end

        #
        # The identity of the finding's advisory, stable across renumbering
        # (CVE/GHSA aliases) and title changes.
        #
        # @return [Set<String>]
        #
        def identity
          self.class.identity_of(@advisory)
        end

        #
        # Determines whether another finding refers to the same issue, even
        # if the advisory was renumbered or retitled.
        #
        # @param [Finding] other
        #
        # @return [Boolean]
        #
        def matches?(other)
          return false unless @type == other.type

          case @type
          when :unpatched_gem
            @gem_name     == other.gem_name &&
            @gem_platform == other.gem_platform &&
            identity.intersect?(other.identity)
          when :insecure_source
            @source == other.source
          end
        end

        #
        # @return [Hash{Symbol => Object}]
        #
        def to_h
          case @type
          when :unpatched_gem
            {
              type: @type,
              gem: {
                name:     @gem_name,
                version:  @gem_version.to_s,
                platform: @gem_platform
              },
              advisory: {
                id:           @advisory_id,
                identifiers:  @advisory.identifiers,
                url:          @advisory.url,
                title:        @advisory.title,
                criticality:  @advisory.criticality,
                patched_versions:    @advisory.patched_versions.map(&:to_s),
                unaffected_versions: @advisory.unaffected_versions.map(&:to_s)
              }
            }
          when :insecure_source
            {
              type:   @type,
              source: @source
            }
          end
        end

      end

      #
      # A single explained (or explicitly unexplained) difference.
      #
      class Entry

        # @return [Symbol]
        attr_reader :classification

        # The finding that appeared or disappeared.
        #
        # @return [Finding]
        attr_reader :finding

        # Whether the finding appeared (`:appeared`) or disappeared
        # (`:disappeared`).
        #
        # @return [Symbol]
        attr_reader :direction

        # The causal evidence supporting the classification.
        #
        # @return [Hash{Symbol => Object}]
        attr_reader :evidence

        # The conditions under which the alert would be closed.
        #
        # @return [Hash{Symbol => Object}, nil]
        attr_reader :closure

        def initialize(classification,direction,finding,evidence,closure=nil)
          @classification = classification
          @direction      = direction
          @finding        = finding
          @evidence       = evidence
          @closure        = closure
        end

        #
        # @return [Hash{Symbol => Object}]
        #
        def to_h
          {
            classification: @classification,
            direction:      @direction,
            finding:        @finding.to_h,
            evidence:       @evidence,
            closure:        @closure
          }
        end

      end

      # The snapshot of the earlier scan.
      #
      # @return [Snapshot]
      attr_reader :before

      # The snapshot of the later scan.
      #
      # @return [Snapshot]
      attr_reader :after

      # The explained differences.
      #
      # @return [Array<Entry>]
      attr_reader :entries

      #
      # Compares two snapshots.
      #
      # @param [Snapshot] before
      #
      # @param [Snapshot] after
      #
      # @return [Diff]
      #
      def self.compare(before,after)
        entries = []
        matched = []

        after.findings.each do |after_finding|
          before_finding = before.findings.find do |finding|
            !matched.include?(finding) && finding.matches?(after_finding)
          end

          if before_finding
            matched << before_finding
          else
            entries << classify_appearance(after_finding,before,after)
          end
        end

        (before.findings - matched).each do |before_finding|
          entries << classify_disappearance(before_finding,before,after)
        end

        new(before,after,entries)
      end

      #
      # Initializes the diff.
      #
      def initialize(before,after,entries)
        @before  = before
        @after   = after
        @entries = entries
      end

      #
      # The entries of one classification.
      #
      # @param [Symbol] classification
      #
      # @return [Array<Entry>]
      #
      def [](classification)
        @entries.select { |entry| entry.classification == classification }
      end

      #
      # Determines whether any finding appeared.
      #
      # @return [Boolean]
      #
      def regressions?
        @entries.any? { |entry| entry.direction == :appeared }
      end

      #
      # Counts of entries per classification.
      #
      # @return [Hash{Symbol => Integer}]
      #
      def summary
        counts = Hash.new(0)
        @entries.each { |entry| counts[entry.classification] += 1 }
        counts
      end

      #
      # @return [Hash{Symbol => Object}]
      #
      def to_h
        {
          version: VERSION,
          before:  @before.to_h,
          after:   @after.to_h,
          summary: summary,
          entries: @entries.map(&:to_h)
        }
      end

      #
      # Classifies a finding that only exists in the after snapshot.
      #
      # @param [Finding] finding
      #
      # @param [Snapshot] before
      #
      # @param [Snapshot] after
      #
      # @return [Entry]
      #
      def self.classify_appearance(finding,before,after)
        if finding.type == :insecure_source
          return Entry.new(:new_dependency,:appeared,finding,{
            cause: 'insecure gem source added to the lockfile'
          })
        end

        before_spec = before.spec(finding.gem_name,finding.gem_platform)
        advisory    = finding.advisory
        closure     = closure_for(advisory)

        if before_spec.nil?
          return Entry.new(:new_dependency,:appeared,finding,{
            cause: 'gem was not present in the before lockfile',
            before_version: nil,
            after_version:  finding.gem_version.to_s
          },closure)
        end

        unless advisory.vulnerable?(before_spec.version)
          return Entry.new(:new_dependency,:appeared,finding,{
            cause: 'the locked version change exposed the gem to the advisory',
            before_version: before_spec.version.to_s,
            after_version:  finding.gem_version.to_s
          },closure)
        end

        before_advisory = before.find_advisory(finding.gem_name,finding.identity)

        if before_advisory.nil?
          return Entry.new(:newly_disclosed,:appeared,finding,{
            cause: 'advisory is absent from the before database; the locked version was already vulnerable',
            version: finding.gem_version.to_s,
            database_before_sha256: before.database_sha256,
            database_after_sha256:  after.database_sha256
          },closure)
        end

        unless before_advisory.vulnerable?(before_spec.version)
          return Entry.new(:advisory_revised,:appeared,finding,{
            cause: 'the advisory existed before but its affected version ranges were revised to cover the locked version',
            version: finding.gem_version.to_s,
            before_patched_versions:    before_advisory.patched_versions.map(&:to_s),
            after_patched_versions:     advisory.patched_versions.map(&:to_s),
            before_unaffected_versions: before_advisory.unaffected_versions.map(&:to_s),
            after_unaffected_versions:  advisory.unaffected_versions.map(&:to_s)
          },closure)
        end

        if before.ignores?(finding.identity) && !after.ignores?(finding.identity)
          return Entry.new(:exemption_expired,:appeared,finding,{
            cause: 'the advisory was ignored by the before configuration but is no longer ignored',
            version: finding.gem_version.to_s,
            ignored_in_before: true,
            ignored_in_after:  false,
            config_before_sha256: before.config_sha256,
            config_after_sha256:  after.config_sha256
          },closure)
        end

        Entry.new(:unexplained,:appeared,finding,{
          cause: 'the before database already flagged the locked version and the advisory was not ignored; the before scan should have reported it',
          version: finding.gem_version.to_s,
          ignored_in_before: before.ignores?(finding.identity)
        },closure)
      end

      #
      # Classifies a finding that only exists in the before snapshot.
      #
      # @param [Finding] finding
      #
      # @param [Snapshot] before
      #
      # @param [Snapshot] after
      #
      # @return [Entry]
      #
      def self.classify_disappearance(finding,before,after)
        if finding.type == :insecure_source
          return Entry.new(:fixed,:disappeared,finding,{
            cause: 'insecure gem source removed from the lockfile'
          })
        end

        after_spec = after.spec(finding.gem_name,finding.gem_platform)

        if after_spec.nil?
          return Entry.new(:fixed,:disappeared,finding,{
            cause: 'gem was removed from the lockfile',
            before_version: finding.gem_version.to_s,
            after_version:  nil
          })
        end

        after_advisory = after.find_advisory(finding.gem_name,finding.identity)

        if after_advisory && !after_advisory.vulnerable?(after_spec.version)
          return Entry.new(:fixed,:disappeared,finding,{
            cause: 'the locked version is patched or unaffected according to the after database',
            before_version: finding.gem_version.to_s,
            after_version:  after_spec.version.to_s,
            patched_versions:    after_advisory.patched_versions.map(&:to_s),
            unaffected_versions: after_advisory.unaffected_versions.map(&:to_s)
          })
        end

        Entry.new(:unexplained,:disappeared,finding,{
          cause: if after_advisory.nil?
                   'the advisory is absent from the after database; the fix cannot be confirmed'
                 else
                   'the locked version is still vulnerable according to the after database'
                 end,
          before_version: finding.gem_version.to_s,
          after_version:  after_spec.version.to_s,
          advisory_absent_in_after_database: after_advisory.nil?,
          ignored_in_after: after.ignores?(finding.identity)
        })
      end

      #
      # The conditions under which an alert on the advisory would close.
      #
      # @param [Advisory] advisory
      #
      # @return [Hash{Symbol => Object}]
      #
      def self.closure_for(advisory)
        {
          upgrade_to: {
            patched_versions:    advisory.patched_versions.map(&:to_s),
            unaffected_versions: advisory.unaffected_versions.map(&:to_s)
          },
          suppress_with: advisory.identifiers
        }
      end

    end
  end
end
