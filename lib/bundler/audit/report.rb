require 'bundler/audit/results'
require 'bundler/audit/snapshot'
require 'bundler/audit/version'

require 'time'

module Bundler
  module Audit
    #
    # Represents the result of a scan.
    #
    class Report

      include Enumerable

      # The version of `bundler-audit` which created the report object.
      #
      # @return [String]
      attr_reader :version

      # The time when the report was generated.
      #
      # @return [Time]
      attr_reader :created_at

      # The database snapshot all results were read from.
      #
      # @return [Snapshot, nil]
      attr_accessor :snapshot

      # The database metadata stored in the report.
      #
      # @return [Hash{Symbol => Object}, nil]
      #
      def database
        @snapshot && @snapshot.to_h
      end

      # The advisory database commit, if the database was a git repository.
      #
      # @return [String, nil]
      #
      def database_commit
        @snapshot && @snapshot.commit
      end

      # The digest of the exact advisory contents used by the scan.
      #
      # @return [String, nil]
      #
      def database_digest
        @snapshot && @snapshot.content_digest
      end

      # The list of all results.
      #
      # @return [Array<Results::Result>]
      attr_reader :results

      # The insecure sources results.
      #
      # @return [Array<Results::InsecureSources>]
      attr_reader :insecure_sources

      # The unpatched gems results.
      #
      # @return [Array<Results::UnpatchedGems>]
      attr_reader :unpatched_gems

      #
      # Initializes the report.
      #
      # @param [#each] results
      #
      def initialize(results=[], snapshot: nil)
        @version    = VERSION
        @created_at = Time.now
        @snapshot   = snapshot

        @results = []
        @insecure_sources = []
        @unpatched_gems = []

        results.each { |result| self << result }
      end

      #
      # Enumerates over the results.
      #
      # @yield [result]
      #
      # @yieldparam [Results::InsecureSource, Results::UnpatchedGem] result
      #
      # @return [Enumerator]
      #
      def each(&block)
        @results.each(&block)
      end

      #
      # Appends a result to the report.
      #
      # @param [InsecureSource, UnpatchedGem] result
      #
      def <<(result)
        @results << result

        case result
        when Results::InsecureSource
          @insecure_sources << result
        when Results::UnpatchedGem
          @unpatched_gems << result
        end

        return self
      end

      #
      # Determines if there were vulnerabilities found.
      #
      # @return [Boolean]
      #
      def vulnerable?
        !@results.empty?
      end

      #
      # @yield [advisory]
      #
      # @yieldparam [Advisory] advisory
      #
      # @return [Enumerator]
      #
      def each_advisory
        return enum_for(__method__) unless block_given?

        @unpatched_gems.each { |result| yield result.advisory }
      end

      #
      # @return [Array<Advisory>]
      #
      def advisories
        @unpatched_gems.map(&:advisory)
      end

      #
      # @yield [gem]
      #
      # @yieldparam [Gem::Specification]
      #
      # @return [Enumerator]
      #
      def each_vulnerable_gem
        return enum_for(__method__) unless block_given?

        @unpatched_gems.each { |result| yield result.gem }
      end

      #
      # @return [Array<Gem::Specification>]
      #
      def vulnerable_gems
        @unpatched_gems.map(&:gem)
      end

      #
      # @return [Hash{Symbol => Object}]
      #
      def to_h
        hash = {
          version:    @version,
          created_at: @created_at,
          results:    @results.map(&:to_h)
        }

        hash[:database] = database if @snapshot

        return hash
      end

    end
  end
end
