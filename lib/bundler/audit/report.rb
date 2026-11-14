require 'bundler/audit/results'
require 'bundler/audit/scan_error'
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

      # The parts of the scan which could not be completed.
      #
      # @return [Array<ScanError>]
      #
      # @since 0.9.4
      attr_reader :errors

      #
      # Initializes the report.
      #
      # @param [#each] results
      #
      def initialize(results=[])
        @version    = VERSION
        @created_at = Time.now

        @results = []
        @insecure_sources = []
        @unpatched_gems = []
        @errors = []

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
      # Records a result or a part of the scan which could not be completed.
      #
      # {ScanError}s are tracked separately from findings so that
      # {#results} continues to contain only concrete findings.
      #
      # @param [InsecureSource, UnpatchedGem, ScanError] result
      #
      # @return [Report]
      #
      # @since 0.8.0
      #
      def <<(result)
        case result
        when Results::InsecureSource
          @results << result
          @insecure_sources << result
        when Results::UnpatchedGem
          @results << result
          @unpatched_gems << result
        when ScanError
          @errors << result
        else
          @results << result
        end

        return self
      end

      #
      # Determines if there were vulnerabilities found.
      #
      # @return [Boolean]
      #
      def vulnerable?
        !@unpatched_gems.empty? || !@insecure_sources.empty?
      end

      #
      # Determines if every check in the scan was completed.
      #
      # A report may be empty because the bundle is secure, or because the
      # advisory database could not be read. Callers must consult this
      # predicate before treating {#vulnerable?} being false as a success.
      #
      # @return [Boolean]
      #
      # @since 0.9.4
      #
      def complete?
        @errors.empty?
      end

      #
      # Determines if any part of the scan could not be completed.
      #
      # @return [Boolean]
      #
      # @since 0.9.4
      #
      def incomplete?
        !complete?
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
        {
          version:    @version,
          created_at: @created_at,
          complete:   complete?,
          results:    @results.map(&:to_h),
          errors:     @errors.map(&:to_h)
        }
      end

    end
  end
end
