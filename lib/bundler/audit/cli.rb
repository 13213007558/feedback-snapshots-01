#
# Copyright (c) 2013-2026 Hal Brodigan (postmodern.mod3 at gmail.com)
#
# bundler-audit is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# bundler-audit is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with bundler-audit.  If not, see <https://www.gnu.org/licenses/>.
#

require 'bundler/audit/scanner'
require 'bundler/audit/diff'
require 'bundler/audit/version'
require 'bundler/audit/cli/formats'

require 'thor'
require 'bundler/audit/cli/thor_ext/shell/basic/say_error'
require 'bundler'
require 'json'

module Bundler
  module Audit
    #
    # The `bundle-audit` command.
    #
    class CLI < ::Thor

      default_task :check
      map '--version' => :version

      desc 'check [DIR]', 'Checks the Gemfile.lock for insecure dependencies'
      method_option :quiet, type: :boolean, aliases: '-q'
      method_option :verbose, type: :boolean, aliases: '-v'
      method_option :ignore, type: :array, aliases: '-i'
      method_option :update, type: :boolean, aliases: '-u'
      method_option :database, type: :string, aliases: '-D',
                               default: Database::DEFAULT_PATH
      method_option :format, type: :string, default: 'text', aliases: '-F'
      method_option :config, type: :string, aliases: '-c', default: '.bundler-audit.yml'
      method_option :gemfile_lock, type: :string, aliases: '-G',
                                   default: 'Gemfile.lock'
      method_option :output, type: :string, aliases: '-o'

      def check(dir=Dir.pwd)
        unless File.directory?(dir)
          say_error "No such file or directory: #{dir}", :red
          exit 1
        end

        begin
          extend Formats.load(options[:format])
        rescue Formats::FormatNotFound
          say_error "Unknown format: #{options[:format]}", :red
          exit 1
        end

        if !Database.exists?(options[:database])
          download(options[:database])
        elsif options[:update]
          update(options[:database])
        end

        database = Database.new(options[:database])
        scanner  = begin
                     Scanner.new(dir,options[:gemfile_lock],database,options[:config])
                   rescue Bundler::GemfileLockNotFound => exception
                     say exception.message, :red
                     exit 1
                   end

        report = scanner.report(ignore: options.ignore)

        output = if options[:output]
                   File.new(options[:output],'w')
                 else
                   $stdout
                 end

        print_report(report,output)

        output.close if options[:output]

        exit(1) if report.vulnerable?
      end

      desc 'stats', 'Prints ruby-advisory-db stats'
      method_option :quiet, type: :boolean, aliases: '-q'

      def stats(path=Database::DEFAULT_PATH)
        database = Database.new(path)

        puts "ruby-advisory-db:"
        puts "  advisories:\t#{database.size} advisories"
        puts "  last updated:\t#{database.last_updated_at}"

        if (commit_id = database.commit_id)
          puts "  commit:\t#{commit_id}"
        end
      end

      desc 'diff BEFORE_DIR AFTER_DIR', 'Explains the differences between two scans'
      method_option :gemfile_lock, type: :string, aliases: '-G',
                                   default: 'Gemfile.lock'
      method_option :database, type: :string, aliases: '-D'
      method_option :database_before, type: :string
      method_option :database_after, type: :string
      method_option :config, type: :string, aliases: '-c',
                              default: '.bundler-audit.yml'
      method_option :format, type: :string, default: 'text', aliases: '-F'
      method_option :output, type: :string, aliases: '-o'

      def diff(before_dir,after_dir)
        [before_dir, after_dir].each do |dir|
          unless File.directory?(dir)
            say_error "No such file or directory: #{dir}", :red
            exit 1
          end
        end

        database_before = Database.new(options[:database_before] ||
                                       options[:database] ||
                                       Database::DEFAULT_PATH)
        database_after  = Database.new(options[:database_after] ||
                                       options[:database] ||
                                       Database::DEFAULT_PATH)

        begin
          before = Diff::Snapshot.capture(before_dir,
                                          gemfile_lock: options[:gemfile_lock],
                                          database: database_before,
                                          config_dot_file: options[:config])
          after  = Diff::Snapshot.capture(after_dir,
                                          gemfile_lock: options[:gemfile_lock],
                                          database: database_after,
                                          config_dot_file: options[:config])
        rescue Bundler::GemfileLockNotFound => exception
          say_error exception.message, :red
          exit 1
        end

        diff = Diff.compare(before,after)

        output = if options[:output]
                   File.new(options[:output],'w')
                 else
                   $stdout
                 end

        case options[:format]
        when 'json'
          output.puts JSON.pretty_generate(diff.to_h)
        when 'text'
          print_diff(diff,output)
        else
          say_error "Unknown format: #{options[:format]}", :red
          exit 1
        end

        output.close if options[:output]

        exit(1) if diff.regressions?
      end

      desc 'download', 'Downloads ruby-advisory-db'
      method_option :quiet, type: :boolean, aliases: '-q'

      def download(path=Database::DEFAULT_PATH)
        if Database.exists?(path)
          say "Database already exists", :yellow
          return
        end

        say("Download ruby-advisory-db ...") unless options.quiet?

        begin
          Database.download(path: path, quiet: options.quiet?)
        rescue Database::DownloadFailed => error
          say error.message, :red
          exit 1
        end

        stats(path) unless options.quiet?
      end

      desc 'update', 'Updates the ruby-advisory-db'
      method_option :quiet, type: :boolean, aliases: '-q'

      def update(path=Database::DEFAULT_PATH)
        unless Database.exists?(path)
          download(path)
          return
        end

        say("Updating ruby-advisory-db ...") unless options.quiet?

        database = Database.new(path)

        begin
          case database.update!(quiet: options.quiet?)
          when true
            say("Updated ruby-advisory-db", :green) unless options.quiet?
          when nil
            if Bundler.git_present?
              unless options.quiet?
                say "Skipping update, ruby-advisory-db is not a git repository", :yellow
              end
            else
              say_error "Git is not installed!", :red
              exit 1
            end
          end
        rescue Database::UpdateFailed => error
          say error.message, :red
          exit 1
        end

        stats(path) unless options.quiet?
      end

      desc 'version', 'Prints the bundler-audit version'
      def version
        puts "bundler-audit #{VERSION}"
      end

      protected

      #
      # @note Silence deprecation warnings from Thor.
      #
      def self.exit_on_failure?
        true
      end

      #
      # @abstract
      #
      def print_report(report)
        raise(NotImplementedError,"#{self.class}##{__method__} not defined")
      end

      #
      # Prints a report diff in plain text.
      #
      # @param [Diff] diff
      #
      # @param [IO] output
      #
      def print_diff(diff,output=$stdout)
        output.puts "Report diff"
        output.puts "==========="
        print_snapshot('Before',diff.before,output)
        print_snapshot('After',diff.after,output)
        output.puts

        if diff.entries.empty?
          output.puts "No differences."
          return
        end

        diff.entries.each do |entry|
          print_diff_entry(entry,output)
        end

        output.puts "Summary"
        output.puts "-------"

        Diff::CLASSIFICATIONS.each do |classification|
          count = diff.summary[classification]

          output.puts "  #{classification}: #{count}" if count
        end
      end

      #
      # Prints the identities bound to one snapshot.
      #
      # @param [String] label
      #
      # @param [Diff::Snapshot] snapshot
      #
      # @param [IO] output
      #
      def print_snapshot(label,snapshot,output)
        output.puts "#{label}: #{snapshot.root}"
        output.puts "  lockfile: #{snapshot.lockfile_path} (sha256: #{snapshot.lockfile_sha256})"

        database_id = if snapshot.database_commit_id
                        "commit: #{snapshot.database_commit_id}"
                      else
                        "sha256: #{snapshot.database_sha256}"
                      end

        output.puts "  database: #{snapshot.database.path} (#{database_id})"

        if snapshot.config_path
          output.puts "  config:   #{snapshot.config_path} (sha256: #{snapshot.config_sha256})"
        else
          output.puts "  config:   none"
        end
      end

      #
      # Prints one diff entry with its causal evidence and closure
      # conditions.
      #
      # @param [Diff::Entry] entry
      #
      # @param [IO] output
      #
      def print_diff_entry(entry,output)
        finding = entry.finding

        subject = case finding.type
                  when :unpatched_gem
                    "#{finding.gem_name} #{finding.gem_version} (#{finding.gem_platform}) - #{finding.advisory_id}"
                  when :insecure_source
                    "insecure source #{finding.source}"
                  end

        output.puts
        output.puts "[#{entry.classification.to_s.upcase}] #{subject}"
        output.puts "  Direction: #{entry.direction}"

        entry.evidence.each do |key,value|
          output.puts "  #{key}: #{format_value(value)}"
        end

        if (closure = entry.closure)
          upgrade_to = closure[:upgrade_to]

          unless upgrade_to[:patched_versions].empty?
            output.puts "  Close by upgrading to: #{upgrade_to[:patched_versions].join(', ')}"
          end

          unless upgrade_to[:unaffected_versions].empty?
            output.puts "  Close by downgrading to unaffected: #{upgrade_to[:unaffected_versions].join(', ')}"
          end

          output.puts "  Or suppress by ignoring: #{closure[:suppress_with].join(', ')}"
        end
      end

      #
      # Formats an evidence value for text output.
      #
      # @param [Object] value
      #
      # @return [String]
      #
      def format_value(value)
        case value
        when Array then value.empty? ? 'none' : value.join(', ')
        when nil   then 'none'
        else value.to_s
        end
      end

    end
  end
end
