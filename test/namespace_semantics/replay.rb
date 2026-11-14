# frozen_string_literal: true

require_relative "runner"

module REXMLTests
  module NamespaceSemantics
    # Standalone command line:
    #
    #   ruby -Ilib:test test/namespace_semantics/replay.rb --seed 7 --cases 16
    #   ruby -Ilib:test test/namespace_semantics/replay.rb --file failing.xml
    #
    # The first form generates with a fixed seed, checks every projection,
    # shrinks each first divergence, and prints a self-contained replay
    # command for it.  The second form checks one document and prints the
    # record-level diff.
    module CLI
      module_function

      def run(argv)
        options = parse(argv)
        case
        when options[:file]
          replay_file(options[:file], options)
        else
          replay_seed(options)
        end
      end

      def parse(argv)
        options = {
          seed: 1234,
          cases: 8,
          apis: APIS,
          shrink: true,
          output_dir: Dir.pwd,
          only: nil,
        }
        until argv.empty?
          argument = argv.shift
          case argument
          when "--seed" then options[:seed] = Integer(argv.shift)
          when "--cases" then options[:cases] = Integer(argv.shift)
          when "--api" then options[:apis] = [argv.shift.to_sym]
          when "--only"
            only = argv.shift.to_sym
            abort "--only must be name or value" unless [:name, :value].include?(only)
            options[:only] = only
          when "--file" then options[:file] = argv.shift
          when "--no-shrink" then options[:shrink] = false
          when "--output-dir" then options[:output_dir] = argv.shift
          when "--help", "-h"
            puts usage
            exit
          else
            abort "unknown option: #{argument}\n\n#{usage}"
          end
        end
        options
      end

      def usage
        <<~USAGE
          Usage: ruby -Ilib:test test/namespace_semantics/replay.rb [options]

            --seed N     generator seed (default 1234)
            --cases N    number of generated documents (default 8)
            --api NAME   restrict to dom, pull, or sax
            --only KIND  restrict to name or value divergences
            --file PATH  replay one XML file instead of generating
            --no-shrink  report without minimizing the failing document
            --output-dir DIR  where minimized cases are written (default: cwd)
        USAGE
      end

      def replay_seed(options)
        generator = Generator.new(options[:seed])
        failures = 0
        options[:cases].times do |index|
          document = generator.document(index)
          xml = document.to_xml
          divergences = Checker.divergences(xml, apis: options[:apis], only: options[:only])
          next if divergences.empty?

          failures += 1
          puts divergences.map(&:describe).join("\n\n")
          if options[:shrink]
            minimized = Shrinker.shrink(xml, apis: options[:apis])
            path = File.join(options[:output_dir], "minimized-#{options[:seed]}-#{index}.xml")
            File.write(path, minimized)
            puts "\n  minimized: #{minimized}"
            puts "  wrote:     #{path}"
            puts "  replay:    ruby -Ilib:test test/namespace_semantics/replay.rb --file #{path}"
          end
          puts
        end
        puts "cases: #{options[:cases]}, diverging: #{failures}"
        return failures.zero?
      end

      def replay_file(path, options)
        xml = File.read(path)
        divergences = Checker.divergences(xml, apis: options[:apis], only: options[:only])
        if divergences.empty?
          puts "no divergence: every projection matches the namespace oracle"
          return true
        end

        puts divergences.map(&:describe).join("\n\n")
        false
      end
    end
  end
end

if $PROGRAM_NAME == __FILE__
  exit(REXMLTests::NamespaceSemantics::CLI.run(ARGV) ? 0 : 1)
end
