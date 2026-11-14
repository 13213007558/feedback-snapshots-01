# frozen_string_literal: true

require_relative 'harness'
require_relative 'corpus'
require_relative 'run_diff'

module DiffFuzz
  class CLI
    def initialize(seeds:, per_seed:, mode:)
      @seeds = seeds
      @per_seed = per_seed
      @mode = mode
      @runner = Runner.new
    end

    def call
      sanity_check!
      cases = build_cases
      $stderr.puts "[info] total cases: #{cases.size} (seeds=#{@seeds.inspect}, per_seed=#{@per_seed})"
      rows = @runner.run(cases)
      print_report(cases, rows)
      rows
    end

    private

    def build_cases
      list = Corpus.structural_cases
      @seeds.each do |seed|
        list.concat(Corpus.mutated_cases(seed: seed, count: @per_seed))
      end
      list
    end

    # Baseline: a valid token must be accepted by both, a tampered one rejected
    # by both. Proves the harness and policy alignment are wired correctly.
    def sanity_check!
      good = Corpus.valid_token
      l, n = DiffFuzz.compare(good)
      unless l.accepted? && n.accepted? && l.trusted && n.trusted
        raise "sanity failed: valid token not accepted by both: #{l.inspect} | #{n.inspect}"
      end

      bad = good.sub(/.$/, good[-1] == 'A' ? 'B' : 'A')
      l, n = DiffFuzz.compare(bad)
      unless l.rejected? && n.rejected?
        raise "sanity failed: tampered token not rejected by both: #{l.inspect} | #{n.inspect}"
      end

      # Finder must be invoked by both when a finder is configured.
      l, n = DiffFuzz.compare(good, use_finder: true)
      unless l.finder_called? && n.finder_called? && l.accepted? && n.accepted?
        raise "sanity failed: key-finder baseline mismatch: #{l.inspect} | #{n.inspect}"
      end

      $stderr.puts '[ok] baseline sanity checks passed (accept/verify, reject/tamper, finder)'
    end

    def print_report(cases, rows)
      groups = rows.group_by(&:kind)
      puts '=' * 78
      puts 'ruby-jwt differential fuzz: JWT.decode (legacy) vs JWT::EncodedToken (new)'
      puts "cases=#{cases.size} divergent=#{rows.size} seeds=#{@seeds.inspect} per_seed=#{@per_seed}"
      puts '=' * 78
      groups.each do |kind, grp|
        puts "\n### #{kind} (#{grp.size})"
        grp.sort_by { |r| r.case_meta.category }.each { |r| print_row(r) }
      end
    end

    def print_row(row)
      c, l, n = row.case_meta, row.legacy, row.new_api
      puts "- [#{c.category}] id=#{c.id} seed=#{c.seed.inspect} finder=#{c.use_finder}"
      puts "    token=#{c.token.inspect}"
      puts "    override=#{c.payload_override.inspect}"
      puts "    legacy: #{fmt(l)}"
      puts "    new   : #{fmt(n)}"
    end

    def fmt(o)
      base = "#{o.verdict} trusted=#{o.trusted} finder=#{o.finder_called}"
      o.error_class ? "#{base} #{o.error_class}(#{o.error_message.inspect})" : base
    end
  end
end

if __FILE__ == $PROGRAM_NAME
  seeds    = (ENV['SEEDS'] || '1,2,3').split(',').map(&:to_i)
  per_seed = (ENV['PER_SEED'] || '150').to_i
  mode     = ENV['MODE'] || 'fuzz'
  DiffFuzz::CLI.new(seeds: seeds, per_seed: per_seed, mode: mode).call
end
