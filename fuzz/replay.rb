# frozen_string_literal: true

# Replay one or more deterministic structural cases by id, or a seeded random
# case by "seed:index". Prints the token and both APIs' full outcomes.
require_relative 'harness'
require_relative 'corpus'
require_relative 'run_diff'

runner = DiffFuzz::Runner.new
args = ARGV.dup
use_finder = args.delete('--finder') { false }
args.each do |arg|
  c = if arg.include?(':')
        seed, idx = arg.split(':').map(&:to_i)
        DiffFuzz::Corpus.mutated_cases(seed: seed, count: idx + 1).last
      else
        DiffFuzz::Corpus.structural_cases.find { |x| x.id == arg }
      end
  unless c
    puts "unknown case: #{arg}"
    next
  end
  l, n = DiffFuzz.compare(c.token, payload_override: c.payload_override,
                                    use_finder: use_finder || c.use_finder)
  puts "id=#{c.id} category=#{c.category} seed=#{c.seed.inspect} finder=#{use_finder || c.use_finder}"
  puts "  token   = #{c.token.inspect}"
  puts "  override= #{c.payload_override.inspect}"
  puts "  legacy  : #{l.verdict} trusted=#{l.trusted} finder=#{l.finder_called} #{l.error_class} #{l.error_message.inspect}#{' CRASH' if l.crash}"
  puts "  new     : #{n.verdict} trusted=#{n.trusted} finder=#{n.finder_called} #{n.error_class} #{n.error_message.inspect}#{' CRASH' if n.crash}"
  puts "  divergent=#{runner.divergent?(l, n)} kind=#{runner.classify(c, l, n)}"
end
