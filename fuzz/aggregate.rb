# frozen_string_literal: true
require_relative 'harness'
require_relative 'corpus'
require_relative 'run_diff'

runner = DiffFuzz::Runner.new
tally = Hash.new(0)
examples = {}
all_cases = DiffFuzz::Corpus.structural_cases
[false, true].each do |uf|
  all_cases.each do |c|
    l, n = DiffFuzz.compare(c.token, payload_override: c.payload_override, use_finder: uf)
    next unless runner.divergent?(l, n)
    key = [c.category, l.error_class&.sub('JWT::',''), n.error_class&.sub('JWT::',''),
           l.finder_called, n.finder_called, l.verdict, n.verdict]
    tally[key] += 1
    examples[key] ||= c.id
  end
end
puts format('%-18s %-22s %-22s %-6s %-5s %-7s %-7s %4s %s',
            'category','legacy_err','new_err','lfind','nfind','lver','nver','n','example')
tally.sort_by { |k, _| k[0] }.each do |k, cnt|
  cat, le, ne, lf, nf, lv, nv = k
  puts format('%-18s %-22s %-22s %-6s %-5s %-7s %-7s %4d %s',
              cat, le || '-', ne || '-', lf, nf, lv, nv, cnt, examples[k])
end
