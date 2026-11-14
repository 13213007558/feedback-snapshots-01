# frozen_string_literal: true
require_relative 'harness'
require_relative 'corpus'

cases = DiffFuzz::Corpus.structural_cases
puts format('%-26s %-7s | %-34s %-7s %-7s | %-34s %-7s %-7s | %s',
            'id', 'finder', 'legacy', 'trust', 'find', 'new', 'trust', 'find', 'SAME?')
puts '-' * 150
cases.each do |c|
  [false, true].each do |use_finder|
    l, n = DiffFuzz.compare(c.token, payload_override: c.payload_override, use_finder: use_finder)
    same = (l.verdict == n.verdict && l.trusted == n.trusted && l.finder_called == n.finder_called)
    lerr = l.crash? ? "CRASH:#{l.error_class}" : (l.error_class&.sub('JWT::','') || 'ACCEPT')
    nerr = n.crash? ? "CRASH:#{n.error_class}" : (n.error_class&.sub('JWT::','') || 'ACCEPT')
    puts format('%-26s %-7s | %-34s %-7s %-7s | %-34s %-7s %-7s | %s',
                c.id, use_finder, lerr[0,34], l.trusted, l.finder_called,
                nerr[0,34], n.trusted, n.finder_called, same ? '' : '<< DIFF')
  end
end
