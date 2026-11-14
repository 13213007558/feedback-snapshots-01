# frozen_string_literal: true

# Demonstrates a transformer that sanitizes embedded content by calling back
# into the same Sanitize instance, and shows that the nested call can't leak
# its node, allowlist, or trust decisions into the outer call.
#
# Run with:
#
#   bundle exec ruby -Ilib examples/reentrant_transformer.rb

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "sanitize"

class EmbeddedContentTransformer
  attr_accessor :sanitizer

  def initialize
    @depth = 0
    @events = []
  end

  attr_reader :events

  def call(env)
    node = env[:node]

    if @depth.positive?
      # Inner pass: pretend the embedded content has already been approved by
      # a trusted subsystem, so trust every node it contains.
      @events << [:inner, env[:node_name], node.name]
      return {node_allowlist: [node]}
    end

    return unless env[:node_name] == "div"
    return unless node.element? && !node.key?("data-embedded")

    node["data-embedded"] = "1"
    outer_node = node
    outer_name = env[:node_name]
    outer_allowlisted = env[:is_allowlisted]
    outer_allowlist = env[:node_allowlist]

    @depth += 1
    begin
      # Sanitize the embedded content with the same instance.
      sanitizer.node!(node)
    ensure
      @depth -= 1
    end

    # After the nested call, the outer call's context must be exactly what it
    # was before. Not just the outer transformer's own `env` (it owns that),
    # but also the context Sanitize exposes to extensions.
    unless sanitizer.current_node.equal?(outer_node)
      raise "current node was not restored to the outer node"
    end
    unless sanitizer.current_node_name == outer_name
      raise "current node name was not restored (#{sanitizer.current_node_name.inspect})"
    end
    unless sanitizer.current_env[:is_allowlisted] == outer_allowlisted
      raise "outer allowlist status changed"
    end
    unless sanitizer.current_env[:node_allowlist].equal?(outer_allowlist)
      raise "outer allowlist was replaced"
    end
    unless env[:node_allowlist].equal?(outer_allowlist)
      raise "the outer env's allowlist was replaced"
    end

    # Deliberately trust the outer node only if the outer call itself considers
    # it trusted. The inner pass allowlisted everything; that must not carry
    # over.
    trusted_by_outer = env[:node_allowlist].include?(node)
    @events << [:outer_after_nested, sanitizer.current_node_name, trusted_by_outer]

    {node_allowlist: [node]} if trusted_by_outer
  end
end

transformer = EmbeddedContentTransformer.new

# A second transformer that runs after the first one for every node. It
# records the node it's asked to inspect and the node Sanitize says is current,
# so we can see whether a nested call left stale context behind.
observed = []

observer = lambda do |env|
  next unless %w[div span].include?(env[:node_name])

  current = transformer.sanitizer.current_node
  observed << [env[:node_name], env[:node].name, current&.name, current.equal?(env[:node])]
end

outer = Sanitize.new(
  elements: ["div"],
  attributes: {"div" => ["data-embedded"]},
  transformers: [transformer, observer]
)
transformer.sanitizer = outer

html = <<~HTML
  <div>
    safe text
    <script>alert("script")</script>
    <img src="x" onerror="alert('img')">
    <span>span</span>
  </div>
HTML

result = outer.fragment(html)

puts "input:  #{html.strip.inspect}"
puts "output: #{result.inspect}"
puts
puts "events:"
transformer.events.each { |event| puts "  #{event.inspect}" }
puts
puts "later transformer observations (node_name, node, current_node, same_object):"
observed.each { |event| puts "  #{event.inspect}" }
puts

# Every observation made by the later transformer must show the node it was
# actually handed, even directly after the nested call.
unless observed.all? { |_, _, _, same| same }
  raise "a later transformer saw a stale current node: #{observed.inspect}"
end

# The nested pass allowlisted <script>, <img>, and <span>, but the outer config
# allows only <div>, so they're removed anyway (script and img contents are
# discarded; span's text is kept because it's safe).
expected = %(<div data-embedded="1">\n  safe text\n  \n  \n  span\n</div>\n)

unless result == expected
  raise "unexpected output:\n  expected: #{expected.inspect}\n  actual:   #{result.inspect}"
end

%w[<script <img <span].each do |tag|
  raise "dangerous markup survived: #{tag}" if result.downcase.include?(tag)
end

puts "OK: later transformers saw the correct outer node, and the inner allowlist did not escape the outer sanitization."
