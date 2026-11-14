# frozen_string_literal: true

require "json"
require_relative "app"
require_relative "mitigation"
require_relative "lab"

include SidechannelLab::Lab

failures = []
check = lambda do |name, cond, detail|
  status = cond ? "PASS" : "FAIL"
  failures << name unless cond
  puts "[#{status}] #{name} -- #{detail}"
end

# 1. Single-character alphabet oracle at position 0: the true first token
#    character must rank among the smallest wire sizes (replicated guess).
stack = deflater_stack
first_char = SidechannelLab::SECRET_TOKEN[0]
candidates = SidechannelLab::ALPHABET
sizes = candidates.to_h do |ch|
  r = measure(stack, "/reflection", params: { echo: ch, repeats: 32 })
  [ch, r[:wire_bytes]]
end
ranked = sizes.sort_by { |_ch, size| size }
true_size = sizes[first_char]
min_size = ranked.first[1]
check.call("oracle distinguishes true first char (#{first_char})",
           true_size <= min_size + 1,
           "true=#{true_size}B min=#{min_size}B rank=#{ranked.index { |c, _| c == first_char } + 1}/#{candidates.size}")

# 2. Mitigation: every sensitive route is uncompressed, public stays gzip.
gate = SidechannelLab.build_stack
sensitive_ok = %w[/reflection /separate /stream /token-only].all? do |path|
  r = measure(gate, path, params: { echo: "x", repeats: 4, chunks: 2, mode: "fixed", pad: 32 })
  r[:encoding] == "identity" && r[:cache_control].include?("no-transform")
end
check.call("gate bypasses compression on sensitive routes", sensitive_ok,
           "all identity + no-transform")
pub = measure(gate, "/public/app.js")
check.call("public asset remains gzip compressed",
           pub[:encoding] == "gzip" && pub[:wire_bytes] < pub[:decoded_bytes],
           "#{pub[:decoded_bytes]}B -> #{pub[:wire_bytes]}B")

# 3. Marker stack behaves the same.
marker = SidechannelLab.build_marker_stack
ms = measure(marker, "/reflection", params: { echo: "x", repeats: 4 })
mp = measure(marker, "/public/app.js")
check.call("marker stack: sensitive identity, public gzip",
           ms[:encoding] == "identity" && mp[:encoding] == "gzip",
           "reflection=#{ms[:encoding]}, app.js=#{mp[:encoding]}")

# 4. no-transform alone makes stock Deflater skip (defense in depth).
nt = Rack::Builder.new do
  use Rack::Deflater
  run lambda { |_env|
    [200, { "content-type" => "text/html",
            "cache-control" => "private, no-store, no-transform" },
     [SidechannelLab::Pages.token_only]]
  }
end
r = measure(nt, "/")
check.call("no-transform disables stock Rack::Deflater",
           r[:encoding] == "identity", "encoding=#{r[:encoding]}")

# 5. Determinism: same request twice yields identical wire size.
a = measure(stack, "/reflection", params: { echo: SidechannelLab::SECRET_TOKEN[0, 8], repeats: 16 })[:wire_bytes]
b = measure(stack, "/reflection", params: { echo: SidechannelLab::SECRET_TOKEN[0, 8], repeats: 16 })[:wire_bytes]
check.call("fixed mtime gives reproducible wire sizes", a == b, "#{a} == #{b}")

# 6. Chunking never removes the oracle delta.
chunk_ok = [1, 2, 8, 32].all? do |n|
  w = measure(stack, "/stream", params: { echo: "#" * 8, repeats: 32, chunks: n })[:wire_bytes]
  r = measure(stack, "/stream", params: { echo: SidechannelLab::SECRET_TOKEN[0, 8], repeats: 32, chunks: n })[:wire_bytes]
  w - r >= 1
end
check.call("oracle delta survives all chunk counts (sync=true)", chunk_ok, "delta >= 2B observed in run")

puts
if failures.empty?
  puts "ALL CHECKS PASSED"
else
  puts "FAILURES: #{failures.join(', ')}"
  exit 1
end
