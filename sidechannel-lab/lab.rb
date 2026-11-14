# frozen_string_literal: true

require "json"
require "zlib"
require "rack"
require_relative "app"
require_relative "mitigation"

module SidechannelLab
  module Lab
    module_function

    GZIP = "gzip"

    def request(stack, path, params: {}, accept_encoding: GZIP, headers: {})
      req = Rack::MockRequest.new(stack)
      query = Rack::Utils.build_nested_query(params) unless params.empty?
      full = query && !query.empty? ? "#{path}?#{query}" : path
      merged = { "Accept-Encoding" => accept_encoding }.merge(headers)
      env_headers = merged.transform_keys do |name|
        key = name.upcase.tr("-", "_")
        key.start_with?("HTTP_") ? key : "HTTP_#{key}"
      end
      req.get(full, env_headers)
    end

    def body_bytes(response)
      response.body.bytes
    end

    def gunzip(bytes)
      Zlib::GzipReader.new(StringIO.new(bytes.pack("C*"))).read
    end

    def measure(stack, path, **opts)
      response = request(stack, path, **opts)
      raw = body_bytes(response)
      result = {
        path: path,
        encoding: response.headers["content-encoding"] || "identity",
        vary: response.headers["vary"],
        cache_control: response.headers["cache-control"],
        content_length_header: response.headers["content-length"],
        wire_bytes: raw.size,
      }
      if result[:encoding] == "gzip"
        decoded = gunzip(raw)
        result[:decoded_bytes] = decoded.bytesize
        result[:roundtrip_ok] = (decoded.bytesize == (result[:decoded_bytes]))
      else
        result[:decoded_bytes] = raw.size
      end
      result
    end

    # Same-length candidate guesses so any size difference is compression,
    # not input length. prefix = true guesses a token prefix; false a
    # wrong-prefix control of the same length.
    def candidate(prefix, length, prefix_guess)
      if prefix_guess
        SECRET_TOKEN[0, length]
      else
        ("#" * length)
      end
    end

    def deflater_stack(sync: true)
      Rack::Deflater.new(SidechannelLab::App.new, sync: sync)
    end

    def banner(title)
      puts "\n=== #{title} ==="
    end

    def table(rows, cols)
      widths = cols.map { |c| [c.to_s.length, *rows.map { |r| r[c].to_s.length }].max }
      head = cols.zip(widths).map { |c, w| c.to_s.ljust(w) }.join("  ")
      puts head
      puts widths.map { |w| "-" * w }.join("  ")
      rows.each do |r|
        puts cols.zip(widths).map { |c, w| r[c].to_s.ljust(w) }.join("  ")
      end
    end

    def run
      results = {}
      all_rows = []

      # ---- A. Baselines: no reflection, token-only, echo-only ----------
      banner("A. Baselines (Rack::Deflater, sync=true), accept-encoding: gzip")
      baseline = []
      [
        [:token_only, "/token-only", {}],
        [:co_located_wrong_guess, "/reflection", { echo: "#" * 8, repeats: 64 }],
        [:echo_only, "/echo-only", { echo: "#" * 8, repeats: 64 }],
      ].each do |name, path, params|
        r = measure(deflater_stack, path, params: params)
        r[:scenario] = name
        baseline << r
        all_rows << r
      end
      table(baseline, %i[scenario encoding wire_bytes decoded_bytes cache_control])
      results[:baselines] = baseline

      # ---- B. Oracle: prefix guess vs wrong guess, same length ----------
      banner("B. Reflection oracle on /reflection (same-length guesses)")
      oracle = []
      [8, 32].each do |repeats|
        [1, 4, 8, 16].each do |len|
          [[true, "prefix"], [false, "wrong "]].each do |is_prefix, label|
            guess = candidate(nil, len, is_prefix)
            r = measure(deflater_stack, "/reflection",
                        params: { echo: guess, repeats: repeats })
            r[:repeats] = repeats
            r[:guess_len] = len
            r[:guess_kind] = label
            oracle << r
            all_rows << r
          end
        end
      end
      table(oracle, %i[repeats guess_len guess_kind wire_bytes decoded_bytes encoding])
      deltas = []
      oracle.group_by { |r| [r[:repeats], r[:guess_len]] }.each do |(repeats, len), pair|
        wrong = pair.find { |r| r[:guess_kind] == "wrong " }
        right = pair.find { |r| r[:guess_kind] == "prefix" }
        deltas << { repeats: repeats, guess_len: len,
                    wrong_wire: wrong[:wire_bytes], prefix_wire: right[:wire_bytes],
                    delta_wire: wrong[:wire_bytes] - right[:wire_bytes] }
      end
      table(deltas, %i[repeats guess_len wrong_wire prefix_wire delta_wire])
      results[:oracle] = { rows: oracle, deltas: deltas }

      # ---- C. Full-prefix sweep: every prefix length --------------------
      banner("C. Prefix sweep (repeats=16): correct prefix vs same-length wrong")
      sweep = []
      (0..TOKEN_LEN).each do |len|
        guess = len.zero? ? "" : SECRET_TOKEN[0, len]
        wrong_guess = "#" * len
        right = measure(deflater_stack, "/reflection",
                        params: { echo: guess, repeats: 16 })[:wire_bytes]
        wrong = measure(deflater_stack, "/reflection",
                        params: { echo: wrong_guess, repeats: 16 })[:wire_bytes]
        sweep << { prefix_len: len, prefix_wire: right,
                   wrong_wire: wrong, delta_wire: wrong - right }
      end
      table(sweep, %i[prefix_len wrong_wire prefix_wire delta_wire])
      results[:prefix_sweep] = sweep

      # ---- D. Secret/input separation -----------------------------------
      banner("D. Separation padding between secret and reflection (repeats=32)")
      separation = []
      [["fixed", 0], ["fixed", 1024], ["fixed", 4096],
       ["random", 1024], ["random", 4096]].each do |mode, pad|
        [[true, "prefix"], [false, "wrong "]].each do |is_prefix, label|
          guess = candidate(nil, 8, is_prefix)
          r = measure(deflater_stack, "/separate",
                      params: { echo: guess, repeats: 32, mode: mode, pad: pad })
          separation << { mode: mode, pad: pad, guess: label,
                          wire_bytes: r[:wire_bytes] }
        end
      end
      sep_summary = separation.group_by { |r| [r[:mode], r[:pad]] }.map do |(mode, pad), pair|
        wrong = pair.find { |r| r[:guess] == "wrong " }
        right = pair.find { |r| r[:guess] == "prefix" }
        { mode: mode, pad: pad, wrong_wire: wrong[:wire_bytes],
          prefix_wire: right[:wire_bytes],
          delta_wire: wrong[:wire_bytes] - right[:wire_bytes] }
      end
      table(sep_summary, %i[mode pad wrong_wire prefix_wire delta_wire])
      results[:separation] = sep_summary

      # Random padding across repeated requests (deploy-relevant noise check).
      banner("D2. Random 4096-byte padding: wire size over 8 fresh requests")
      noise = 8.times.map do
        measure(deflater_stack, "/separate",
                params: { echo: SECRET_TOKEN[0, 8], repeats: 32,
                          mode: "random", pad: 4096 })[:wire_bytes]
      end
      puts "prefix guess sizes: #{noise.inspect}"
      noise_wrong = 8.times.map do
        measure(deflater_stack, "/separate",
                params: { echo: "#" * 8, repeats: 32,
                          mode: "random", pad: 4096 })[:wire_bytes]
      end
      puts "wrong guess sizes:  #{noise_wrong.inspect}"
      results[:random_padding_samples] = { prefix: noise, wrong: noise_wrong }

      # ---- E. Streaming / chunking --------------------------------------
      banner("E. Chunked bodies on /stream (sync=true vs sync=false)")
      chunks = []
      [1, 2, 8, 32].each do |n|
        [true, false].each do |sync|
          [[true, "prefix"], [false, "wrong "]].each do |is_prefix, label|
            guess = candidate(nil, 8, is_prefix)
            r = measure(deflater_stack(sync: sync), "/stream",
                        params: { echo: guess, repeats: 32, chunks: n })
            chunks << { chunks: n, sync: sync.to_s, guess: label,
                        wire_bytes: r[:wire_bytes], encoding: r[:encoding] }
          end
        end
      end
      table(chunks, %i[chunks sync guess wire_bytes encoding])
      chunk_summary = chunks.group_by { |r| [r[:chunks], r[:sync]] }.map do |(n, sync), pair|
        wrong = pair.find { |r| r[:guess] == "wrong " }
        right = pair.find { |r| r[:guess] == "prefix" }
        { chunks: n, sync: sync, wrong_wire: wrong[:wire_bytes],
          prefix_wire: right[:wire_bytes],
          delta_wire: wrong[:wire_bytes] - right[:wire_bytes] }
      end
      table(chunk_summary, %i[chunks sync wrong_wire prefix_wire delta_wire])
      results[:chunking] = { rows: chunks, summary: chunk_summary }

      # ---- F. Cache / transform headers ---------------------------------
      banner("F. Cache header interactions")
      cache_rows = []
      # F1: no-transform makes Rack::Deflater skip compression outright.
      app_no_transform = Rack::Builder.new do
        use Rack::Deflater
        run lambda { |_env|
          [200, { "content-type" => "text/html",
                  "cache-control" => "private, no-store, no-transform",
                  "last-modified" => FIXED_LAST_MODIFIED },
           [SidechannelLab::Pages.token_only]]
        }
      end
      r = measure(app_no_transform, "/", params: {})
      r[:case] = "no-transform response"
      cache_rows << r

      # F2: normal sensitive response headers after Deflater.
      r = measure(deflater_stack, "/reflection", params: { echo: "x", repeats: 8 })
      r[:case] = "sensitive /reflection"
      cache_rows << r

      # F3: public cacheable asset.
      r = measure(deflater_stack, "/public/app.js")
      r[:case] = "public asset"
      cache_rows << r

      # F4: identity request (attacker cannot force gzip).
      r = measure(deflater_stack, "/reflection",
                  params: { echo: "x", repeats: 8 }, accept_encoding: "identity")
      r[:case] = "accept-encoding identity"
      cache_rows << r

      table(cache_rows, %i[case encoding wire_bytes decoded_bytes vary cache_control])
      results[:cache_headers] = cache_rows

      # ---- G. Mitigation stack verification ------------------------------
      banner("G. SelectiveDeflation stack (sensitive bypass, public compressed)")
      gate_rows = []
      [
        ["/reflection", { echo: "x", repeats: 8 }],
        ["/separate", { echo: "x", repeats: 8, mode: "fixed", pad: 64 }],
        ["/stream", { echo: "x", repeats: 8, chunks: 4 }],
        ["/token-only", {}],
        ["/public/app.js", {}],
      ].each do |path, params|
        r = measure(SidechannelLab.build_stack, path, params: params)
        r[:path] = path
        gate_rows << r
      end
      table(gate_rows, %i[path encoding wire_bytes decoded_bytes cache_control])
      results[:mitigation_gate] = gate_rows

      banner("G2. Marker-based stack (Deflater :if condition)")
      marker_rows = []
      [["/reflection", { echo: "x", repeats: 8 }], ["/public/app.js", {}]].each do |path, params|
        r = measure(SidechannelLab.build_marker_stack, path, params: params)
        r[:path] = path
        marker_rows << r
      end
      table(marker_rows, %i[path encoding wire_bytes decoded_bytes cache_control])
      results[:mitigation_marker] = marker_rows

      # ---- H. Signal strength, noise and gzip window distance -----------
      banner("H1. Amplification: delta vs reflection repeat count (guess len 8)")
      amp = []
      [8, 32, 128, 512].each do |repeats|
        [true, false].each do |sync|
          wrong = measure(deflater_stack(sync: sync), "/reflection",
                          params: { echo: "#" * 8, repeats: repeats })[:wire_bytes]
          right = measure(deflater_stack(sync: sync), "/reflection",
                          params: { echo: SECRET_TOKEN[0, 8], repeats: repeats })[:wire_bytes]
          amp << { repeats: repeats, sync: sync.to_s,
                   wrong_wire: wrong, prefix_wire: right,
                   delta_wire: wrong - right }
        end
      end
      table(amp, %i[repeats sync wrong_wire prefix_wire delta_wire])
      results[:amplification] = amp

      banner("H2. Repeated-sample noise on co-located oracle (repeats=128, 15 samples)")
      n = 15
      prefix_sizes = n.times.map do
        measure(deflater_stack, "/reflection",
                params: { echo: SECRET_TOKEN[0, 8], repeats: 128 })[:wire_bytes]
      end
      wrong_sizes = n.times.map do
        measure(deflater_stack, "/reflection",
                params: { echo: "#" * 8, repeats: 128 })[:wire_bytes]
      end
      stats = lambda do |vals|
        mean = vals.sum / vals.size.to_f
        { min: vals.min, max: vals.max, mean: mean.round(2),
          std: Math.sqrt(vals.sum { |v| (v - mean)**2 } / vals.size).round(2) }
      end
      noise = { prefix: stats.call(prefix_sizes), wrong: stats.call(wrong_sizes),
                prefix_samples: prefix_sizes, wrong_samples: wrong_sizes }
      puts "prefix(#{SECRET_TOKEN[0, 8]}): #{noise[:prefix].inspect}"
      puts "wrong   (########): #{noise[:wrong].inspect}"
      results[:oracle_noise] = noise

      banner("H3. Distance sweep: fixed padding bytes between secret and reflection")
      distance = []
      [0, 512, 4096, 16_384, 32_768].each do |pad|
        wrong = measure(deflater_stack, "/separate",
                        params: { echo: "#" * 8, repeats: 64, mode: "fixed", pad: pad })[:wire_bytes]
        right = measure(deflater_stack, "/separate",
                        params: { echo: SECRET_TOKEN[0, 8], repeats: 64, mode: "fixed", pad: pad })[:wire_bytes]
        distance << { pad_bytes: pad, wrong_wire: wrong,
                      prefix_wire: right, delta_wire: wrong - right }
      end
      table(distance, %i[pad_bytes wrong_wire prefix_wire delta_wire])
      results[:distance_sweep] = distance

      File.write("results/results.json", JSON.pretty_generate(results))
      File.write("results/summary.tsv", TSV.dump(all_rows))
      puts "\nWrote results/results.json and results/summary.tsv"
    end
  end

  module TSV
    def self.dump(rows)
      return "" if rows.empty?
      keys = rows.first.keys
      [keys.join("\t"), *rows.map { |r| keys.map { |k| r[k] }.join("\t") }].join("\n")
    end
  end
end
