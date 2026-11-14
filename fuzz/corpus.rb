# frozen_string_literal: true

require_relative 'harness'

module DiffFuzz
  # A single fuzz case.
  #   token            -> compact-serialized string handed to both APIs
  #   payload_override -> when set, the new API gets it via encoded_payload=
  #                       (detached-payload workflow; legacy has no equivalent)
  #   use_finder       -> drive both APIs through their key-finder callback
  #   category / seed  -> replay metadata
  Case = Struct.new(:id, :category, :token, :payload_override, :use_finder, :seed,
                    keyword_init: true)

  module Corpus
    module_function

    def encode_header(hash_or_raw, raw: false)
      raw ? hash_or_raw : DiffFuzz.b64u(::JSON.generate(hash_or_raw))
    end

    # A correctly signed HS256 token used as the common seed.
    def valid_token(payload = { 'a' => 1, 'nbf' => 0 }, alg: 'HS256', header_extra: {})
      h = header_extra.merge('alg' => alg)
      hseg = DiffFuzz.b64u(::JSON.generate(h))
      pseg = DiffFuzz.b64u(::JSON.generate(payload))
      signing_input = "#{hseg}.#{pseg}"
      sig = OpenSSL::HMAC.digest('SHA256', DiffFuzz::GOOD_SECRET, signing_input)
      sseg = DiffFuzz.b64u(sig)
      "#{signing_input}.#{sseg}"
    end

    # Deterministic PRNG (ruby's Random, seeded) so runs are replayable.
    def prng(seed) = Random.new(seed)

    # Hand-built structural edge cases. Each is deterministic.
    def structural_cases
      cases = []
      add = ->(id, category, token, **extra) { cases << Case.new(id: id, category: category, token: token, **extra) }

      h = DiffFuzz.b64u('{"alg":"HS256"}')
      p = DiffFuzz.b64u('{"a":1}')
      s = DiffFuzz.b64u('sig')

      # --- Segment count ---
      add.call('seg-3',        'segment_count', "#{h}.#{p}.#{s}")
      add.call('seg-2',        'segment_count', "#{h}.#{p}")
      add.call('seg-1',        'segment_count', h)
      add.call('seg-4',        'segment_count', "#{h}.#{p}.#{s}.extra")
      add.call('seg-5',        'segment_count', "#{h}.#{p}.#{s}.x.y")
      add.call('seg-0-empty',  'segment_count', '')
      add.call('seg-leadingdot','segment_count', ".#{p}.#{s}")
      add.call('seg-trailingdot','segment_count', "#{h}.#{p}.")
      add.call('seg-2dots',    'segment_count', "#{h}..#{s}")
      add.call('seg-3dots',    'segment_count', "#{h}...")

      # --- Base64url boundaries (header / payload / signature) ---
      add.call('b64-pad-header',  'base64url', "#{DiffFuzz.b64u('{"alg":"HS256"}')}===.#{p}.#{s}")
      add.call('b64-plus-header', 'base64url', "eyJhbGciOiJIUzI1NiJ9==.#{p}.#{s}")
      add.call('b64-slash',       'base64url', "#{h.gsub('-', '+')}.#{p}.#{s}")
      add.call('b64-underscore',  'base64url', "#{h.gsub('_', '/')}.#{p}.#{s}")
      add.call('b64-space',       'base64url', "#{h} .#{p}.#{s}")
      add.call('b64-nullbyte',    'base64url', "#{h}\x00.#{p}.#{s}")
      add.call('b64-unicode',     'base64url', "#{h}é.#{p}.#{s}")
      add.call('b64-truncated',   'base64url', "#{h[0..-2]}.#{p}.#{s}")
      add.call('b64-empty-header','base64url', ".#{p}.#{s}")
      add.call('b64-empty-payload','base64url', "#{h}..#{s}")
      add.call('b64-empty-sig',   'base64url', "#{h}.#{p}.")
      add.call('b64-bad-payload', 'base64url', "#{h}.!!!notb64!!!.#{s}")
      add.call('b64-bad-sig',     'base64url', "#{h}.#{p}.@@@@")
      add.call('b64-pad-payload', 'base64url', "#{h}.#{p}=.#{s}")
      add.call('b64-valid-json-raw-bad-b64', 'base64url', "#{h}.#{DiffFuzz.b64u('x')}.#{s}")

      # --- Duplicate JSON members ---
      dup_header = DiffFuzz.b64u('{"alg":"none","alg":"HS256"}')
      add.call('dup-alg-header', 'duplicate_json', "#{dup_header}.#{p}.#{s}")
      dup_header2 = DiffFuzz.b64u('{"alg":"HS256","alg":"none"}')
      add.call('dup-alg-reverse', 'duplicate_json', "#{dup_header2}.#{p}.#{s}")
      dup_payload = DiffFuzz.b64u('{"a":1,"a":2}')
      add.call('dup-payload', 'duplicate_json', "#{h}.#{dup_payload}.#{s}")
      dup_b64 = DiffFuzz.b64u('{"b64":true,"b64":false,"alg":"HS256"}')
      add.call('dup-b64-header', 'duplicate_json', "#{dup_b64}.#{p}.#{s}")

      # --- Non-object headers ---
      ['[]', '"astring"', '123', 'null', 'true', '{}', '[1,2]'].each_with_index do |raw, i|
        add.call("nonobj-header-#{i}", 'non_object_header',
                 "#{DiffFuzz.b64u(raw)}.#{p}.#{s}")
      end
      # Header that decodes to valid JSON but nested/non-hash, plus malformed JSON
      add.call('nonobj-malformed-json', 'non_object_header',
               "#{DiffFuzz.b64u('{not json}')}.#{p}.#{s}")
      add.call('nonobj-empty-json', 'non_object_header',
               "#{DiffFuzz.b64u('')}.#{p}.#{s}")

      # --- Detached payload (RFC 7797 style, b64:false) and empty payload ---
      dh = DiffFuzz.b64u('{"alg":"HS256","b64":false,"crit":["b64"]}')
      detached_signing = "#{dh}.#{p}"
      dsig = DiffFuzz.b64u(OpenSSL::HMAC.digest('SHA256', DiffFuzz::GOOD_SECRET, detached_signing))
      add.call('detached-b64-empty-sig-seg', 'detached_payload',
               "#{dh}.", payload_override: p)
      add.call('detached-signed-empty-payload', 'detached_payload',
               "#{dh}.#{dsig}", payload_override: p)
      # b64:false but no detached re-attachment (payload segment empty)
      add.call('detached-no-reattach', 'detached_payload', "#{dh}.#{dsig}")
      # b64 header present but crit missing
      dh2 = DiffFuzz.b64u('{"alg":"HS256","b64":false}')
      add.call('detached-b64-no-crit', 'detached_payload', "#{dh2}.#{p}.#{s}")

      cases
    end

    # Seeded random mutators derived from a valid base token.
    def mutated_cases(seed:, count: 200)
      rng = prng(seed)
      base = valid_token
      cases = []
      count.times do |i|
        token, category = mutate(base, rng)
        use_finder = rng.rand < 0.5
        cases << Case.new(id: "rnd-#{seed}-#{i}", category: category,
                          token: token, use_finder: use_finder, seed: seed)
      end
      cases
    end

    def mutate(token, rng)
      segments = token.split('.', -1)
      choice = rng.rand(7)
      case choice
      when 0
        # segment count mutation
        n = rng.rand(0..5)
        grown = Array.new(n) { |i| segments[i] || DiffFuzz.b64u(rand_json(rng)) }
        [grown.join('.'), 'segment_count']
      when 1
        # base64 char mutation on a random segment
        seg_idx = rng.rand(segments.length)
        chars = ['=', '+', '/', ' ', "\x00", '_', '-', '@', '!', "ÿ", '']
        copy = segments.dup
        pos = rng.rand([copy[seg_idx].length, 1].max)
        c = chars.sample(random: rng)
        copy[seg_idx] = copy[seg_idx].dup.insert(pos, c)
        [copy.join('.'), 'base64url']
      when 2
        # flip/duplicate JSON member
        seg_idx = [0, 1].sample(random: rng)
        raw = begin
                ::JSON.parse(DiffFuzz.b64u_dec(segments[seg_idx]))
              rescue StandardError
                {}
              end
        key = %w[alg a b64 crit].sample(random: rng)
        val = ['HS256', 'none', nil, true, false, [], {}].sample(random: rng)
        raw2 = raw.merge(key => val)
        json = ::JSON.generate(raw2).sub("\"#{key}\":", "\"#{key}\":\"X\",\"#{key}\":")
        copy = segments.dup
        copy[seg_idx] = DiffFuzz.b64u(json)
        [copy.join('.'), 'duplicate_json']
      when 3
        # non-object header
        nonobj = ['[]', 'null', '123', '"s"', 'true', ''].sample(random: rng)
        copy = segments.dup
        copy[0] = DiffFuzz.b64u(nonobj)
        [copy.join('.'), 'non_object_header']
      when 4
        # empty out a segment (detached / empty payload / empty sig)
        seg_idx = rng.rand(segments.length)
        copy = segments.dup
        copy[seg_idx] = ''
        [copy.join('.'), 'detached_payload']
      when 5
        # random byte splice / truncation
        seg_idx = rng.rand(segments.length)
        copy = segments.dup
        s = copy[seg_idx]
        s = s[0, rng.rand(0..s.length)] if s.length.positive?
        copy[seg_idx] = s + (rng.rand(2).zero? ? DiffFuzz.b64u(rand_json(rng)) : '')
        [copy.join('.'), 'base64url']
      else
        # alg header tamper
        algs = ['none', 'HS256', 'RS256', '', 'HS512', nil]
        h = { 'alg' => algs.sample(random: rng) }
        copy = segments.dup
        copy[0] = DiffFuzz.b64u(::JSON.generate(h))
        [copy.join('.'), 'non_object_header']
      end
    end

    def rand_json(rng)
      ::JSON.generate({ 'k' => rng.rand(100), 'alg' => %w[HS256 none].sample(random: rng) })
    end
  end
end
