# frozen_string_literal: true

require "cgi/escape"
require "helper"

# Property tests for the URI sanitization pipeline, which runs three steps back
# to back: character-reference decoding, control-character stripping, and
# protocol recognition. The expected result for every generated input comes from
# ReferenceUri below - an independent model written from the WHATWG / HTML5 /
# RFC 3986 rules. It deliberately does not reference Loofah's regexes or
# constants, so a shared mistake in the subject's patterns cannot also hide in
# the expectation.
class Html5TestUriGenerationProperties < Loofah::TestCase
  # ---------------------------------------------------------------------------
  # Independent reference model
  #
  # Re-derived from the specifications rather than from Loofah's source. The
  # only regular expressions here are small hand-written character-class checks
  # for RFC scheme/mediatype grammar; none of Loofah's URI regexes are reused.
  # ---------------------------------------------------------------------------
  module ReferenceUri
    MAX_CODEPOINT = 0x10FFFF
    HEX_DIGITS = (("0".."9").to_a + ("a".."f").to_a + ("A".."F").to_a).freeze
    DEC_DIGITS = ("0".."9").to_a.freeze

    # Codepoints the sanitizer removes between decoding and protocol recognition.
    STRIPPED = ((0x00..0x20).to_a + [0x60, 0x7F] + (0x80..0x101).to_a).freeze

    NAMED_WHITESPACE = ["&Tab;", "&NewLine;"].freeze
    NAMED_DELIMITERS = { "&colon;" => ":", "&sol;" => "/" }.freeze

    # Scheme and data mediatype allowlists, spelled out from the sanitizer's
    # public configuration rather than read from Loofah at runtime.
    SAFE_SCHEMES = %w[
      afs aim callto data ed2k fax ftp gopher http https irc line mailto modem
      news nntp rsync rtsp sftp sms ssh tag tel telnet urn webcal xmpp
    ].freeze
    SAFE_DATA_TYPES = %w[image/gif image/jpeg image/png text/css text/plain].freeze

    module_function

    def safe?(raw)
      return false unless raw.valid_encoding?

      normalized =
        begin
          normalize(raw)
        rescue EncodingError
          return false
        end
      scheme, = split_scheme(normalized)
      return true if scheme.nil?
      return false unless SAFE_SCHEMES.include?(scheme)
      if scheme == "data"
        # The mediatype parser only removes a literal "data:" prefix. An encoded
        # separator leaves the prefix in place, so the whole string is split on
        # its comma instead, reproducing the sanitizer's text/plain fallback.
        return false unless SAFE_DATA_TYPES.include?(data_mediatype(normalized))
      end

      true
    end

    # Full normalization up to (and including) ASCII downcasing. Exposed so the
    # shrinking and work-scaling tests can reuse the reference pipeline.
    def normalize(raw)
      s = transcode_utf8(raw)
      raise EncodingError unless s

      # A semicolon-terminated numeric reference is HTML-unescaped while it is
      # decoded, then the whole string gets one more unescape pass. A
      # double-encoded reference ("&amp;#58;") therefore resolves only one layer.
      s = decode_numeric(s)
      s = CGI.unescapeHTML(s)
      s = strip_control(s)
      NAMED_WHITESPACE.each { |ref| s = s.gsub(ref, "") }
      NAMED_DELIMITERS.each { |ref, ch| s = s.gsub(ref, ch) }
      s.downcase
    end

    # Explicit per-character numeric reference scanner (decimal or hex, with or
    # without the trailing semicolon). Returns the decoded string plus the number
    # of input characters examined, which the work-scaling test reuses.
    def decode_numeric(input)
      decoded, = decode_numeric_with_work(input)
      decoded
    end

    def decode_numeric_with_work(input)
      out = String.new(encoding: Encoding::UTF_8)
      work = 0
      i = 0
      while i < input.length
        work += 1
        if input[i, 2] == "&#"
          hex = input[i + 2] == "x" || input[i + 2] == "X"
          allowed = hex ? HEX_DIGITS : DEC_DIGITS
          start = hex ? i + 3 : i + 2
          j = start
          while j < input.length && allowed.include?(input[j])
            work += 1
            j += 1
          end
          digits = input[start...j]
          if digits.empty?
            out << input[i]
            i += 1
            next
          end

          terminated = input[j] == ";"
          j += 1 if terminated
          decoded = decode_digits(digits, hex)
          if decoded.nil?
            out << input[i...j]
          elsif terminated
            # unescapeHTML is a no-op on the raw character the reference yields.
            out << CGI.unescapeHTML(decoded)
          else
            out << decoded
          end
          i = j
        else
          out << input[i]
          i += 1
        end
      end
      [out, work]
    end

    def decode_digits(digits, hex)
      significant = digits.sub(/\A0+/, "")
      max_significant = hex ? 6 : 7
      return nil if significant.length > max_significant

      codepoint = significant.to_i(hex ? 16 : 10)
      return nil if codepoint > MAX_CODEPOINT

      codepoint.chr(Encoding::UTF_8)
    rescue RangeError
      nil
    end

    def strip_control(input)
      input.chars.reject { |ch| STRIPPED.include?(ch.ord) }.join
    end

    # Returns [scheme, remainder]. The scheme terminates at a literal colon or at
    # an encoded colon (percent "%3a", or a residual numeric reference
    # "&#00...58" / "&#x00...3a", with or without a semicolon).
    def split_scheme(s)
      return [nil, nil] unless s[0] && scheme_start?(s[0])

      k = 1
      k += 1 while k < s.length && scheme_body?(s[k])
      return [nil, nil] if k >= s.length

      if s[k] == ":"
        [s[0...k], s[(k + 1)..]]
      else
        width = encoded_colon_width(s, k)
        width ? [s[0...k], s[(k + width)..]] : [nil, nil]
      end
    end

    # Hand-written recognition of the encoded-colon forms; returns the consumed
    # width or nil. This does not reuse Loofah's PROTOCOL_SEPARATOR pattern.
    def encoded_colon_width(s, k)
      if s[k, 3] && s[k, 3].upcase == "%3A"
        3
      elsif s[k, 2] == "&#"
        numeric_colon_width(s, k)
      end
    end

    def numeric_colon_width(s, k)
      hex = s[k + 2] == "x" || s[k + 2] == "X"
      digit_start = hex ? k + 3 : k + 2
      j = digit_start
      j += 1 while s[j] == "0"
      required = hex ? "3a" : "58"
      return nil unless s[j, 2]&.downcase == required

      j += 2
      j += 1 if s[j] == ";"
      j - k
    end

    def scheme_start?(ch)
      ch.match?(/[a-z]/)
    end

    def scheme_body?(ch)
      ch.match?(/[a-z0-9+\-.]/)
    end

    def data_mediatype(full_uri)
      metadata, comma, _data = full_uri.delete_prefix("data:").partition(",")
      return nil if comma.empty?

      mediatype = metadata.delete_suffix(";base64").split(";", 2).first.to_s.strip
      valid_mediatype?(mediatype) ? mediatype : "text/plain"
    end

    # RFC 9110 tchar-based type "/" subtype check.
    def valid_mediatype?(mediatype)
      type, slash, subtype = mediatype.partition("/")
      return false if slash.empty? || type.empty? || subtype.empty?

      token = /\A[!#$%&'*+\-.^_`|~a-z0-9]+\z/
      token.match?(type) && token.match?(subtype)
    end

    def transcode_utf8(raw)
      raw.encode(Encoding::UTF_8)
    rescue EncodingError
      nil
    end
  end

  # ---------------------------------------------------------------------------
  # Deterministic input generation
  # ---------------------------------------------------------------------------
  SEED = 0x5EED1337
  CONTROL_CHARACTERS = ["\x00", "\t", "\n", "\r", "\f", "\x7F", "\x80", "\xA0", "ā", "`"].freeze
  SCHEMES = %w[javascript vbscript data http https mailto].freeze
  PAYLOADS = ["alert(1)", "msgbox(1)", "image/png;base64,iVBOR", "text/html,<x>", "example.com/x", "foo@bar.com"].freeze
  DECIMAL_COLONS = ["58", "058", "0000000000000000058", "000000000000000000000000000000000058"].freeze
  HEX_COLONS = ["3a", "03a", "00000000000000003a", "00000000000000000000000000000000003a"].freeze
  OTHER_NUMBERS = ["9", "09", "10", "010", "13", "013", "2f", "0002f", "61", "73", "76", "6a"].freeze
  NAMED_COLONS = ["&colon;", "&amp;colon;", ":"].freeze
  NAMED_SOLIDUSES = ["&sol;", "&amp;sol;", "/"].freeze
  NAMED_WHITESPACE = ["&Tab;", "&NewLine;", "&amp;Tab;", "&amp;NewLine;"].freeze
  ENCODINGS = [
    Encoding::UTF_8, Encoding::ISO_8859_1, Encoding::UTF_16LE, Encoding::US_ASCII, Encoding::ASCII_8BIT,
  ].freeze

  RANDOM_ATOMS = [
    "javascript", "vbscript", "data", "http", "https", "mailto", "x",
    "&#58", "&#058;", "&#x3a", "&#X3A;", "&#000000000058", "&#9", "&#13;",
    "&colon;", "&sol;", "&Tab;", "&NewLine;", "&amp;colon;", "&amp;#58;",
    ":", "/", ";", ",", "%3A", "%3a", "&#37;3A",
    "\x00", "\t", "\n", "\r", "\f", "\x7f", "\x80", "\xa0", "ā", "`",
    "a", "0", ".", "+", "-", "text/html", "image/png", "base64", "alert(1)",
    "&#x2f", "&#47;", "&", "#", "é",
  ].freeze

  def generated_corpus
    @generated_corpus ||= build_structured_corpus + build_random_corpus
  end

  # Characters the HTML parsers can normalize or otherwise alter inside an
  # attribute value before the URI pipeline runs (NUL truncation, line-ending
  # folding, or whitespace-only attribute removal after stripping). Literal
  # control characters stay fully covered by the standalone judgement test; in
  # the attribute test they appear through character-reference forms instead,
  # which reach the URI pipeline untouched.
  def literal_control_character?(sample)
    sample.each_char.any? { |ch| ReferenceUri::STRIPPED.include?(ch.ord) }
  end

  # HTML parsing and string slicing need well-formed UTF-8. Encoding and invalid
  # byte handling still gets full coverage through the standalone judgement test,
  # which is the layer that owns transcoding.
  def utf8_corpus
    generated_corpus.map do |sample|
      sample.encode(Encoding::UTF_8)
    rescue EncodingError
      nil
    end.compact.select do |sample|
      sample.valid_encoding? && !literal_control_character?(sample)
    end
  end

  def build_structured_corpus
    corpus = []

    # Semicolon-less and semicolon-bearing numeric references, including long
    # zero-padded runs, in both decimal and hexadecimal form.
    (DECIMAL_COLONS + HEX_COLONS + OTHER_NUMBERS).each do |digits|
      ["&#{digits}", "&#x#{digits}"].each do |reference|
        ["", ";"].each do |semicolon|
          SCHEMES.each do |scheme|
            PAYLOADS.each do |payload|
              ref = "#{reference}#{semicolon}"
              corpus << "#{scheme}#{ref}#{payload}"
              CONTROL_CHARACTERS.each { |cc| corpus << "#{scheme}#{ref}#{cc}#{payload}" }
            end
          end
        end
      end
    end

    # Named delimiter and whitespace references, including double-encoded forms
    # and control characters embedded inside a named reference.
    NAMED_COLONS.each do |colon|
      NAMED_SOLIDUSES.each do |solidus|
        corpus << "javascript#{colon}alert(1)"
        corpus << "data#{colon}text#{solidus}html,<x>"
        corpus << "data#{colon}image#{solidus}png;base64,iV"
      end
    end
    NAMED_WHITESPACE.each do |whitespace|
      corpus << "java#{whitespace}script:alert(1)"
      corpus << "javascript#{whitespace}:alert(1)"
      corpus << "java#{whitespace}script&colon;alert(1)"
      CONTROL_CHARACTERS.each do |cc|
        corpus << "java&Ta#{cc}b;script:alert(1)"
        corpus << "data&s#{cc}ol;html,<x>"
      end
    end

    # The same logical strings presented in different string encodings.
    bases = [
      "javascript:alert('é')", "http://example.com/é", "javascript&#58alert(1)",
      "data&colon;image&sol;png;base64,iV", "java&Tab;script:alert(1)",
      "javascript&#x3a alert(1)", "/relative/path", "#anchor", "data:,hello",
    ]
    bases.each do |base|
      ENCODINGS.each do |encoding|
        corpus << base.encode(encoding)
      rescue EncodingError
        nil
      end
    end

    # Invalid byte sequences in otherwise UTF-8-tagged strings, plus raw binary.
    corpus << "\xFFjavascript&#58alert(1)".b.force_encoding(Encoding::UTF_8)
    corpus << "http://x/\xE9".b
    corpus.compact.uniq
  end

  def build_random_corpus
    rng = Random.new(SEED)
    Array.new(4000) do
      raw = Array.new(rng.rand(1..12)) { RANDOM_ATOMS.sample(random: rng) }.join
      if rng.rand < 0.3 && raw.valid_encoding? && raw.include?("&#")
        zeros = "0" * rng.rand(0..80)
        raw = raw.sub(/&#(x?)/) { "&#{Regexp.last_match(1)}#{zeros}" }
      end
      encoding = ENCODINGS.sample(random: rng)
      raw.encode(encoding)
    rescue EncodingError
      nil
    end.compact.select(&:valid_encoding?).uniq
  end

  # Greedy delta debugging followed by a single-character sweep. The predicate is
  # the independent oracle, so the result is a 1-minimal fragment that still
  # decides the protocol on its own.
  def shrink_rejected(original)
    current = original
    loop do
      reduced = false
      granularity = 2
      while granularity <= current.length
        step = (current.length.to_f / granularity).ceil
        index = 0
        while index < current.length
          candidate = current[0...index] + current[[index + step, current.length].min..]
          if !candidate.empty? && !ReferenceUri.safe?(candidate)
            current = candidate
            reduced = true
            break
          end
          index += step
        end
        break if reduced

        granularity *= 2
      end
      break unless reduced
    end

    changed = true
    while changed
      changed = false
      current.length.times do |index|
        candidate = current[0...index] + current[(index + 1)..]
        if !candidate.empty? && !ReferenceUri.safe?(candidate)
          current = candidate
          changed = true
          break
        end
      end
    end
    current
  end

  def parsed_attribute_value(fragment_class, uri)
    fragment_class.parse(%(<a href="#{uri}">link</a>)).at_css("a")&.[]("href")
  end

  def uri_attribute_survives?(fragment_class, uri)
    html = %(<a href="#{uri}">link</a>)
    fragment_class.parse(html).scrub!(:strip).at_css("a")&.key?("href") || false
  end

  def string_to_i_calls(uri)
    calls = 0
    trace = TracePoint.new(:c_call) do |event|
      calls += 1 if event.method_id == :to_i && event.defined_class == String
    end
    trace.enable { Loofah::HTML5::Scrub.allowed_uri?(uri.dup) }
    calls
  end

  # ---------------------------------------------------------------------------
  # Tests
  # ---------------------------------------------------------------------------
  def test_generated_judgements_match_the_independent_model
    generated_corpus.each do |sample|
      assert_equal(
        ReferenceUri.safe?(sample.dup),
        Loofah::HTML5::Scrub.allowed_uri?(sample.dup),
        "standalone URI judgement diverged for #{sample.inspect}",
      )
    end
  end

  def test_generated_attribute_scrubbing_matches_the_independent_model
    fragment_classes = [Loofah::HTML4::DocumentFragment]
    fragment_classes << Loofah::HTML5::DocumentFragment if Loofah.html5_support?

    utf8_corpus.each do |sample|
      fragment_classes.each do |fragment_class|
        # The parser runs first and may itself decode named references (HTML5) or
        # leave them literal (HTML4). Run the independent model against the exact
        # attribute value the parser hands to the URI pipeline, not the source.
        parsed_value = parsed_attribute_value(fragment_class, sample)
        next if parsed_value.nil?

        # Two independent conditions keep an attribute: the URI must be accepted,
        # and the parser-supplied value (which allowed_uri? does not mutate) must
        # contain non-whitespace content; otherwise the attribute scrubber drops
        # it. Both predictions come from the reference model.
        expected_survives =
          ReferenceUri.safe?(parsed_value.dup) &&
          parsed_value.match?(/[^[:space:]]/)
        survives = uri_attribute_survives?(fragment_class, sample)
        assert_equal(
          expected_survives,
          survives,
          "attribute scrubbing for #{fragment_class} diverged for #{sample.inspect}",
        )
      end
    end
  end

  def test_rejected_samples_shrink_to_a_minimal_protocol_deciding_fragment
    rejected = utf8_corpus.reject { |sample| ReferenceUri.safe?(sample.dup) }
    assert_operator(rejected.size, :>, 100, "the corpus must actually contain rejected URIs")

    rejected.first(40).each do |sample|
      minimal = shrink_rejected(sample.dup)

      refute_empty(minimal)
      refute(ReferenceUri.safe?(minimal), "shrunk fragment must still be rejected: #{minimal.inspect}")

      # 1-minimality: deleting any single remaining character flips the decision.
      minimal.length.times do |index|
        candidate = minimal[0...index] + minimal[(index + 1)..]
        next if candidate.empty?

        assert(
          ReferenceUri.safe?(candidate),
          "fragment #{minimal.inspect} is not 1-minimal at #{index}: #{candidate.inspect} still rejected",
        )
      end

      # The surviving core contains a scheme-terminating separator, proving the
      # shrinker kept the part that actually decides the protocol.
      assert_match(/:|&#x?0*3a;?|&#0*58;?|%3a/i, minimal)
    end
  end

  def test_reference_decoder_work_scales_linearly_with_input_size
    # Deterministic work measure: characters examined by the reference scanner,
    # not wall-clock time, so the assertion is immune to machine load. A linear
    # scan spends at most one unit of work per character plus a small fixed
    # per-reference overhead. A quadratic (or worse) implementation would make the
    # per-character cost grow without an upper bound as the input gets longer, so
    # pinning every size under the same constant ceiling rules that out.
    sizes = [8, 64, 512, 4096, 32768]
    sizes.each do |zeros|
      input = "javascript&#" + ("0" * zeros) + "58alert(1)"
      _, examined = ReferenceUri.decode_numeric_with_work(input)

      assert_operator(examined, :<=, input.length + 2,
        "work #{examined} exceeded a linear bound for a #{input.length}-character input")
      assert_operator(examined, :>=, input.length - 2,
        "the long zero-padded run must still be scanned, not skipped")
    end

    # Across a 4000x size increase, doubling the input must at most roughly double
    # the work, with headroom for the fixed per-reference cost on the small input.
    smallest = "javascript&#" + ("0" * sizes.first) + "58alert(1)"
    largest = "javascript&#" + ("0" * sizes.last) + "58alert(1)"
    _, small_work = ReferenceUri.decode_numeric_with_work(smallest)
    _, large_work = ReferenceUri.decode_numeric_with_work(largest)
    length_ratio = largest.length.to_f / smallest.length
    work_ratio = large_work.to_f / small_work
    assert_operator(work_ratio, :<=, length_ratio * 1.05,
      "work ratio #{work_ratio.round(3)} outgrew length ratio #{length_ratio.round(3)}")
  end

  def test_overlong_references_skip_big_integer_decoding
    # The sanitizer guards the number of significant digits before building an
    # integer: at most seven decimal or six hexadecimal. Confirm this
    # deterministically with a call-count trace instead of a timing budget, so an
    # over-long significant run never reaches String#to_i. Leading zeros do not
    # count as significant digits, which the in-range padded case also pins down.
    in_range_decimal = "&#0000058;"
    overlong_decimal = "&#12345678;"
    overlong_hex = "&#x1234567;"

    assert_equal(1, string_to_i_calls(in_range_decimal))
    assert_equal(0, string_to_i_calls(overlong_decimal))
    assert_equal(0, string_to_i_calls(overlong_hex))

    # Both decisions still agree with the independent model.
    assert_equal(ReferenceUri.safe?(overlong_decimal), Loofah::HTML5::Scrub.allowed_uri?(overlong_decimal))
    assert_equal(ReferenceUri.safe?(overlong_hex), Loofah::HTML5::Scrub.allowed_uri?(overlong_hex))
  end

  def test_generation_is_deterministic_across_runs
    assert_equal(build_structured_corpus.map(&:to_s), build_structured_corpus.map(&:to_s))
    assert_equal(build_random_corpus.map(&:to_s), build_random_corpus.map(&:to_s))
  end
end
