# encoding: utf-8
# frozen_string_literal: true

require 'spec_helper'

# Generative tests for email header injection (RFC 5322 / RFC 2047 / RFC 6577).
#
# The goal is to prove that a single, user-editable field value cannot, after
# being parsed, displayed and re-encoded by Mail, turn into additional
# From / recipient / authentication-result style header fields.
#
# Two design constraints drive this file:
#
# 1. The oracle is independent of the library under test. We never treat the
#    number of objects Mail itself splits out as the sole verdict. Instead we
#    scan the raw, on-the-wire bytes with our own tiny RFC 5322 line/folding
#    parser (IndependentRawHeader) and count field boundaries there, then cross
#    check that against Mail's own object model.
#
# 2. Every failing input is reduced. Because generated payloads are token
#    sequences, the shrinker drops tokens greedily until it holds the shortest
#    sequence that still produces a semantic increase, and records at which
#    stage the increase appears:
#      * re-encode/serialize  - a new raw field boundary on the wire
#      * display/decode        - an extra mailbox in the in-memory field value
#      * re-parse              - a new field after reparsing the wire bytes
#      * re-parse/address-value- an extra mailbox within the same one field
#      * oracle-disagreement   - raw boundary delta and library delta diverge
RSpec.describe "Mail header injection (generative)", :generative do
  # Header names whose appearance out of a single user field would change the
  # security semantics of a message. Compared case-insensitively.
  SECURITY_SENSITIVE_FIELDS = %w[
    from sender reply-to return-path to cc bcc
    resent-from resent-to resent-cc resent-bcc resent-sender
    received authentication-results dkim-signature arc-authentication-results
    arc-message-signature arc-seal
  ].freeze

  # A fixed, deterministic seed list so the suite is reproducible. Override at
  # runtime with HEADER_FUZZ_SEEDS="1 2 3" and HEADER_FUZZ_ITERATIONS=N.
  DEFAULT_SEEDS = (1..40).to_a.freeze

  def self.generation_seeds
    if ENV['HEADER_FUZZ_SEEDS']
      ENV['HEADER_FUZZ_SEEDS'].split.map(&:to_i)
    else
      DEFAULT_SEEDS
    end
  end

  ITERATIONS = ENV.fetch('HEADER_FUZZ_ITERATIONS', '6').to_i

  # ---------------------------------------------------------------------------
  # Independent oracle: a deliberately small RFC 5322 header parser that does
  # NOT use Mail. It works purely on the serialized bytes the field/message
  # produced, so a bug in Mail's own HEADER_SPLIT cannot mask an injection.
  # ---------------------------------------------------------------------------
  class IndependentRawHeader
    Field = Struct.new(:name, :body, keyword_init: true)

    FIELD_NAME_RE = /\A([\x21-\x39\x3b-\x7e]+):/ # printable ASCII except ":"

    # Split a raw message into header text (everything before the blank line)
    # using the CRLF CRLF separator, tolerating lone LF.
    def self.header_text(raw)
      normalized = raw.to_s.gsub(/\r\n/, "\n").gsub(/\r/, "\n")
      normalized.split(/\n\n/, 2).first.to_s
    end

    # Walk the physical lines. A line beginning with a space or horizontal tab
    # is a continuation (folding) of the previous field, never a new field.
    # Every other line matching "name:" starts a new field boundary.
    def self.fields(raw)
      text = header_text(raw)
      physical_lines = text.split("\n", -1)
      fields = []
      physical_lines.each do |line|
        if line.start_with?(' ', "\t")
          # folded continuation: attach to the current field, do not start one
          fields.last.body << "\n" << line if fields.last
        elsif (match = line.match(FIELD_NAME_RE))
          fields << Field.new(
            name: match[1],
            body: line[(match[0].length)..] || ''
          )
        end
      end
      fields
    end

    def self.field_names(raw)
      fields(raw).map { |f| f.name.downcase }
    end

    # Count of occurrences of each security-sensitive name, measured on the
    # raw wire bytes. This is the number an attacker could influence.
    def self.sensitive_counts(raw)
      names = field_names(raw)
      SECURITY_SENSITIVE_FIELDS.each_with_object({}) do |name, memo|
        memo[name] = names.count(name)
      end
    end

    def self.count(raw, name)
      field_names(raw).count(name.downcase)
    end
  end

  # Deterministic pseudo random generator (xorshift) so runs are reproducible
  # and do not depend on Array#sample ordering across Ruby versions.
  class DeterministicRandom
    def initialize(seed)
      @state = (seed.to_i.zero? ? 0x9e3779b9 : seed.to_i) & 0xffffffff
    end

    def next_i
      x = @state
      x ^= (x << 13) & 0xffffffff
      x ^= x >> 17
      x ^= (x << 5) & 0xffffffff
      @state = x & 0xffffffff
    end

    def rand(range)
      range.begin + (next_i % range.size)
    end

    def sample(array)
      array[rand(0...array.size)]
    end
  end

  # ---------------------------------------------------------------------------
  # Payload generators. Each generated value is an ordered list of tokens that
  # the shrinker can remove one at a time. Tokens combine encoded words,
  # folding, mixed character sets and control characters.
  # ---------------------------------------------------------------------------
  module Payloads
    module_function

    SAFE_UNICODE = ['hello', '你好', 'café', '主题', 'Ωρίωνας', '🎉🎉', 'ａｂｃ', 'naïve'].freeze
    MIXED_CHARSETS = %w[UTF-8 ISO-8859-1 ISO-2022-JP US-ASCII].freeze

    def benign_unicode(length)
      chunk = '主题测试Ωρίων'
      chunk * (length / chunk.length + 1)
    end

    # Token catalog. Every token is itself legal to embed in a field *value*;
    # the question is whether the encoder keeps it confined to that value.
    def token(rng)
      pick = rng.rand(0..9)
      if pick <= 2
        line_break_token(rng)
      elsif pick <= 4
        fold_token(rng)
      elsif pick <= 6
        encoded_word_token(rng)
      elsif pick == 7
        control_token(rng)
      else
        text_token(rng)
      end
    end

    def text_token(rng)
      rng.sample(SAFE_UNICODE)
    end

    def line_break_token(rng)
      # The canonical header-injection building block, in several line-ending
      # shapes so we exercise CRLF, lone LF and lone CR handling.
      rng.sample(["\r\n", "\n", "\r"]) + rng.sample(SECURITY_SENSITIVE_FIELDS) +
        rng.sample([': ', ':']) + rng.sample(['evil@attacker.test', 'spf=pass', 'victim@example.test'])
    end

    def fold_token(rng)
      # A CRLF immediately followed by WSP is a legal fold. An encoder must
      # unfold it to white space rather than let a hidden field survive.
      rng.sample(["\r\n ", "\r\n\t", "\n ", "\r "]) +
        rng.sample(SECURITY_SENSITIVE_FIELDS) + ': evil@attacker.test'
    end

    def encoded_word_token(rng)
      charset = rng.sample(MIXED_CHARSETS)
      payload = rng.sample([
        "\r\nFrom: hidden@attacker.test",
        "\nBcc: blind@attacker.test",
        "你好 café",
        "Authentication-Results: mx.attacker.test spf=pass",
        "plain text"
      ])
      encoding = rng.sample(['B', 'Q'])
      encoded = encoding == 'B' ? b64(payload) : quoted(payload)
      "=?#{charset}?#{encoding}?#{encoded}?="
    end

    def control_token(rng)
      rng.sample(["\x00", "\x01", "\x0b", "\x0c", "\x7f", "\x00From: x@y.test"])
    end

    def b64(text)
      [text].pack('m0').gsub("\n", '')
    end

    def quoted(text)
      text.bytes.map { |b| b >= 0x20 && b < 0x7f && b != 0x3f && b != 0x3d && b != 0x5f ? b.chr : "=%02X" % b }.join
    end

    def build(rng, min_tokens, max_tokens)
      count = rng.rand(min_tokens..max_tokens)
      prefix = text_token(rng)
      rest = Array.new(count) { token(rng) }
      [prefix] + rest
    end
  end

  # A generated case targeted at a specific user-editable field.
  class GeneratedCase
    attr_reader :field_name, :tokens, :seed

    def initialize(field_name, tokens, seed)
      @field_name = field_name
      @tokens = tokens
      @seed = seed
    end

    def value
      tokens.join
    end

    def with_tokens(new_tokens)
      GeneratedCase.new(field_name, new_tokens, seed)
    end

    def address?
      %w[from to cc reply-to].include?(field_name.downcase)
    end

    # Wrap the raw token stream so it occupies the display-name / comment area
    # of an address field, leaving a fixed, valid route address behind.
    def address_value
      display = tokens.join.gsub('"', "'")
      "\"#{display}\" <holder@fixed-route.test>"
    end
  end

  # Drives one value through every Mail stage and records where the first
  # semantic increase happens. The baseline message contains the same fixed
  # headers with an innocuous value, so added/removed framework headers do not
  # produce false positives.
  class StageProbe
    BASELINE_VALUE = 'benign baseline value'
    BASELINE_ADDRESS = '"benign baseline" <holder@fixed-route.test>'

    attr_reader :stage, :detail, :independent_counts, :library_counts

    # Test-only seam. When set to a callable, it receives the serialized wire
    # string and the generated case and may return a tampered wire form. It
    # lets the suite prove the oracle would catch a genuinely vulnerable
    # encoder without weakening any production assertion. Always nil in the
    # real generative checks.
    @wire_tamper = nil
    class << self
      attr_accessor :wire_tamper
    end

    def self.run(generated_case)
      new(generated_case).run
    end

    def initialize(generated_case)
      @c = generated_case
    end

    def run
      baseline_value = @c.address? ? BASELINE_ADDRESS : BASELINE_VALUE
      baseline = build_message(baseline_value)
      candidate = build_message(@c.address? ? @c.address_value : @c.value)

      baseline_wire = baseline.encoded
      wire = candidate.encoded
      wire = self.class.wire_tamper.call(wire, @c) if self.class.wire_tamper

      base_independent = IndependentRawHeader.sensitive_counts(baseline_wire)
      @independent_counts = IndependentRawHeader.sensitive_counts(wire)

      @library_counts = SECURITY_SENSITIVE_FIELDS.each_with_object({}) do |name, memo|
        memo[name] = candidate.header.fields.count { |f| f.name.downcase == name }
      end
      base_library = SECURITY_SENSITIVE_FIELDS.each_with_object({}) do |name, memo|
        memo[name] = baseline.header.fields.count { |f| f.name.downcase == name }
      end

      detect_increase(base_independent, @independent_counts, base_library,
                      baseline_wire, wire, baseline, candidate)
      self
    end

    def injected?
      !@stage.nil?
    end

    private

    def build_message(value)
      # Only pre-populate the fixed framework fields that are NOT the target
      # user field. The target field is assigned exactly once below, so a
      # duplicated header in the result cannot be an artifact of the harness.
      Mail.new do |m|
        m.from     = 'sender@fixed-route.test'
        m.to       = 'recipient@fixed-route.test'
        m.cc       = 'cc-holder@fixed-route.test'
        m.reply_to = 'reply-holder@fixed-route.test'
        m.subject  = 'fixed subject'
        clear_target_scaffold(m)
        assign_user_field(m, value)
        m.body     = 'fixed body'
      end
    end

    def clear_target_scaffold(mail)
      name = @c.field_name.downcase
      mail.header[name] = nil if %w[from to cc reply-to].include?(name)
    end

    def assign_user_field(mail, value)
      case @c.field_name.downcase
      when 'subject' then mail.subject = value
      when 'comments' then mail.comments = value
      when 'from' then mail.from = value
      when 'to' then mail.to = value
      when 'cc' then mail.cc = value
      when 'reply-to' then mail.reply_to = value
      else mail[@c.field_name] = value
      end
    end

    def detect_increase(base_ind, ind, base_lib, baseline_wire, wire, baseline, candidate)
      # Stage 1: parse. The raw wire message the candidate produced must not
      # expose a new sensitive boundary when scanned independently.
      increased = diff(base_ind, ind)
      unless increased.empty?
        return record('re-encode/serialize', increased, ind, wire)
      end

      # Stage 2: display. The decoded/displayed value must not be parseable as
      # additional addresses for the recipient/from class fields.
      display_increase = display_semantic_increase(candidate, baseline)
      unless display_increase.empty?
        return record('display/decode', display_increase, ind, wire)
      end

      # Stage 3: re-parse of the serialized bytes through Mail. Independent
      # counts already guard the wire form; this confirms the library object
      # model agrees and did not silently merge/split.
      reparsed = Mail.new(wire)
      reparsed_counts = SECURITY_SENSITIVE_FIELDS.each_with_object({}) do |name, memo|
        memo[name] = reparsed.header.fields.count { |f| f.name.downcase == name }
      end
      reparsed_increase = diff(base_lib, reparsed_counts)
      unless reparsed_increase.empty?
        return record('re-parse', reparsed_increase, ind, wire)
      end

      # Stage 3b: even when the field *count* is unchanged, a value can gain an
      # extra mailbox within the same single field after re-parsing. Compare
      # the reparsed mailbox set against the baseline to catch this value-level
      # semantic increase.
      reparsed_address_increase = reparsed_address_semantic_increase(reparsed, baseline)
      unless reparsed_address_increase.empty?
        return record('re-parse/address-value', reparsed_address_increase, ind, wire)
      end

      # Cross-check: the independent raw boundary deltas and the library deltas
      # must agree, so a field the library silently dropped or invented cannot
      # pass unnoticed.
      independent_delta = delta(base_ind, ind)
      library_delta = delta(base_lib, reparsed_counts)
      mismatch = independent_delta.select do |name, ind_delta|
        ind_delta != library_delta.fetch(name, 0)
      end
      record('oracle-disagreement', mismatch, ind, wire) unless mismatch.empty?
    end

    def diff(baseline, current)
      current.select { |name, count| count > baseline.fetch(name, 0) }
    end

    # Signed change versus baseline (positive = added, negative = removed).
    def delta(baseline, current)
      current.each_with_object({}) do |(name, count), memo|
        memo[name] = count - baseline.fetch(name, 0)
      end
    end

    def mailbox_set(message)
      field = message.header[@c.field_name]
      return [] unless field.respond_to?(:element) && field.element.respond_to?(:addresses)

      field.element.addresses.map(&:address)
    end

    def display_semantic_increase(candidate, baseline)
      return {} unless @c.address?

      extra = mailbox_set(candidate) - mailbox_set(baseline)
      extra.empty? ? {} : { @c.field_name.downcase => extra }
    end

    def reparsed_address_semantic_increase(reparsed, baseline)
      return {} unless @c.address?

      extra = mailbox_set(reparsed) - mailbox_set(baseline)
      extra.empty? ? {} : { @c.field_name.downcase => extra }
    end

    def record(stage, increase, counts, _wire)
      @stage = stage
      @detail = increase
      @independent_counts = counts
    end
  end

  # Greedy token-level shrinking: remove tokens while the probe still fails,
  # keeping the shortest failing sequence, then report the minimal fragment.
  class Shrinker
    def self.shrink(generated_case)
      probe = StageProbe.run(generated_case)
      return [generated_case, probe] unless probe.injected?

      tokens = generated_case.tokens.dup
      shrunk = generated_case
      shrunk_probe = probe

      changed = true
      while changed
        changed = false
        tokens.each_index do |index|
          candidate_tokens = tokens.values_at(*(tokens.each_index.to_a - [index]))
          next if candidate_tokens.empty?

          candidate_case = generated_case.with_tokens(candidate_tokens)
          candidate_probe = StageProbe.run(candidate_case)
          next unless candidate_probe.injected?

          tokens = candidate_tokens
          shrunk = candidate_case
          shrunk_probe = candidate_probe
          changed = true
          break
        end
      end

      [shrunk, shrunk_probe]
    end
  end

  # ---------------------------------------------------------------------------
  # Specs
  # ---------------------------------------------------------------------------
  UNSTRUCTURED_TARGETS = %w[subject comments].freeze
  ADDRESS_TARGETS = %w[from to cc reply-to].freeze

  def generate_case(field_name, seed)
    rng = DeterministicRandom.new(seed)
    tokens = Payloads.build(rng, 2, 9)
    GeneratedCase.new(field_name, tokens, seed)
  end

  def assert_no_injection(generated_case)
    minimal_case, probe = Shrinker.shrink(generated_case)

    expect(probe.injected?).to(
      eq(false),
      -> { failure_message(generated_case, minimal_case, probe) }
    )
  end

  def failure_message(original, minimal, probe)
    lines = []
    lines << "Header injection semantic increase detected at stage: #{probe.stage}"
    lines << "field=#{original.field_name} seed=#{original.seed}"
    lines << "minimal fragment tokens=#{minimal.tokens.inspect}"
    lines << "minimal fragment value=#{minimal.value.inspect}"
    lines << "increase=#{probe.detail.inspect}"
    lines << "independent raw counts=#{probe.independent_counts.inspect}"
    lines << "library counts=#{probe.library_counts.inspect}"
    lines.join("\n")
  end

  describe "unstructured user fields (subject, comments)" do
    UNSTRUCTURED_TARGETS.each do |field_name|
      context "for #{field_name}" do
        self.generation_seeds.each_with_index do |seed, iteration|
          break if iteration >= ITERATIONS

          it "keeps generated value inside one field (seed #{seed})" do
            assert_no_injection(generate_case(field_name, seed * 7 + 11))
          end
        end
      end
    end
  end

  describe "address-bearing user fields (from/recipients)" do
    ADDRESS_TARGETS.each do |field_name|
      context "for #{field_name}" do
        self.generation_seeds.each_with_index do |seed, iteration|
          break if iteration >= ITERATIONS

          it "keeps generated display text out of the route addresses (seed #{seed})" do
            assert_no_injection(generate_case(field_name, seed * 13 + 5))
          end
        end
      end
    end
  end

  describe "independent field-boundary oracle" do
    it "counts folded continuations as part of the preceding field, not new fields" do
      raw = "Subject: first\r\n folded line\r\nFrom: a@b.test\r\n\r\nbody"
      names = IndependentRawHeader.field_names(raw)
      expect(names).to eq(%w[subject from])
    end

    it "treats a CRLF + non-WSP token as a new boundary in raw bytes" do
      # This documents the oracle itself: if an encoder ever emitted this raw
      # form, the independent scanner would catch the injected From.
      raw = "Subject: x\r\nFrom: injected@attacker.test\r\n\r\nbody"
      expect(IndependentRawHeader.count(raw, 'from')).to eq(1)
      expect(IndependentRawHeader.sensitive_counts(raw)['from']).to eq(1)
    end

    it "is independent of Mail's own HEADER_SPLIT constant" do
      raw = "Subject: a\r\n\tfolded\r\nTo: x@y.test\r\n\r\nb"
      expect(IndependentRawHeader.field_names(raw)).to eq(%w[subject to])
      # Mail may reorder known headers, so compare as a set rather than order.
      expect(Mail.new(raw).header.fields.map { |f| f.name.downcase }).to match_array(%w[subject to])
    end
  end

  describe "benign long Unicode subjects" do
    lengths = {
      200 => 'short multibyte subject',
      1000 => 'long multibyte subject',
      5000 => 'very long multibyte subject'
    }

    lengths.each do |length, label|
      it "round trips a #{label} without adding headers" do
        value = Payloads.benign_unicode(length)
        mail = Mail.new { |m| m.subject = value; m.body = 'b' }
        wire = mail.encoded

        # No raw boundary other than the framework headers may appear.
        expect(IndependentRawHeader.count(wire, 'from')).to eq(0)
        expect(IndependentRawHeader.count(wire, 'to')).to eq(0)
        expect(IndependentRawHeader.count(wire, 'authentication-results')).to eq(0)

        reparsed = Mail.new(wire)
        expect(reparsed.header[:subject].decoded).to eq(value)
        # Folding must only ever produce continuation lines (leading WSP), so
        # every boundary the independent scanner finds must be a framework
        # header Mail itself adds, never a user-injected security field.
        allowed = %w[
          subject mime-version content-type content-transfer-encoding
          date message-id
        ]
        IndependentRawHeader.fields(wire).each do |field|
          expect(allowed).to include(field.name.downcase)
        end
      end
    end
  end

  describe "addresses with comments (control table)" do
    # Each row pins down the exact mailbox/display/comment interpretation so a
    # change in address semantics is caught independently of header counts.
    #
    # raw_input, expected_mailboxes, expected_display_names, expected_comments
    rows = [
      [
        'carol@example.test (plain comment)',
        ['carol@example.test'],
        [nil],
        [['plain comment']]
      ],
      [
        '"Bob (root)" <bob@example.test> (route comment)',
        ['bob@example.test'],
        ['Bob (root)'],
        [nil]
      ],
      [
        '"Bob" <bob@example.test>, carol@example.test (other)',
        ['bob@example.test', 'carol@example.test'],
        ['Bob', nil],
        [nil, ['other']]
      ]
    ]

    rows.each do |raw_input, mailboxes, display_names, comments|
      it "parses #{raw_input[0, 40].inspect} into the documented mailbox set" do
        addresses = Mail::AddressList.new(raw_input).addresses

        expect(addresses.map(&:address)).to eq(mailboxes)
        expect(addresses.map(&:display_name)).to eq(display_names)
        expect(addresses.map(&:comments)).to eq(comments)

        # The same value, fed through a full message and re-encoded, must not
        # gain a From/recipient field beyond the single one it occupies.
        mail = Mail.new { |m| m.to = raw_input }
        wire = mail.encoded
        expect(IndependentRawHeader.count(wire, 'to')).to eq(1)
        expect(IndependentRawHeader.count(wire, 'from')).to eq(0)

        reparsed = Mail.new(wire)
        expect(reparsed[:to].element.addresses.map(&:address)).to eq(mailboxes)
      end
    end
  end

  describe "encoded-word and mixed charset confinement" do
    require 'base64'

    it "neutralizes a CRLF hidden inside a base64 encoded word" do
      hidden = Base64.strict_encode64("\r\nFrom: pwn@attacker.test")
      mail = Mail.new { |m| m.subject = "=?UTF-8?B?#{hidden}?=" }
      wire = mail.encoded

      expect(IndependentRawHeader.count(wire, 'from')).to eq(0)
      expect(IndependentRawHeader.field_names(wire)).not_to include('from')
      # The CR/LF must be represented as encoded bytes, never raw line breaks
      # at a field boundary.
      subject_line = IndependentRawHeader.fields(wire).find { |f| f.name.downcase == 'subject' }
      expect(subject_line.body).not_to match(/[\r\n]/)
    end

    it "re-encodes mixed charsets into one value without spawning headers" do
      value = '=?UTF-8?B?5L2g5aW9?= and =?ISO-8859-1?Q?caf=E9?= tail'
      mail = Mail.new { |m| m.subject = value }
      wire = mail.encoded

      SECURITY_SENSITIVE_FIELDS.each do |name|
        expect(IndependentRawHeader.count(wire, name)).to eq(0)
      end
      expect(Mail.new(wire).header[:subject].decoded).to eq('你好 and café tail')
    end

    it "keeps an encoded-word CRLF inside an address display name confined" do
      hidden = Base64.strict_encode64("A\r\nFrom: x@attacker.test")
      mail = Mail.new { |m| m.from = "=?UTF-8?B?#{hidden}?= <legit@fixed-route.test>" }
      wire = mail.encoded

      expect(IndependentRawHeader.count(wire, 'from')).to eq(1)
      reparsed = Mail.new(wire)
      expect(reparsed[:from].element.addresses.map(&:address)).to eq(['legit@fixed-route.test'])
    end
  end

  describe "shrinker and stage reporting" do
    after { StageProbe.wire_tamper = nil }

    it "flags a vulnerable encoder, names the stage, and shrinks to the shortest fragment" do
      # Simulate an encoder that fails to neutralize a CRLF-bearing token: it
      # writes the decoded token back to the wire as a raw header boundary.
      StageProbe.wire_tamper = lambda do |wire, generated|
        break wire unless generated.value.include?("\r\nFrom: x@y.test")

        wire.sub(
          /Subject: [^\r\n]*/,
          "Subject: safe\r\nFrom: x@y.test"
        )
      end

      tokens = ['safe', 'padding', "\r\nFrom: x@y.test", 'tail', 'more-padding']
      generated = GeneratedCase.new('subject', tokens, 1)

      minimal_case, probe = Shrinker.shrink(generated)

      expect(probe.injected?).to eq(true)
      # The independent raw-wire scan is what surfaces the boundary.
      expect(probe.stage).to eq('re-encode/serialize')
      expect(probe.detail).to include('from')
      # The shrinker keeps the single token that triggers the semantics and
      # drops every benign token around it.
      expect(minimal_case.tokens).to eq(["\r\nFrom: x@y.test"])
      expect(minimal_case.value).to eq("\r\nFrom: x@y.test")
    end

    it "reports no injection against the real Mail encoder" do
      tokens = ['safe', 'padding', "\r\nFrom: x@y.test", 'tail']
      generated = GeneratedCase.new('subject', tokens, 1)
      probe = StageProbe.run(generated)
      expect(probe.injected?).to eq(false)
    end

    it "flags a value-level extra mailbox at re-parse even with no new boundary" do
      # A vulnerable round trip that keeps a single Reply-To boundary but
      # smuggles a second, syntactically valid mailbox into its value. The raw
      # boundary count stays flat, so only the re-parsed mailbox-set comparison
      # catches it.
      StageProbe.wire_tamper = lambda do |wire, generated|
        break wire unless generated.field_name.downcase == 'reply-to'

        wire.sub('Reply-To: ', 'Reply-To: smuggled-extra@evil.test, ')
      end

      generated = GeneratedCase.new('reply-to', ['display text'], 1)
      probe = StageProbe.run(generated)

      expect(probe.injected?).to eq(true)
      expect(probe.stage).to eq('re-parse/address-value')
      expect(probe.detail).to eq('reply-to' => ['smuggled-extra@evil.test'])
    end
  end
end
