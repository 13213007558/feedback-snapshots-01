# -*- ruby encoding: utf-8 -*-
#
# Generative tests for Net::LDAP::Dataset LDIF reading and writing.
#
# Directory snapshots are imported from LDIF and later used for permission
# comparisons, so every attribute must stay attached to the DN of the record
# it physically belongs to. These tests do not trust the parser to describe
# itself: input is generated from an independent record model (LdifRecord /
# LdifValue), the parsed Dataset is compared against that model, and the
# Dataset is serialized and re-parsed so write-side attribution is checked
# too.
#
# Every generated sample keeps a parallel map of physical line number ->
# logical record owner. Failure messages print that map so a crossed record
# can be located directly in the LDIF text.
#
# Malformed input (invalid base64, duplicate DNs, attributes without a DN,
# folding across a record boundary) must be rejected with a dedicated
# Net::LDAP::LdifError naming the offending physical line, instead of being
# silently swallowed and reported as a successful import.
require_relative 'test_helper'
require 'base64'

class TestLdifDatasetGeneration < Test::Unit::TestCase
  PLAIN_ALPHABET = (("a".."z").to_a + ("A".."Z").to_a + ("0".."9").to_a +
    %w[- _ . @ : =]).freeze
  ATTR_NAMES = %w[cn sn mail uid member hasAccessRole].freeze
  GENERATIONS = 60

  # A single attribute value in the independent model. The model stores the
  # raw value plus the rendering decisions (base64 and/or line folding) that
  # the generator is asked to emit.
  LdifValue = Struct.new(:raw, :encoding, :folded) do
    def base64?
      encoding == :base64
    end
  end

  # A logical LDIF record: one DN and an ordered list of attribute/value
  # pairs. Nothing here knows how Dataset parses text.
  LdifRecord = Struct.new(:dn, :dn_encoding, :dn_folded, :attrs)

  # A rendered LDIF document. +physical_lines+ and +owners+ are parallel
  # arrays: owners[i] is the logical owner of physical line i, either a
  # record index or one of :version/:comment/:blank/:orphan.
  class LdifSample
    attr_reader :physical_lines, :owners, :records, :line_ending, :version

    def initialize(records, physical_lines, owners, line_ending, version)
      @records = records
      @physical_lines = physical_lines
      @owners = owners
      @line_ending = line_ending
      @version = version
    end

    def to_s
      physical_lines.join(line_ending)
    end

    def dns
      records.map(&:dn)
    end

    # What a correct parser must produce: DN -> attribute -> raw values,
    # using the same canonical attribute keys Dataset uses.
    def expected_attribution
      records.each_with_object({}) do |record, by_dn|
        by_dn[record.dn] = record.attrs.each_with_object({}) do |(name, values), by_attr|
          by_attr[name.downcase.to_sym] = values.map(&:raw)
        end
      end
    end

    # Global raw-value -> owning-DN index. Values carry unique tokens, so a
    # value found under another DN proves a record-crossing bug.
    def value_owners
      records.each_with_object({}) do |record, map|
        record.attrs.each do |_name, values|
          values.each { |value| map[value.raw] = record.dn }
        end
      end
    end

    def line_number(physical_line, occurrence: 1)
      matches = physical_lines.each_index.select { |index| physical_lines[index] == physical_line }
      if matches.length < occurrence
        raise "test bug: physical line #{physical_line.inspect} occurs " \
          "only #{matches.length} time(s)"
      end
      matches[occurrence - 1] + 1
    end

    # Physical line number alongside the logical record it belongs to, with
    # continuation and blank lines shown explicitly. This is the evidence
    # printed whenever attribution does not match the model.
    def annotated
      legend = records.each_with_index.map do |record, index|
        "rec##{index} -> #{record.dn.inspect}"
      end
      body = physical_lines.each_with_index.map do |line, index|
        format("%4d [%-7s] %s", index + 1, owner_tag(owners[index]), line.inspect)
      end
      (legend + body).join("\n")
    end

    private

    def owner_tag(owner)
      owner.is_a?(Integer) ? "rec##{owner}" : owner.to_s
    end
  end

  # Renders the independent model into LDIF physical lines while recording
  # ownership of every line. Also used by the malformed-input tests so that
  # deliberately broken samples keep the same line/record mapping.
  class LdifBuilder
    attr_reader :physical_lines, :owners

    def initialize(line_ending: "\n")
      @line_ending = line_ending
      @physical_lines = []
      @owners = []
    end

    def emit_version
      emit("version: 1", :version)
    end

    def emit_comment(text, owner: :comment)
      emit("# #{text}", owner)
    end

    def emit_blank
      emit("", :blank)
    end

    def emit_raw(line, owner)
      emit(line, owner)
    end

    def emit_dn(record, record_index)
      if record.dn_encoding == :base64
        emit_encoded_line("dn", record.dn, record.dn_folded, record_index)
      else
        emit_folded("dn: #{record.dn}", record.dn_folded, record_index)
      end
    end

    def emit_attribute(name, value, record_index)
      if value.base64?
        emit_encoded_line(name, value.raw, value.folded, record_index)
      else
        emit_folded("#{name}: #{value.raw}", value.folded, record_index)
      end
    end

    def build(records, version: nil)
      LdifSample.new(records, physical_lines, owners, @line_ending, version)
    end

    private

    def emit(line, owner)
      physical_lines << line
      owners << owner
      line
    end

    # RFC 2849 folding: continuation physical lines start with one space;
    # the parser must remove exactly that leading space and rejoin.
    def emit_folded(line, folded, owner)
      return emit(line, owner) unless folded && line.length > 2
      cut = (line.length / 2.0).ceil
      emit(line[0...cut], owner)
      emit(" #{line[cut..]}", owner)
    end

    def emit_encoded_line(prefix, raw, folded, owner)
      encoded = Base64.strict_encode64(raw)
      line = "#{prefix}:: #{encoded}"
      return emit(line, owner) unless folded && encoded.length > 4
      cut = (encoded.length / 2.0).ceil
      emit("#{prefix}:: #{encoded[0...cut]}", owner)
      emit(" #{encoded[cut..]}", owner)
    end
  end

  # ----------------------------------------------------------------
  # Model-driven random generation (deterministic per seed).
  # ----------------------------------------------------------------

  def self.generate_sample(seed)
    rng = Random.new(2026_1114 + seed)
    builder = LdifBuilder.new(line_ending: seed.even? ? "\r\n" : "\n")
    records = build_records(rng)

    builder.emit_version if rng.rand < 0.4
    builder.emit_comment("seed #{seed} header comment") if rng.rand < 0.6
    builder.emit_blank if builder.physical_lines.any?

    records.each_with_index do |record, record_index|
      builder.emit_comment("seed #{seed} rec #{record_index}", owner: record_index) if rng.rand < 0.5
      builder.emit_dn(record, record_index)
      record.attrs.each do |name, values|
        values.each { |value| builder.emit_attribute(name, value, record_index) }
      end
      last_record = record_index == records.length - 1
      if last_record && rng.rand < 0.5
        # Leave the final record unterminated so the last physical line is
        # an attribute line rather than a blank separator.
        next
      end
      builder.emit_blank
      builder.emit_blank if rng.rand < 0.4
    end

    builder.build(records, version: builder.owners.include?(:version) ? "1" : nil)
  end

  def self.build_records(rng)
    Array.new(2 + rng.rand(4)) do |record_index|
      dn = "cn=user#{record_index}-#{token(rng, 6)},ou=people,dc=example,dc=com"
      attrs = Array.new(1 + rng.rand(3)) do |attr_index|
        name = ATTR_NAMES[(record_index + attr_index) % ATTR_NAMES.length]
        values = Array.new(1 + rng.rand(2)) do |value_index|
          build_value(rng, record_index, name, value_index, attr_index)
        end
        [name, values]
      end
      # Guarantee every sample exercises base64 and folding at least once.
      attrs.first[1][0] = LdifValue.new(binary_value(rng, record_index, "anchor"), :base64, true)
      if attrs[0][1].length > 1
        attrs[0][1][1] = LdifValue.new(plain_value(rng, record_index, attrs[0][0], "fold"), :plain, true)
      end
      LdifRecord.new(dn, rng.rand < 0.3 ? :base64 : :plain, rng.rand < 0.5, attrs)
    end
  end

  def self.build_value(rng, record_index, name, value_index, attr_index)
    if attr_index.zero? && value_index.zero?
      LdifValue.new(binary_value(rng, record_index, name), :base64, rng.rand < 0.6)
    elsif rng.rand < 0.35
      LdifValue.new(binary_value(rng, record_index, name), :base64, rng.rand < 0.7)
    else
      LdifValue.new(plain_value(rng, record_index, name, value_index), :plain, rng.rand < 0.5)
    end
  end

  def self.plain_value(rng, record_index, name, tag)
    # Globally unique, printable, and free of leading/trailing spaces so it
    # is legal as an unencoded LDIF value.
    "r#{record_index}-#{name}-#{tag}-#{token(rng, 12)}"
  end

  def self.binary_value(rng, record_index, name)
    # Non-printable bytes force the value through the base64 code path.
    "bin-r#{record_index}-#{name}-#{token(rng, 10)}".b <<
      [0x01, rng.rand(0x80..0xFE)].pack("CC")
  end

  def self.token(rng, length)
    Array.new(length) { PLAIN_ALPHABET[rng.rand(PLAIN_ALPHABET.length)] }.join
  end

  # ----------------------------------------------------------------
  # Assertions shared by the positive tests.
  # ----------------------------------------------------------------

  def assert_attribution_matches_model(dataset, sample)
    assert_equal(sample.expected_attribution, compact_dataset(dataset),
      attribution_failure(sample, dataset))
  end

  def assert_each_value_stays_with_its_dn(dataset, sample)
    ownership = sample.value_owners
    dataset.each_pair do |dn, attrs|
      attrs.each_value do |values|
        values.each do |value|
          assert_equal(ownership[value], dn,
            crossed_record_failure(sample, value, dn, ownership[value]))
        end
      end
    end
  end

  def assert_physical_ownership_consistent(sample)
    sample.physical_lines.each_with_index do |line, index|
      next unless line.start_with?(" ")
      previous_owner = sample.owners[index - 1]
      assert_equal(previous_owner, sample.owners[index],
        "continuation line #{index + 1} changed logical owner:\n#{sample.annotated}")
      assert(previous_owner.is_a?(Integer),
        "continuation line #{index + 1} has no record owner:\n#{sample.annotated}")
    end
  end

  def assert_writer_lines_stay_under_their_dn(dataset, sample)
    current_dn = nil
    expected = sample.expected_attribution
    dataset.to_ldif.each do |line|
      if line.start_with?("dn: ")
        current_dn = line[4..]
        assert(expected.key?(current_dn),
          "writer emitted unknown DN #{current_dn.inspect}:\n#{sample.annotated}")
      elsif line.empty?
        current_dn = nil
      elsif line.start_with?("#", "version:")
        next
      elsif line =~ /^([^:]+):[:]?\s*/
        attribute = $1.downcase.to_sym
        assert(current_dn && expected[current_dn].key?(attribute),
          "writer emitted #{attribute} outside its record (#{current_dn.inspect}):\n#{sample.annotated}")
      end
    end
  end

  def compact_dataset(dataset)
    dataset.each_pair.with_object({}) do |(dn, attrs), result|
      result[dn] = attrs
    end
  end

  def attribution_failure(sample, dataset)
    "parsed attribution does not match the record model.\n" \
      "expected: #{sample.expected_attribution.inspect}\n" \
      "parsed:   #{compact_dataset(dataset).inspect}\n#{sample.annotated}"
  end

  def crossed_record_failure(sample, value, parsed_dn, model_dn)
    "value #{value.inspect} landed under #{parsed_dn.inspect} but belongs to " \
      "#{model_dn.inspect}:\n#{sample.annotated}"
  end

  # ----------------------------------------------------------------
  # Positive, model-driven round-trip tests.
  # ----------------------------------------------------------------

  def test_generated_ldif_keeps_every_attribute_with_its_dn
    GENERATIONS.times do |seed|
      sample = self.class.generate_sample(seed)
      assert_physical_ownership_consistent(sample)

      dataset = Net::LDAP::Dataset.read_ldif(StringIO.new(sample.to_s))

      assert_equal(sample.dns.sort, dataset.keys.sort,
        "DN set mismatch for seed #{seed}:\n#{sample.annotated}")
      assert_attribution_matches_model(dataset, sample)
      assert_each_value_stays_with_its_dn(dataset, sample)
      assert_equal(sample.version, dataset.version,
        "version mismatch for seed #{seed}:\n#{sample.annotated}")

      # Write the parsed snapshot back out and parse again: serialization
      # must not move an attribute to a different DN either.
      rewritten = Net::LDAP::Dataset.read_ldif(StringIO.new(dataset.to_ldif_string))
      assert_attribution_matches_model(rewritten, sample)
      assert_each_value_stays_with_its_dn(rewritten, sample)
      assert_writer_lines_stay_under_their_dn(dataset, sample)
    end
  end

  def test_folding_comments_and_double_blanks_do_not_split_a_record
    alice = plain_record("cn=alice,dc=example,dc=com",
      [["hasAccessRole",
        [plain("alice-role-fold-continuation"), plain("alice-role-2")]]])
    bob = plain_record("cn=bob,dc=example,dc=com",
      [["hasAccessRole", [plain("bob-role-1")]]])
    sample = handwritten_sample([alice, bob]) do |builder|
      builder.emit_comment("leading comment")
      builder.emit_dn(alice, 0)
      builder.emit_raw("hasAccessRole: alice-role-fold-", 0)
      builder.emit_raw(" continuation", 0)
      builder.emit_raw("hasAccessRole: alice-role-2", 0)
      builder.emit_comment("comment inside the record", owner: 0)
      builder.emit_blank
      builder.emit_blank
      builder.emit_dn(bob, 1)
      builder.emit_raw("hasAccessRole: bob-role-1", 1)
    end

    dataset = Net::LDAP::Dataset.read_ldif(StringIO.new(sample.to_s))
    assert_attribution_matches_model(dataset, sample)
    assert_each_value_stays_with_its_dn(dataset, sample)
  end

  def test_folded_base64_attribute_and_dn_round_trip_by_owner
    binary = "binary-anchor-\x01\xFE".b
    record = LdifRecord.new("cn=carol,dc=example,dc=com", :base64, true,
      [["jpegPhoto", [LdifValue.new(binary, :base64, true)]]])
    sample = handwritten_sample([record]) do |builder|
      builder.emit_dn(record, 0)
      builder.emit_attribute("jpegPhoto", record.attrs[0][1][0], 0)
      builder.emit_blank
    end

    dataset = Net::LDAP::Dataset.read_ldif(StringIO.new(sample.to_s))
    assert_attribution_matches_model(dataset, sample)
    rewritten = Net::LDAP::Dataset.read_ldif(StringIO.new(dataset.to_ldif_string))
    assert_attribution_matches_model(rewritten, sample)
  end

  def test_plain_folded_value_containing_colons_and_equals
    record = plain_record("cn=dave,dc=example,dc=com",
      [["member", [LdifValue.new("uid=dave:group=a=b", :plain, false)]]])
    sample = handwritten_sample([record]) do |builder|
      builder.emit_dn(record, 0)
      builder.emit_raw("member: uid=dave:gro", 0)
      builder.emit_raw(" up=a=b", 0)
      builder.emit_blank
    end

    dataset = Net::LDAP::Dataset.read_ldif(StringIO.new(sample.to_s))
    assert_attribution_matches_model(dataset, sample)
  end

  def test_empty_value_and_unterminated_final_record
    record = plain_record("cn=erin,dc=example,dc=com",
      [["description", [LdifValue.new("", :plain, false)]],
       ["cn", [plain("erin")]]])
    sample = handwritten_sample([record]) do |builder|
      builder.emit_dn(record, 0)
      builder.emit_raw("description:", 0)
      builder.emit_raw("cn: erin", 0)
    end

    dataset = Net::LDAP::Dataset.read_ldif(StringIO.new(sample.to_s))
    assert_attribution_matches_model(dataset, sample)
  end

  # ----------------------------------------------------------------
  # Negative tests: malformed LDIF must not be reported as a clean
  # import. The required contract is Net::LDAP::LdifError, raised with
  # the offending physical line number in the message.
  # ----------------------------------------------------------------

  def test_invalid_base64_attribute_is_rejected_with_line_number
    bad_line = "cn:: @@@not-base64@@@"
    sample = malformed_sample do |builder|
      builder.emit_raw("dn: cn=base64-attr,dc=example,dc=com", 0)
      builder.emit_raw(bad_line, 0)
      builder.emit_blank
    end
    assert_parse_rejected(sample, bad_line, "invalid base64 attribute")
  end

  def test_invalid_base64_dn_is_rejected_with_line_number
    bad_line = "dn:: @@@not-base64@@@"
    sample = malformed_sample do |builder|
      builder.emit_raw(bad_line, 0)
      builder.emit_raw("cn: orphaned-by-bad-dn", 0)
      builder.emit_blank
    end
    assert_parse_rejected(sample, bad_line, "invalid base64 DN")
  end

  def test_invalid_base64_hidden_in_folded_value_is_rejected
    bad_line = "cn:: @@@not"
    sample = malformed_sample do |builder|
      builder.emit_raw("dn: cn=folded-bad,dc=example,dc=com", 0)
      builder.emit_raw(bad_line, 0)
      builder.emit_raw(" base64@@@", 0)
      builder.emit_blank
    end
    assert_parse_rejected(sample, bad_line, "invalid base64 inside folded value")
  end

  def test_duplicate_dn_is_rejected_instead_of_silently_overwritten
    duplicate_dn_line = "dn: cn=dup,dc=example,dc=com"
    sample = malformed_sample do |builder|
      builder.emit_raw(duplicate_dn_line, 0)
      builder.emit_raw("hasAccessRole: first-record-permission", 0)
      builder.emit_blank
      builder.emit_raw(duplicate_dn_line, 1)
      builder.emit_raw("hasAccessRole: second-record-permission", 1)
      builder.emit_blank
    end
    assert_parse_rejected(sample, duplicate_dn_line, "duplicate DN", occurrence: 2)
  end

  def test_attribute_before_any_dn_is_rejected
    orphan_line = "hasAccessRole: permission-with-no-record"
    sample = malformed_sample do |builder|
      builder.emit_raw(orphan_line, :orphan)
      builder.emit_blank
      builder.emit_raw("dn: cn=has-parent,dc=example,dc=com", 0)
      builder.emit_raw("cn: has-parent", 0)
      builder.emit_blank
    end
    assert_parse_rejected(sample, orphan_line,
      "attribute without a owning DN")
  end

  def test_orphan_attribute_after_blank_line_is_rejected
    orphan_line = "hasAccessRole: orphan-permission"
    sample = malformed_sample do |builder|
      builder.emit_raw("dn: cn=first,dc=example,dc=com", 0)
      builder.emit_raw("cn: first", 0)
      builder.emit_blank
      builder.emit_raw(orphan_line, :orphan)
      builder.emit_blank
      builder.emit_raw("dn: cn=second,dc=example,dc=com", 1)
      builder.emit_raw("cn: second", 1)
      builder.emit_blank
    end
    assert_parse_rejected(sample, orphan_line,
      "attribute after a record separator with no owning DN")
  end

  def test_folding_onto_the_next_dn_line_is_rejected
    crossing_line = " hasAccessRole: target-permission"
    sample = malformed_sample do |builder|
      builder.emit_raw("dn: cn=fold-source,dc=example,dc=com", 0)
      builder.emit_raw("hasAccessRole: source-permission", 0)
      builder.emit_raw("dn: cn=fold-target,dc=example,dc=com", 1)
      builder.emit_raw(crossing_line, 1)
      builder.emit_blank
    end
    assert_parse_rejected(sample, crossing_line,
      "continuation line folding across a DN boundary")
  end

  def test_folding_after_a_separator_blank_is_rejected
    smuggled_line = " hasAccessRole: smuggled-permission"
    sample = malformed_sample do |builder|
      builder.emit_raw("dn: cn=blank-fold,dc=example,dc=com", 0)
      builder.emit_raw("hasAccessRole: kept-permission", 0)
      builder.emit_blank
      builder.emit_raw(smuggled_line, :orphan)
      builder.emit_blank
      builder.emit_raw("dn: cn=next-record,dc=example,dc=com", 1)
      builder.emit_raw("cn: next-record", 1)
      builder.emit_blank
    end
    assert_parse_rejected(sample, smuggled_line,
      "continuation line after a record-separating blank line")
  end

  private

  def plain_record(dn, attrs, dn_encoding: :plain)
    LdifRecord.new(dn, dn_encoding, false, attrs)
  end

  def plain(text)
    LdifValue.new(text, :plain, false)
  end

  # The model records are supplied explicitly; the block only decides how
  # the physical lines are rendered, so the expected attribution is taken
  # from the independent model rather than reconstructed from the text.
  def handwritten_sample(records)
    builder = LdifBuilder.new
    yield builder
    builder.build(records)
  end

  # Malformed documents have no trustworthy logical record, so the expected
  # model stays empty and physical lines carry their intended owner (or
  # :orphan) purely for the annotated failure output.
  def malformed_sample
    builder = LdifBuilder.new
    yield builder
    builder.build([])
  end

  def assert_parse_rejected(sample, evidence_line, reason, occurrence: 1)
    unless Net::LDAP.const_defined?(:LdifError)
      flunk("LDIF parser has no Net::LDAP::LdifError contract, so #{reason} " \
        "cannot be rejected explicitly:\n#{sample.annotated}")
    end

    begin
      Net::LDAP::Dataset.read_ldif(StringIO.new(sample.to_s))
    rescue Net::LDAP::LdifError => error
      line_number = sample.line_number(evidence_line, occurrence: occurrence)
      assert_match(/line/i, error.message,
        "LdifError for #{reason} does not name a physical line:\n#{sample.annotated}")
      assert_match(/\b#{line_number}\b/, error.message,
        "LdifError for #{reason} names the wrong line (expected #{line_number}):" \
          "\n#{error.message}\n#{sample.annotated}")
      return
    rescue => error
      flunk("parser raised an opaque #{error.class} for #{reason} instead of " \
        "Net::LDAP::LdifError: #{error.message}\n#{sample.annotated}")
    end

    flunk("parser accepted #{reason} and reported success:\n#{sample.annotated}")
  end
end
