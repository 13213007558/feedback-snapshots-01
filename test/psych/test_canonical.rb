# frozen_string_literal: true
require_relative 'helper'

module Psych
  class TestCanonical < TestCase
    # ------------------------------------------------------------------
    # Independent vectors: canonical bytes and SHA-256 hex digests were
    # computed by hand / with an external tool (shasum -a 256), not by
    # the implementation under test.
    # ------------------------------------------------------------------

    # Vector 1: three equivalent writings of the same policy.
    V1_CANONICAL = <<~CANONICAL
      YCANON/1
      {"effective":{"name":"default","rules":["allow","deny"]},"policy":{"name":"default","rules":["allow","deny"]},"version":1}
    CANONICAL
    V1_DIGEST = "50002cdab7b57f48b172f1f6631f02e57a518747e216fb9946b63bd0828211e0"

    # Vector 2: string "false" and boolean false are different values.
    V2_STRING_CANONICAL = "YCANON/1\n{\"flag\":\"false\"}\n"
    V2_STRING_DIGEST    = "26ea1865b7453f32ac8014a32151ddf12d5b139f99a0863d73bcb254030cde15"
    V2_BOOL_CANONICAL   = "YCANON/1\n{\"flag\":false}\n"
    V2_BOOL_DIGEST      = "4c7406b499b96f011f1ffa50a3c1da005d55cd29876f5ead3d8abf44b14aa45d"

    # Vector 3: a merge key overridden by an explicit key digests to the
    # same bytes as writing the effective mapping out literally.
    V3_CANONICAL = <<~CANONICAL
      YCANON/1
      {"policy":{"defaults":{"action":"deny","log":true},"effective":{"action":"allow","log":true}}}
    CANONICAL
    V3_DIGEST = "b522e362bd0571fa852d184fb72c42e6b918e29d922281d0871b46cb2b067bc6"

    V1_BLOCK = <<~YAML
      # security policy, draft 3
      policy: &main
        name: default
        rules:
          - allow
          - deny
      effective: *main
      version: 1
    YAML

    # Same content as V1_BLOCK: different comments, indentation, key
    # order, flow style, and a different anchor name.
    V1_FLOW = <<~YAML
      version: 1
      policy: &cfg
        rules: [allow, deny]   # inline comment, flow style
        name: default
      effective: *cfg
    YAML

    # Same content again, using a merge key instead of an alias.
    V1_MERGE = <<~YAML
      version: 1
      policy: &p
        name: default
        rules: [allow, deny]
      effective:
        <<: *p
    YAML

    def test_vector1_equivalent_writings_share_one_digest
      assert_equal V1_CANONICAL, Canonical.canonicalize(V1_BLOCK)
      assert_equal V1_DIGEST, Canonical.digest(V1_BLOCK)
      assert_equal V1_DIGEST, Canonical.digest(V1_FLOW)
      assert_equal V1_DIGEST, Canonical.digest(V1_MERGE)
    end

    def test_vector2_string_false_and_boolean_false_differ
      assert_equal V2_STRING_CANONICAL, Canonical.canonicalize(%(flag: "false"\n))
      assert_equal V2_STRING_DIGEST, Canonical.digest(%(flag: "false"\n))
      assert_equal V2_BOOL_CANONICAL, Canonical.canonicalize("flag: false\n")
      assert_equal V2_BOOL_DIGEST, Canonical.digest("flag: false\n")
      refute_equal V2_STRING_DIGEST, V2_BOOL_DIGEST
    end

    def test_vector3_overridden_merge_key_matches_literal_writing
      merged = <<~YAML
        policy:
          defaults: &d
            action: deny
            log: true
          effective:
            <<: *d
            action: allow
      YAML
      literal = <<~YAML
        policy:
          defaults: {action: deny, log: true}
          effective: {action: allow, log: true}
      YAML
      assert_equal V3_CANONICAL, Canonical.canonicalize(merged)
      assert_equal V3_DIGEST, Canonical.digest(merged)
      assert_equal V3_DIGEST, Canonical.digest(literal)
    end

    def test_overridden_value_does_not_leak_into_digest
      # If the overridden "deny" leaked into the digest, this would
      # accidentally match V3.
      without_override = <<~YAML
        policy:
          defaults: &d
            action: deny
            log: true
          effective:
            <<: *d
      YAML
      refute_equal V3_DIGEST, Canonical.digest(without_override)
    end

    def test_version_is_explicit_and_checked
      assert_equal 1, Canonical::VERSION
      assert_equal Canonical.digest("a: 1\n"), Canonical.digest("a: 1\n", version: 1)
      assert_raise(ArgumentError) { Canonical.digest("a: 1\n", version: 2) }
      assert_raise(ArgumentError) { Canonical.canonicalize("a: 1\n", version: 0) }
    end

    def test_format_header_binds_digest_to_version
      assert_equal "YCANON/1\n", Canonical::FORMAT_HEADER
      assert Canonical.canonicalize("a: 1\n").start_with?("YCANON/1\n")
    end

    def test_yaml_11_bool_lookalikes_are_strings
      assert_equal "YCANON/1\n{\"flag\":\"yes\"}\n", Canonical.canonicalize("flag: yes\n")
      assert_equal "YCANON/1\n{\"flag\":\"off\"}\n", Canonical.canonicalize("flag: off\n")
    end

    def test_scalar_normalization
      canonical = Canonical.canonicalize("hex: 0x10\noct: 0o17\nneg: -3\nfloat: 1.0\nnil1: ~\nnil2:\n")
      assert_equal "YCANON/1\n{\"float\":1.0,\"hex\":16,\"neg\":-3,\"nil1\":null,\"nil2\":null,\"oct\":15}\n", canonical
    end

    def test_int_and_float_are_distinct
      refute_equal Canonical.digest("n: 1\n"), Canonical.digest("n: 1.0\n")
    end

    def test_string_escaping
      assert_equal "YCANON/1\n\"a\\nb\\t\\\"c\\\"\"\n",
                   Canonical.canonicalize(%("a\\nb\\t\\"c\\""\n))
    end

    def test_cycle_is_rejected
      assert_raise(Canonical::CycleError) do
        Canonical.digest("a: &x\n  self: *x\n")
      end
    end

    def test_cycle_through_merge_is_rejected
      assert_raise(Canonical::CycleError) do
        Canonical.digest("a: &x\n  <<: *x\n")
      end
    end

    def test_unknown_tags_are_rejected
      assert_raise(Canonical::UnsupportedTagError) { Canonical.digest("!custom thing\n") }
      assert_raise(Canonical::UnsupportedTagError) { Canonical.digest("!!binary aGk=\n") }
      assert_raise(Canonical::UnsupportedTagError) { Canonical.digest("!!set {a, b}\n") }
    end

    def test_core_tags_are_accepted
      assert_equal "YCANON/1\n{\"b\":true,\"i\":7,\"s\":\"7\"}\n",
                   Canonical.canonicalize("b: !!bool true\ni: !!int 7\ns: !!str 7\n")
    end

    def test_duplicate_keys_are_rejected
      assert_raise(Canonical::DuplicateKeyError) { Canonical.digest("a: 1\na: 2\n") }
    end

    def test_merge_conflict_is_rejected
      yaml = <<~YAML
        m1: &m1
          k: 1
        m2: &m2
          k: 2
        top:
          <<: [*m1, *m2]
      YAML
      assert_raise(Canonical::MergeConflictError) { Canonical.digest(yaml) }
    end

    def test_non_string_keys_are_rejected
      assert_raise(Canonical::KeyTypeError) { Canonical.digest("1: x\n") }
      assert_raise(Canonical::KeyTypeError) { Canonical.digest("true: x\n") }
      assert_raise(Canonical::KeyTypeError) { Canonical.digest("? [a, b]\n: x\n") }
    end

    def test_non_finite_floats_are_rejected
      assert_raise(Canonical::UnrepresentableValueError) { Canonical.digest("x: .inf\n") }
      assert_raise(Canonical::UnrepresentableValueError) { Canonical.digest("x: .nan\n") }
    end

    def test_multi_document_stream_is_rejected
      assert_raise(Canonical::InvalidDocumentError) { Canonical.digest("---\na\n---\nb\n") }
    end

    def test_empty_document_is_null
      assert_equal "YCANON/1\nnull\n", Canonical.canonicalize("# only a comment\n")
    end
  end
end
