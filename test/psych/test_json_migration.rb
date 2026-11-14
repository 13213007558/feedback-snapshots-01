# frozen_string_literal: true
require_relative 'helper'
require 'json'

module Psych
  module JSON
    class TestMigration < TestCase
      # A permission config mixing allow and deny rules.  Migrating it
      # must not overwrite a deny entry, and must not turn a value the
      # migrator does not understand into null.
      MIXED_POLICY = <<~YAML
        ---
        service: api-gateway
        defaults:
          action: deny
          log: true
          retries: 3
          timeout: 0.5
          note: null
        rules:
          - action: allow
            resource: /public/*
            methods: [GET, HEAD]
          - action: deny
            resource: /admin/*
            methods: [POST, DELETE]
            reason: "restricted: admin only"
      YAML

      def test_mixed_allow_deny_config_migrates_losslessly
        data = ::JSON.parse Psych::JSON.migrate(MIXED_POLICY)

        assert_equal 'deny', data['defaults']['action']
        assert_equal true, data['defaults']['log']
        assert_equal 3, data['defaults']['retries']
        assert_equal 0.5, data['defaults']['timeout']
        assert_nil data['defaults']['note']

        allow, deny = data['rules']
        assert_equal 'allow', allow['action']
        assert_equal '/public/*', allow['resource']
        assert_equal %w[GET HEAD], allow['methods']
        assert_equal 'deny', deny['action']
        assert_equal '/admin/*', deny['resource']
        assert_equal %w[POST DELETE], deny['methods']
        assert_equal 'restricted: admin only', deny['reason']
      end

      def test_migration_matches_safe_load_for_safe_documents
        assert_equal Psych.safe_load(MIXED_POLICY),
                     ::JSON.parse(Psych::JSON.migrate(MIXED_POLICY))
      end

      def test_output_is_valid_json_text
        json = Psych::JSON.migrate MIXED_POLICY
        assert_kind_of String, json
        assert_equal Encoding::UTF_8, json.encoding
        assert_nothing_raised { ::JSON.parse json }
      end

      def test_duplicate_key_is_rejected_instead_of_overwriting_deny
        yaml = <<~YAML
          action: allow
          action: deny
        YAML
        error = assert_raise(Psych::JSON::MigrationError) { Psych::JSON.migrate yaml }
        assert_equal '$.action', error.path
        assert_match(/duplicate key "action"/, error.reason)
      end

      def test_unknown_value_is_an_error_not_null
        yaml = <<~YAML
          rules:
            - action: allow
            - action: deny
              schedule: 2024-01-01
        YAML
        error = assert_raise(Psych::JSON::MigrationError) { Psych::JSON.migrate yaml }
        assert_equal '$.rules[1].schedule', error.path
        assert_match(/Date/, error.reason)
      end

      def test_merge_key_is_rejected
        yaml = <<~YAML
          base: &base
            action: deny
          rules:
            - <<: *base
              resource: /public
        YAML
        error = assert_raise(Psych::JSON::MigrationError) { Psych::JSON.migrate yaml }
        assert_equal '$.rules[0]', error.path
        assert_match(/merge key/, error.reason)
      end

      def test_quoted_merge_key_is_a_plain_string
        assert_equal({ '<<' => 1 }, ::JSON.parse(Psych::JSON.migrate(%q{"<<": 1})))
      end

      def test_shared_reference_is_rejected
        yaml = <<~YAML
          allow: &shared
            resource: /a
          deny: *shared
        YAML
        error = assert_raise(Psych::JSON::MigrationError) { Psych::JSON.migrate yaml }
        assert_equal '$.deny', error.path
        assert_match(/shared reference '\*shared'/, error.reason)
      end

      def test_circular_reference_is_rejected
        error = assert_raise(Psych::JSON::MigrationError) { Psych::JSON.migrate("&a\n- *a\n") }
        assert_equal '$[0]', error.path
        assert_match(/circular reference/, error.reason)
      end

      def test_unknown_anchor_is_rejected
        error = assert_raise(Psych::JSON::MigrationError) { Psych::JSON.migrate('*nope') }
        assert_match(/unknown anchor/, error.reason)
      end

      def test_scalar_alias_expands_losslessly
        yaml = <<~YAML
          allow: &level read-only
          deny: *level
        YAML
        assert_equal({ 'allow' => 'read-only', 'deny' => 'read-only' },
                     ::JSON.parse(Psych::JSON.migrate(yaml)))
      end

      def test_non_string_key_is_rejected
        error = assert_raise(Psych::JSON::MigrationError) { Psych::JSON.migrate("1: one") }
        assert_equal '$', error.path
        assert_match(/non-string mapping key "1" \(Integer\)/, error.reason)
      end

      def test_key_colliding_after_stringification_is_reported
        error = assert_raise(Psych::JSON::MigrationError) { Psych::JSON.migrate('{"1": str, 1: int}') }
        assert_equal '$', error.path
        assert_match(/collide with the existing key "1"/, error.reason)
      end

      def test_complex_mapping_key_is_rejected
        error = assert_raise(Psych::JSON::MigrationError) { Psych::JSON.migrate("? [a, b]\n: value\n") }
        assert_match(/mapping key is a Sequence/, error.reason)
      end

      def test_non_finite_floats_are_rejected
        { '.nan' => '$.score', '.inf' => '$.score', '-.inf' => '$.score' }.each do |literal, path|
          error = assert_raise(Psych::JSON::MigrationError) { Psych::JSON.migrate("score: #{literal}") }
          assert_equal path, error.path
          assert_match(/non-finite float/, error.reason)
        end
      end

      def test_symbol_is_rejected
        error = assert_raise(Psych::JSON::MigrationError) { Psych::JSON.migrate('action: :deny') }
        assert_equal '$.action', error.path
        assert_match(/symbol :deny/, error.reason)
      end

      def test_unknown_tag_is_rejected_without_calling_object_hooks
        hooked = Class.new do
          define_singleton_method(:yaml_new) { |*| $migration_hook_called = true }
          define_singleton_method(:name) { 'MigrationHooked' }
        end
        stub_const = Object.const_set :MigrationHooked, hooked
        begin
          $migration_hook_called = false
          error = assert_raise(Psych::JSON::MigrationError) do
            Psych::JSON.migrate("--- !ruby/object:MigrationHooked {}\n")
          end
          assert_match(/unsupported tag/, error.reason)
          refute $migration_hook_called, 'custom object hook must not be invoked'
        ensure
          Object.send :remove_const, :MigrationHooked
        end
      end

      def test_binary_and_set_tags_are_rejected
        error = assert_raise(Psych::JSON::MigrationError) { Psych::JSON.migrate('payload: !!binary aGk=') }
        assert_equal '$.payload', error.path
        assert_match(/unsupported tag/, error.reason)

        error = assert_raise(Psych::JSON::MigrationError) { Psych::JSON.migrate("!!set\n? a\n? b\n") }
        assert_match(/unsupported tag/, error.reason)
      end

      def test_tag_value_mismatch_is_rejected
        error = assert_raise(Psych::JSON::MigrationError) { Psych::JSON.migrate('!!int hello') }
        assert_match(/does not match its tag/, error.reason)
      end

      def test_core_schema_tags_are_supported
        data = ::JSON.parse Psych::JSON.migrate(<<~YAML)
          "str": !!str 007
          "int": !!int "42"
          "float": !!float "0.5"
          "bool": !!bool "true"
          "null": !!null ""
        YAML
        assert_equal({ 'str' => '007', 'int' => 42, 'float' => 0.5, 'bool' => true, 'null' => nil }, data)
      end

      def test_quoted_scalars_stay_strings
        data = ::JSON.parse Psych::JSON.migrate(<<~YAML)
          a: "yes"
          b: "123"
          c: "null"
        YAML
        assert_equal({ 'a' => 'yes', 'b' => '123', 'c' => 'null' }, data)
      end

      def test_multiple_documents_are_rejected
        error = assert_raise(Psych::JSON::MigrationError) { Psych::JSON.migrate("--- 1\n--- 2\n") }
        assert_equal '$', error.path
        assert_match(/single YAML document/, error.reason)
      end

      def test_safe_types_subset_is_explicit
        assert_equal [NilClass, TrueClass, FalseClass, Integer, Float, String, Array, Hash],
                     Psych::JSON::SAFE_TYPES
      end

      def test_strings_are_json_escaped
        data = ::JSON.parse Psych::JSON.migrate(%Q{msg: "a\\"b\\\\c\\u0001d"})
        assert_equal "a\"b\\c\u0001d", data['msg']
      end
    end
  end
end
