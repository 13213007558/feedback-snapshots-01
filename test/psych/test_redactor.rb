# frozen_string_literal: true
require_relative 'helper'

module Psych
  class TestRedactor < TestCase
    def test_redacts_requested_scalar_and_keeps_unrelated_content
      result = redact(<<~YAML, [["db", "password"]])
        db:
          host: db.example.com
          password: hunter2
      YAML

      loaded = Psych.unsafe_load(result.yaml)
      assert_equal "[REDACTED]", loaded["db"]["password"]
      assert_equal "db.example.com", loaded["db"]["host"]
      refute_includes result.yaml, "hunter2"
    end

    def test_alias_sharing_same_scalar_is_redacted_everywhere
      yaml = <<~YAML
        primary: &conn
          password: hunter2
        replica: *conn
      YAML
      result = redact(yaml, [["primary", "password"]])

      loaded = Psych.unsafe_load(result.yaml)
      assert_equal "[REDACTED]", loaded["primary"]["password"]
      assert_equal "[REDACTED]", loaded["replica"]["password"]
      refute_includes result.yaml, "hunter2"

      shared = result.additional_paths.find { |entry| entry.path == %w[replica password] }
      assert shared
      assert_equal :contained, shared.reason
    end

    def test_shared_container_alias_is_reported_as_alias
      yaml = <<~YAML
        pool: &pool
          - secret-a
          - secret-b
        mirror: *pool
      YAML
      result = redact(yaml, [["pool"]])

      entry = result.hidden_paths.find { |item| item.path == ["mirror"] }
      assert entry
      assert_equal :alias, entry.reason
      refute_includes result.yaml, "secret-a"
      refute_includes result.yaml, "secret-b"
    end

    def test_cycle_back_edge_is_reported_and_emittable
      yaml = <<~YAML
        ring: &ring
          label: secret-label
          loopback: *ring
      YAML
      result = redact(yaml, [["ring"]])

      cycle = result.hidden_paths.find { |entry| entry.reason == :cycle }
      assert cycle
      assert_equal %w[ring loopback], cycle.path
      # The output must parse even though the anchor is now a redacted scalar
      # and the back edge points at that scalar.
      loaded = Psych.unsafe_load(result.yaml)
      assert_equal "[REDACTED]", loaded["ring"]
      refute_includes result.yaml, "secret-label"
    end

    def test_sensitive_mapping_key_is_redacted_but_value_kept
      yaml = <<~YAML
        headers:
          X-Api-Key: plain-value
      YAML
      path = ["headers", "X-Api-Key", Psych::Redactor::KEY]
      result = redact(yaml, [path])

      loaded = Psych.unsafe_load(result.yaml)
      assert_equal ["[REDACTED]"], loaded["headers"].keys
      assert_equal "plain-value", loaded["headers"].values.first
      refute_includes result.yaml, "X-Api-Key"

      requested = result.hidden_paths.find { |entry| entry.reason == :requested }
      assert_equal :key, requested.role
    end

    def test_explicit_merge_override_is_redacted_without_touching_merge_source_path
      yaml = <<~YAML
        base: &base
          user: admin
          password: base-secret
        derived:
          <<: *base
          password: override-secret
      YAML
      result = redact(yaml, [["derived", "password"]])

      loaded = Psych.unsafe_load(result.yaml)
      assert_equal "[REDACTED]", loaded["derived"]["password"]
      assert_equal "admin", loaded["derived"]["user"]
      refute_includes result.yaml, "override-secret"
      # Only the requested explicit value is hidden; base keeps its own secret
      # unless that path was requested too.
      assert_equal "base-secret", loaded["base"]["password"]
    end

    def test_merged_only_sensitive_field_is_hidden_and_reported_as_merge
      yaml = <<~YAML
        base: &base
          user: admin
          api_token: shared-token
        derived:
          <<: *base
      YAML
      result = redact(yaml, [["base", "api_token"]])

      loaded = Psych.unsafe_load(result.yaml)
      assert_equal "[REDACTED]", loaded["derived"]["api_token"]
      assert_equal "admin", loaded["derived"]["user"]
      entry = result.hidden_paths.find { |item| item.reason == :merge }
      assert entry
      assert_equal ["derived", "<<", "api_token"], entry.path
      refute_includes result.yaml, "shared-token"
    end

    def test_string_tagged_chevron_is_not_treated_as_merge
      yaml = <<~YAML
        box:
          !!str '<<': kept-value
      YAML
      result = redact(yaml, [["box", "<<"]])

      loaded = Psych.unsafe_load(result.yaml)
      assert_equal "[REDACTED]", loaded["box"]["<<"]
      refute_includes result.yaml, "kept-value"
      assert_empty result.hidden_paths.select { |entry| entry.reason == :merge }
    end

    def test_sequence_index_paths
      yaml = <<~YAML
        items:
          - public
          - secret
      YAML
      result = redact(yaml, [["items", 1]])

      loaded = Psych.unsafe_load(result.yaml)
      assert_equal ["public", "[REDACTED]"], loaded["items"]
    end

    def test_does_not_mutate_the_original_parsed_tree
      yaml = <<~YAML
        db: &db
          password: hunter2
        alias: *db
      YAML
      original = Psych.parse(yaml)
      redact(original, [["db", "password"]])

      loaded = original.to_ruby
      assert_equal "hunter2", loaded["db"]["password"]
      assert_same loaded["db"], loaded["alias"]
      assert_includes Psych.dump(loaded), "hunter2"
    end

    def test_missing_path_fails_closed
      assert_raise Psych::Redactor::PathNotFound do
        redact("db:\n  host: localhost\n", [["db", "password"]])
      end
    end

    def test_invalid_path_shape_is_rejected
      assert_raise ArgumentError do
        redact("a: b\n", [["a", :nope]])
      end
    end

    def test_custom_replacement
      result = redact("password: hunter2\n", [["password"]], replacement: "***")
      assert_includes result.yaml, '"***"'
      refute_includes result.yaml, "hunter2"
    end

    def test_multiple_documents_stream
      yaml = "---\npassword: one\n---\npassword: two\n"
      result = Psych::Redactor.redact(Psych.parse_stream(yaml), paths: [["password"]])

      assert_instance_of Psych::Nodes::Stream, result.tree
      docs = Psych.parse_stream(result.yaml).children
      assert_equal ["[REDACTED]", "[REDACTED]"], docs.map { |doc| doc.to_ruby["password"] }
    end

    def test_every_reachable_value_is_walked_after_reparse
      yaml = <<~YAML
        shared: &s
          password: hunter2
        via_alias: *s
        via_merge:
          <<: *s
      YAML
      result = redact(yaml, [["shared", "password"]])
      loaded = Psych.unsafe_load(result.yaml)
      values = walk_values(loaded)

      refute_includes values, "hunter2"
      assert_includes values, "[REDACTED]"
      # Alias and merge both resolve back to the same redacted shared object.
      assert_same loaded["shared"]["password"], loaded["via_alias"]["password"]
      assert_equal "[REDACTED]", loaded["via_merge"]["password"]
      assert_equal 1, values.count("[REDACTED]")
    end

    def test_merge_sequence_hides_shared_secret
      yaml = <<~YAML
        a: &a
          token: token-a
        b: &b
          token: token-b
        merged:
          <<: [*a, *b]
      YAML
      result = redact(yaml, [["a", "token"], ["b", "token"]])

      loaded = Psych.unsafe_load(result.yaml)
      assert_equal "[REDACTED]", loaded["merged"]["token"]
      refute_includes result.yaml, "token-a"
      refute_includes result.yaml, "token-b"
      assert result.hidden_paths.any? { |entry| entry.reason == :merge }
    end

    def test_anchor_on_sensitive_scalar_keeps_valid_alias
      yaml = <<~YAML
        password: &pw hunter2
        again: *pw
      YAML
      result = redact(yaml, [["password"]])

      loaded = Psych.unsafe_load(result.yaml)
      assert_same loaded["password"], loaded["again"]
      assert_equal "[REDACTED]", loaded["again"]
      refute_includes result.yaml, "hunter2"
    end

    def test_root_path_redacts_entire_document
      result = redact(<<~YAML, [[]])
        keep: no
        secret: yes
      YAML

      assert_equal "[REDACTED]", Psych.unsafe_load(result.yaml)
      refute_includes result.yaml, "secret"
    end

    def test_key_path_missing_fails_closed
      assert_raise Psych::Redactor::PathNotFound do
        redact("headers:\n  Other: x\n", [["headers", "X-Api-Key", Psych::Redactor::KEY]])
      end
    end

    def test_empty_input_is_rejected_with_argument_error
      assert_raise ArgumentError do
        redact("", [["anything"]])
      end
    end

    def test_aliased_sensitive_key_resolves_to_redacted_anchor
      yaml = <<~YAML
        secret_key: &sk hunter2
        map:
          *sk: value
      YAML
      result = redact(yaml, [["secret_key"]])

      loaded = Psych.unsafe_load(result.yaml)
      assert_equal ["[REDACTED]"], loaded["map"].keys
      refute_includes result.yaml, "hunter2"
    end

    def test_nested_merge_explicit_override_is_not_reported_as_merge
      yaml = <<~YAML
        base: &base
          password: base-secret
        child:
          <<: *base
          password: child-secret
      YAML
      result = redact(yaml, [["base", "password"]])

      # The child's explicit password overrides the merge and is not itself
      # requested, so it must remain visible while the base anchor is hidden.
      loaded = Psych.unsafe_load(result.yaml)
      assert_equal "child-secret", loaded["child"]["password"]
      assert_equal "[REDACTED]", loaded["base"]["password"]
      merge_entries = result.hidden_paths.select { |entry| entry.reason == :merge }
      assert_empty merge_entries
    end

    private

    def redact(yaml_or_tree, paths, replacement: Psych::Redactor::DEFAULT_REPLACEMENT)
      Psych::Redactor.redact(yaml_or_tree, paths: paths, replacement: replacement)
    end

    def walk_values(object, seen = {}.compare_by_identity, output = [])
      return output if seen.key?(object)
      seen[object] = true
      case object
      when Hash
        object.each do |key, value|
          output << key unless key.is_a?(Hash) || key.is_a?(Array)
          walk_values(value, seen, output)
        end
      when Array
        object.each { |item| walk_values(item, seen, output) }
      else
        output << object
      end
      output
    end
  end
end
