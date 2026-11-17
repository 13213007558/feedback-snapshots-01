# frozen_string_literal: false
require File.expand_path('helper', File.dirname(__FILE__))
require 'psych'
require 'stringio'

# Regression tests for untrusted YAML cookie imports.
#
# The YAML saver must never trust a record just because its object tag
# is on the safe_load whitelist: YAML parsing is restricted to a fixed
# class whitelist, every decoded record is rebuilt and validated through
# the HTTP::Cookie setters, and a failure on any record aborts the whole
# import without mutating the existing jar.
class TestYAMLSaverSecurity < Test::Unit::TestCase
  SAVER = HTTP::CookieJar::YAMLSaver

  def load_yaml(yaml, jar = HTTP::CookieJar.new)
    jar.load(StringIO.new(yaml), :yaml)
    jar
  end

  def load_fixture(name, jar = HTTP::CookieJar.new)
    jar.load(test_file(File.join('fixtures', name)), :yaml)
    jar
  end

  # A valid cookie in both the modern Array form and the legacy
  # Mechanize nested-Hash form, reused by the happy-path tests.
  MODERN_COOKIE = <<~YAML.freeze
    ---
    - !ruby/object:HTTP::Cookie
      name: session
      value: abc123
      domain: example.org
      for_domain: true
      path: /
      secure: false
      httponly: true
      expires: 2099-01-01 00:00:00 Z
  YAML

  LEGACY_COOKIE = <<~YAML.freeze
    ---
    example.org:
      /:
        session:
          name: session
          value: abc123
          domain: example.org
          for_domain: true
          path: /
          secure: false
          httponly: true
          expires: Thu, 01 Jan 2099 00:00:00 GMT
          max_age:
          created_at: 2090-01-01 00:00:00 Z
          accessed_at: 2090-01-01 00:00:00 Z
  YAML

  # ------------------------------------------------------------------
  # The restricted entry point
  # ------------------------------------------------------------------

  def test_safe_load_whitelist_is_fixed
    assert_equal %w[Time HTTP::Cookie Mechanize::Cookie DomainName],
      SAVER::PERMITTED_CLASSES
    assert SAVER::PERMITTED_CLASSES.frozen?
  end

  def test_load_yaml_is_the_only_yaml_entry_point
    source = File.read(File.expand_path('../lib/http/cookie_jar/yaml_saver.rb',
      File.dirname(__FILE__)))
    assert_match(/YAML\.safe_load/, source)
    assert_no_match(/(^|[^_.])YAML\.load\b/, source)
    assert_no_match(/YAML\.unsafe_load/, source)
  end

  # ------------------------------------------------------------------
  # Arbitrary object tags: never instantiated, no custom behaviour
  # ------------------------------------------------------------------

  def test_arbitrary_object_tag_is_rejected
    assert_raise(Psych::DisallowedClass) {
      load_yaml("--- !ruby/object:File {}\n")
    }
  end

  def test_arbitrary_tag_fixture_is_rejected
    assert_raise(Psych::DisallowedClass) {
      load_fixture('arbitrary_tag.yml')
    }
  end

  def test_arbitrary_nested_tag_is_rejected
    payload = <<~YAML
      ---
      - !ruby/object:Net::WriteAdapter
        x: y
    YAML
    assert_raise(Psych::DisallowedClass) { load_yaml(payload) }
  end

  def test_gem_gadget_chain_is_rejected
    payload = <<~YAML
      --- !ruby/object:Gem::Requirement
      requirements: !ruby/object:Gem::Version
        version: '1.0'
    YAML
    assert_raise(Psych::DisallowedClass) { load_yaml(payload) }
  end

  def test_symbol_tag_is_rejected
    assert_raise(Psych::DisallowedClass) {
      load_yaml("--- :evil\n")
    }
  end

  def test_custom_object_hooks_are_never_run
    klass = Class.new {
      def initialize
        raise 'custom initialize must not run'
      end

      def yaml_initialize(*)
        raise 'custom yaml_initialize must not run'
      end
    }
    Object.const_set(:UntrustedImportGadget, klass)
    payload = "--- !ruby/object:UntrustedImportGadget\n  x: 1\n"
    assert_raise(Psych::DisallowedClass) { load_yaml(payload) }
  ensure
    Object.send(:remove_const, :UntrustedImportGadget)
  end

  # ------------------------------------------------------------------
  # Whitelisted tags are not trusted: forged attributes
  # ------------------------------------------------------------------

  def test_allowed_tag_with_forged_domain_is_rebuilt_and_scoped
    jar = load_yaml(MODERN_COOKIE)
    cookie = jar.to_a.first
    assert_instance_of HTTP::Cookie, cookie
    assert_equal 'example.org', cookie.domain
    assert_nil cookie.origin
    assert_equal true, cookie.for_domain?
    assert_equal true, cookie.httponly?
    assert_equal 1, jar.cookies('http://example.org/').size
    assert_equal 1, jar.cookies('http://www.example.org/').size
    assert_equal 0, jar.cookies('http://evil.test/').size
  end

  def test_allowed_tag_with_wrong_typed_domain_is_rejected
    payload = <<~YAML
      ---
      - !ruby/object:HTTP::Cookie
        name: x
        value: y
        domain: 12345
        path: /
    YAML
    assert_raise(TypeError) { load_yaml(payload) }
  end

  def test_allowed_tag_with_wrong_typed_path_is_rejected
    payload = <<~YAML
      ---
      - !ruby/object:HTTP::Cookie
        name: x
        value: y
        domain: a.example
        path: 777
    YAML
    assert_raise(TypeError) { load_yaml(payload) }
  end

  def test_allowed_tag_with_invalid_name_is_rejected
    payload = <<~YAML
      ---
      - !ruby/object:HTTP::Cookie
        name: "bad name"
        value: y
        domain: a.example
        path: /
    YAML
    assert_raise(ArgumentError) { load_yaml(payload) }
  end

  def test_allowed_tag_with_wrong_typed_expires_is_rejected
    payload = <<~YAML
      ---
      - !ruby/object:HTTP::Cookie
        name: x
        value: y
        domain: a.example
        path: /
        expires: 12345
    YAML
    assert_raise(TypeError) { load_yaml(payload) }
  end

  def test_allowed_tag_with_wrong_typed_max_age_is_rejected
    payload = <<~YAML
      ---
      - !ruby/object:HTTP::Cookie
        name: x
        value: y
        domain: a.example
        path: /
        max_age: "not-an-int"
    YAML
    assert_raise(ArgumentError) { load_yaml(payload) }
  end

  def test_array_element_that_is_not_a_cookie_is_rejected
    assert_raise(ArgumentError) { load_yaml("---\n- 1\n- 2\n") }
  end

  # ------------------------------------------------------------------
  # Alias sharing and cycles
  # ------------------------------------------------------------------

  def test_alias_shared_time_anchor_still_loads
    payload = <<~YAML
      ---
      - !ruby/object:HTTP::Cookie
        name: a
        value: v
        domain: example.org
        path: /
        created_at: &t 2030-01-01 00:00:00 Z
        accessed_at: *t
      - !ruby/object:HTTP::Cookie
        name: b
        value: w
        domain: example.org
        path: /
        created_at: *t
        accessed_at: *t
    YAML
    jar = load_yaml(payload)
    assert_equal 2, jar.to_a.size
    assert_equal [jar.to_a.first.created_at.object_id],
      jar.to_a.map(&:created_at).map(&:object_id).uniq
  end

  def test_missing_anchor_is_rejected
    # test-unit matches exception classes with instance_of?, so assert
    # the concrete class Psych raises for an unknown alias anchor.
    assert_raise(Psych::AnchorNotDefined) {
      load_fixture('bad_alias.yml')
    }
  end

  def test_cyclic_document_is_rejected_without_touching_the_jar
    # Psych decodes self-referential structures lazily; walking them as
    # cookie data must fail rather than hang or overflow the stack.
    payload = "---\nexample.org:\n  /:\n    c: &x\n      name: c\n      value: v\n      domain: example.org\n      path: /\n      loop: *x\n"
    jar = HTTP::CookieJar.new
    assert_raise(ArgumentError) { load_yaml(payload, jar) }
    assert jar.empty?
  end

  def test_alias_to_unspecified_class_is_rejected
    payload = "---\na: &t !ruby/object:File {}\nb: *t\n"
    assert_raise(Psych::DisallowedClass) { load_yaml(payload) }
  end

  # ------------------------------------------------------------------
  # Legacy Mechanize nested-Hash form
  # ------------------------------------------------------------------

  def test_legacy_mechanize_hash_migrates
    jar = load_yaml(LEGACY_COOKIE)
    assert_equal 1, jar.to_a.size
    cookie = jar.to_a.first
    assert_equal 'session', cookie.name
    assert_equal 'abc123', cookie.value
    assert_equal 'example.org', cookie.domain
    assert_equal '/', cookie.path
    assert_equal true, cookie.for_domain?
    assert_equal true, cookie.httponly?
    assert cookie.expires.is_a?(Time)
    assert_nil cookie.origin
    assert_equal 1, jar.cookies('http://www.example.org/').size
  end

  def test_legacy_mechanize_unknown_attribute_is_rejected
    payload = <<~YAML
      ---
      example.org:
        /:
          session:
            name: session
            value: abc123
            domain: example.org
            for_domain: true
            path: /
            httponly: true
            evil_field: pwn
            expires: Thu, 01 Jan 2099 00:00:00 GMT
    YAML
    err = assert_raise(ArgumentError) { load_yaml(payload) }
    assert_match(/unknown cookie attribute/, err.message)
  end

  def test_legacy_mechanize_non_boolean_flag_is_rejected
    payload = <<~YAML
      ---
      example.org:
        /:
          session:
            name: session
            value: abc123
            domain: example.org
            path: /
            secure: "yes"
    YAML
    err = assert_raise(ArgumentError) { load_yaml(payload) }
    assert_match(/expected true or false/, err.message)
  end

  def test_legacy_mechanize_non_time_value_is_rejected
    payload = <<~YAML
      ---
      example.org:
        /:
          session:
            name: session
            value: abc123
            domain: example.org
            path: /
            expires: 99
    YAML
    err = assert_raise(ArgumentError) { load_yaml(payload) }
    assert_match(/expected a Time or time String/, err.message)
  end

  def test_legacy_mechanize_unparsable_time_string_is_rejected
    payload = <<~YAML
      ---
      example.org:
        /:
          session:
            name: session
            value: abc123
            domain: example.org
            path: /
            expires: not a date
    YAML
    err = assert_raise(ArgumentError) { load_yaml(payload) }
    assert_match(/unparsable time/, err.message)
  end

  def test_legacy_mechanize_ignored_slot_cannot_smuggle_a_structure
    payload = <<~YAML
      ---
      example.org:
        /:
          session:
            name: session
            value: abc123
            domain: example.org
            path: /
            comment:
              nested: value
    YAML
    err = assert_raise(ArgumentError) { load_yaml(payload) }
    assert_match(/unexpected Hash/, err.message)
  end

  def test_legacy_mechanize_non_string_domain_key_is_rejected
    payload = "---\n5:\n  /:\n    c: {}\n"
    err = assert_raise(ArgumentError) { load_yaml(payload) }
    assert_match(/expected a String key/, err.message)
  end

  def test_legacy_mechanize_bad_nesting_is_rejected
    err = assert_raise(ArgumentError) {
      load_yaml("---\nexample.org: not-a-hash\n")
    }
    assert_match(/expected a Hash/, err.message)
  end

  def test_shipped_mechanize_fixture_still_loads
    jar = HTTP::CookieJar.new
    jar.load(test_file('mechanize.yml'), :yaml)
    assert_equal 4, jar.to_a.size
    assert_equal 2, jar.cookies('http://www.google.com/').size
    assert_equal 2, jar.cookies('http://www.google.co.jp/').size
    assert_equal 0, jar.cookies('http://www.example.org/').size
  end

  def test_legacy_mechanize_form_on_non_rewindable_io_fails_cleanly
    rd, wr = IO.pipe
    Thread.new {
      wr.write(File.read(test_file('mechanize.yml')))
      wr.close
    }
    jar = HTTP::CookieJar.new
    err = assert_raise(ArgumentError) { jar.load(rd, :yaml) }
    assert_match(/non-rewindable stream/, err.message)
    assert jar.empty?
  ensure
    rd.close unless rd.closed?
  end

  # ------------------------------------------------------------------
  # Mid-stream bad record and failure policy
  # ------------------------------------------------------------------

  def test_mid_stream_bad_record_aborts_the_whole_import
    jar = HTTP::CookieJar.new
    assert_raise(ArgumentError) {
      load_fixture('mid_record_bad.yml', jar)
    }
    # The good records around the bad one must not be partially applied.
    assert jar.empty?
  end

  def test_failure_does_not_mutate_a_pre_populated_jar
    jar = HTTP::CookieJar.new
    jar.add(HTTP::Cookie.new(
      name: 'kept', value: '1', domain: 'kept.example', path: '/'))
    assert_raise(Psych::DisallowedClass) {
      load_fixture('arbitrary_tag.yml', jar)
    }
    assert_equal %w[kept], jar.to_a.map(&:name)

    assert_raise(ArgumentError) {
      load_fixture('mid_record_bad.yml', jar)
    }
    assert_equal %w[kept], jar.to_a.map(&:name)
  end

  def test_incompatible_top_level_scalar_is_rejected
    err = assert_raise(ArgumentError) { load_yaml("--- 42\n") }
    assert_match(/incompatible YAML cookie data/, err.message)
  end

  def test_empty_documents_are_valid_no_op_imports
    jar = load_yaml("--- []\n")
    assert jar.empty?
    jar = load_yaml("--- {}\n")
    assert jar.empty?
  end

  # ------------------------------------------------------------------
  # Construction observation: round-trip preserves jar contents
  # ------------------------------------------------------------------

  def test_save_load_round_trip_preserves_cookies
    original = HTTP::CookieJar.new
    original.add(HTTP::Cookie.new(
      name: 'Foo', value: 'Bar',
      domain: 'example.org', for_domain: true, path: '/',
      secure: true, httponly: true,
      expires: Time.at(Time.now.to_i + 86400),
      origin: 'http://example.org/'))

    io = StringIO.new
    original.save(io, :yaml)
    io.rewind

    restored = HTTP::CookieJar.new
    restored.load(io, :yaml)
    assert_equal 1, restored.to_a.size
    cookie = restored.to_a.first
    assert_equal 'Foo', cookie.name
    assert_equal 'Bar', cookie.value
    assert_equal 'example.org', cookie.domain
    assert_equal '/', cookie.path
    assert_equal true, cookie.secure?
    assert_equal true, cookie.httponly?
    assert_in_delta original.to_a.first.expires, cookie.expires, 1
  end

  def test_loaded_cookies_respect_secure_scope
    payload = <<~YAML
      ---
      - !ruby/object:HTTP::Cookie
        name: tok
        value: v
        domain: sec.example
        path: /
        secure: true
        for_domain: false
    YAML
    jar = load_yaml(payload)
    assert_equal 0, jar.cookies('http://sec.example/').size
    assert_equal 1, jar.cookies('https://sec.example/').size
  end
end
