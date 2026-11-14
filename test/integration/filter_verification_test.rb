# frozen_string_literal: true

require 'test_helper'

class FilterVerificationTest < Minitest::Test
  include Liquid

  # Records every chunk written to it, so tests can prove that no raw
  # sensitive value ever reached the output.
  class RecordingBuffer
    attr_reader :writes

    def initialize
      @writes = []
    end

    def <<(chunk)
      @writes << chunk
      self
    end

    def to_s
      @writes.join
    end
  end

  module Sanitizer
    def sanitize(input)
      input.to_s.gsub('<', '&lt;').gsub('>', '&gt;')
    end
  end

  module PrivateSanitizer
    private

    def sanitize(input)
      "cleaned: #{input}"
    end
  end

  module OrderRecorder
    @calls = []

    class << self
      attr_reader :calls

      def reset
        @calls.clear
      end
    end

    def first_filter(input)
      OrderRecorder.calls << :first_filter
      input
    end

    def second_filter(input)
      OrderRecorder.calls << :second_filter
      input
    end
  end

  module ExtraFilter
    def extra(input)
      "extra: #{input}"
    end
  end

  class CustomTag < Liquid::Tag
    def render_to_output_buffer(_context, output)
      output << 'custom'
    end
  end

  def setup
    OrderRecorder.reset
  end

  def build_environment(partials: {}, filters: [Sanitizer])
    stub_file_system = StubFileSystem.new(partials)
    Environment.build(file_system: stub_file_system) do |environment|
      filters.each { |mod| environment.register_filter(mod) }
    end
  end

  def parse_template(source, environment, name: 'notification')
    template = Template.parse(source, environment: environment, line_numbers: true)
    template.name = name
    template
  end

  def test_missing_sanitizer_is_detected_before_any_output
    environment = build_environment(filters: [])
    template    = parse_template("{{ user.secret | sanitize }}", environment)

    error = assert_raises(UndefinedFilter) { template.verify_filters! }

    assert_equal('notification', error.template_name)
    assert_includes(error.message, 'sanitize')
    refute_includes(error.message, 'secret')
    refute_includes(error.message, 'user')

    buffer = RecordingBuffer.new
    assert_raises(UndefinedFilter) do
      template.verify_filters!
      template.render!({ 'user' => { 'secret' => '<sensitive>' } }, output: buffer)
    end
    assert_empty(buffer.writes)
    refute_includes(buffer.to_s, '<sensitive>')
  end

  def test_error_message_never_contains_the_value_to_be_sanitized
    environment = build_environment(filters: [])
    template    = parse_template("{{ user.secret | sanitize }}", environment)

    error = assert_raises(UndefinedFilter) { template.verify_filters! }

    refute_includes(error.to_s, '<sensitive>')
    refute_includes(error.to_s, 'user.secret')
  end

  def test_private_method_with_matching_name_does_not_count
    environment = build_environment(filters: [PrivateSanitizer])
    template    = parse_template("{{ user.secret | sanitize }}", environment)

    assert_raises(UndefinedFilter) { template.verify_filters! }
  end

  def test_filters_in_capture_blocks_are_checked
    environment = build_environment(filters: [])
    template    = parse_template(
      "{% capture msg %}{{ user.secret | sanitize }}{% endcapture %}{{ msg }}",
      environment,
    )

    assert_raises(UndefinedFilter) { template.verify_filters! }
  end

  def test_filters_in_conditional_branches_are_checked
    environment = build_environment(filters: [])
    template    = parse_template(
      "{% if user.admin %}{{ user.secret | sanitize }}{% else %}n/a{% endif %}",
      environment,
    )

    assert_raises(UndefinedFilter) { template.verify_filters! }
  end

  def test_filters_in_statically_named_partials_are_checked
    environment = build_environment(
      partials: { 'footer' => "{{ user.secret | sanitize }}" },
      filters: [],
    )
    template = parse_template("{% render 'footer' %}", environment)

    error = assert_raises(UndefinedFilter) { template.verify_filters! }
    assert_equal('footer', error.template_name)
  end

  def test_filters_in_included_partials_are_checked
    environment = build_environment(
      partials: { 'footer' => "{{ user.secret | sanitize }}" },
      filters: [],
    )
    template = parse_template("{% include 'footer' %}", environment)

    error = assert_raises(UndefinedFilter) { template.verify_filters! }
    assert_equal('footer', error.template_name)
  end

  def test_dynamically_named_partial_is_an_explicit_boundary
    environment = build_environment
    template    = parse_template("{% include snippet_name %}", environment)

    error = assert_raises(UnverifiableContent) { template.verify_filters! }
    assert_equal('notification', error.template_name)
    assert_includes(error.message, 'dynamically')
  end

  def test_extension_tag_is_an_explicit_boundary
    environment = Environment.build do |env|
      env.register_filter(Sanitizer)
      env.register_tag('plot', CustomTag)
    end
    template = parse_template("{% plot %}{{ user.secret | sanitize }}", environment)

    error = assert_raises(UnverifiableContent) { template.verify_filters! }
    assert_includes(error.message, 'plot')
  end

  def test_verified_template_calls_filters_in_template_order
    environment = build_environment(filters: [OrderRecorder])
    template    = parse_template("{{ 'x' | first_filter | second_filter }}", environment)

    template.verify_filters!
    assert_equal('x', template.render!)

    assert_equal([:first_filter, :second_filter], OrderRecorder.calls)
  end

  def test_verified_template_renders_sanitized_output
    environment = build_environment
    template    = parse_template("{{ user.secret | sanitize }}", environment)

    template.verify_filters!
    output = template.render!('user' => { 'secret' => '<sensitive>' })

    assert_equal('&lt;sensitive&gt;', output)
  end

  def test_runtime_added_filters_do_not_silently_change_the_confirmed_set
    environment = build_environment
    template    = parse_template("{{ user.secret | sanitize }}", environment)
    template.verify_filters!

    buffer = RecordingBuffer.new
    error  = assert_raises(FilterVerificationError) do
      template.render!({ 'user' => { 'secret' => '<sensitive>' } }, filters: [ExtraFilter], output: buffer)
    end

    assert_equal('notification', error.template_name)
    assert_empty(buffer.writes)
    refute_includes(buffer.to_s, '<sensitive>')
  end

  def test_extra_filters_confirmed_up_front_render_fine
    environment = build_environment
    template    = parse_template("{{ 'x' | extra | sanitize }}", environment)

    template.verify_filters!(filters: [ExtraFilter])
    assert_equal('extra: x', template.render!({}, filters: [ExtraFilter]))
  end

  def test_verification_result_reflects_confirmed_filters
    environment = build_environment
    template    = parse_template("{{ user.secret | sanitize }}", environment)

    verification = template.verify_filters!

    assert_includes(verification.filter_names, 'sanitize')
    assert(verification.frozen? || verification.filter_names.frozen?)
  end
end
