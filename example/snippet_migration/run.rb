#!/usr/bin/env ruby
# frozen_string_literal: true

require 'bundler/setup'
require 'json'
require 'liquid'

SnippetFileSystem = Struct.new(:root) do
  def read_template_file(name)
    path = File.join(root, "#{name}.liquid")
    raise Liquid::FileSystemError, "No such template #{name.inspect}" unless File.file?(path)

    File.read(path)
  end
end

# Counts lookups so the example can prove whether a private parent value was
# read. The value itself is never printed.
class ReadProbe < Liquid::Drop
  attr_reader :reads

  def initialize(secret)
    super()
    @secret = secret
    @reads = 0
  end

  def to_liquid
    @reads += 1
    self
  end

  def to_s
    @secret
  end
end

GLOBALS = {
  'shop' => { 'name' => 'Example Shop' },
  'routes' => { 'cart' => '/cart' },
  'all_products' => [],
}.freeze

CALLER_BINDINGS = {
  'featured_product' => { 'title' => 'Arbor Draft', 'price' => 39900 },
  'badge' => 'New',
  'entries' => [
    { 'title' => 'Arbor Draft', 'quantity' => 1 },
    { 'title' => 'Arbor Element', 'quantity' => 2 },
  ],
}.freeze

PRIVATE_SECRET = 'caller-secret'

CALLER_TEMPLATE = File.join(__dir__, 'templates', 'caller.liquid')
SNIPPETS = File.join(__dir__, 'snippets')

# The migrated caller is intentionally explicit: every non-global value the
# snippets read is passed at the call site. No parent context is forwarded.
MIGRATED_TEMPLATE = <<~LIQUID.chomp
  {%- assign heading = 'Catalog' -%}
  <section>
    <h1>{{ heading }}</h1>

    {% render 'product_card' with featured_product as product, badge: badge %}

    {% render 'line_items', entries: entries %}

    {% render 'secret_probe' %}
  </section>
LIQUID

def render(source, environments:, static_environments:)
  environment = Liquid::Environment.build(file_system: SnippetFileSystem.new(SNIPPETS))
  context = Liquid::Context.build(
    environments: environments,
    static_environments: static_environments,
    registers: { file_system: environment.file_system },
    environment: environment,
  )
  Liquid::Template.parse(source, error_mode: :strict2, environment: environment).render!(context).chomp
end

expected = [
  '<section>',
  '  <h1>Catalog</h1>',
  '',
  '  <article class="card" data-shop="Example Shop">',
  '  <h2>Arbor Draft</h2>',
  '  <span class="badge">New</span>',
  '</article>',
  '',
  '',
  '  <ul class="line-items">',
  '  <li>1. Arbor Draft × 1</li>',
  '  <li>2. Arbor Element × 2</li>',
  '</ul>',
  '',
  '',
  '  ',
  '</section>',
].join("\n")

# Legitimate path: caller locals include the values the snippets need, plus a
# private object that secret_probe touches. include reads it; render must not.
legacy_probe = ReadProbe.new(PRIVATE_SECRET)
include_output = render(
  File.read(CALLER_TEMPLATE),
  environments: CALLER_BINDINGS.merge('private_token' => legacy_probe),
  static_environments: GLOBALS,
)

render_probe = ReadProbe.new(PRIVATE_SECRET)
migrated_output = render(
  MIGRATED_TEMPLATE,
  environments: CALLER_BINDINGS.merge('private_token' => render_probe),
  static_environments: GLOBALS,
)

raise 'legitimate include and render outputs differ' unless include_output == migrated_output
raise 'migrated output mismatch' unless migrated_output == expected
raise 'private value leaked into migrated output' if migrated_output.include?(PRIVATE_SECRET)
raise 'legacy include did not read private value' unless legacy_probe.reads.positive?
raise 'render read private parent value' unless render_probe.reads.zero?

# Side-effect control: include leaks snippet assignments into the caller scope;
# render keeps them isolated. This is why the migrated caller does not rely on
# the snippet's local `heading` assignment.
SIDE_EFFECT_TEMPLATE = "#{File.read(CALLER_TEMPLATE)}\n{{ heading }}"
SIDE_EFFECT_MIGRATED = "#{MIGRATED_TEMPLATE}\n{{ heading }}"
include_side_effect = render(
  SIDE_EFFECT_TEMPLATE,
  environments: CALLER_BINDINGS,
  static_environments: GLOBALS,
)
render_side_effect = render(
  SIDE_EFFECT_MIGRATED,
  environments: CALLER_BINDINGS,
  static_environments: GLOBALS,
)

raise 'expected include to leak snippet assignment' unless include_side_effect.end_with?('Arbor Draft')
raise 'expected render to keep snippet assignment isolated' unless render_side_effect.end_with?('Catalog')

puts JSON.pretty_generate(
  'legitimate_include' => include_output,
  'migrated_render_with_explicit_args' => migrated_output,
  'legitimate_outputs_identical' => include_output == migrated_output,
  'private_value_reads' => {
    'legacy_include' => legacy_probe.reads,
    'migrated_render' => render_probe.reads,
  },
  'side_effect_control' => {
    'legacy_include_trailing_heading' => include_side_effect.lines.last.chomp,
    'migrated_render_trailing_heading' => render_side_effect.lines.last.chomp,
  },
  'assertions' => {
    'migrated_output_matches_expected' => true,
    'private_value_not_read_after_migration' => true,
    'include_assignment_does_not_leak_through_render' => true,
  },
)
