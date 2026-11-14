# frozen_string_literal: true

require_relative "raw_document"
require_relative "oracle"

module REXMLTests
  module NamespaceSemantics
    # Seeded generator.  Each (seed, index) deterministically selects a
    # hazard family and a shape inside it, then fills in names, prefixes,
    # nesting and values from a private Random instance.  Documents are
    # legal by construction: templates only pair an attribute prefix with
    # a local name once per element.
    class Generator
      TRUSTED_URI = "urn:cfg:trusted"
      OTHER_URIS = ["urn:cfg:other", "urn:cfg:third", "urn:cfg:quarantine"].freeze
      PREFIXES = ["p", "q", "r"].freeze
      ELEMENT_LOCALS = ["entry", "item", "node", "value"].freeze
      ATTRIBUTE_LOCALS = ["role", "mode", "flag", "scope"].freeze
      VALUES = ["allow", "deny", "admin", "v0", "a&amp;b", "x&lt;y"].freeze

      HAZARDS = [
        :default_undeclare,
        :prefix_alias,
        :same_local_attributes,
        :sibling_restore,
      ].freeze

      def initialize(seed)
        @seed = seed
      end

      def document(index)
        hazard = HAZARDS[index % HAZARDS.length]
        rng = Random.new(@seed * 1_000_003 + index)
        root = build_root(rng, hazard)
        RawDocument.new(root)
      end

      private

      def build_root(rng, hazard)
        case hazard
        when :default_undeclare then build_default_undeclare(rng)
        when :prefix_alias then build_prefix_alias(rng)
        when :same_local_attributes then build_same_local_attributes(rng)
        else build_sibling_restore(rng)
        end
      end

      # Withdraw the default namespace, rebind a prefix in the same element,
      # nest one level deeper, then restore both for a following sibling.
      def build_default_undeclare(rng)
        prefix = pick(rng, PREFIXES)
        shadow_uri = pick(rng, OTHER_URIS)
        withdrawn = RawElement.new(
          qname: pick(rng, ELEMENT_LOCALS),
          attributes: [["xmlns", ""], ["xmlns:#{prefix}", shadow_uri]],
          children: [
            RawElement.new(
              qname: pick(rng, ELEMENT_LOCALS),
              attributes: [[pick(rng, ATTRIBUTE_LOCALS), pick(rng, VALUES)]],
              children: [
                RawElement.new(
                  qname: "#{prefix}:#{pick(rng, ELEMENT_LOCALS)}",
                  attributes: [["#{prefix}:#{pick(rng, ATTRIBUTE_LOCALS)}", pick(rng, VALUES)]],
                ),
              ],
            ),
          ],
        )
        RawElement.new(
          qname: pick(rng, ELEMENT_LOCALS),
          attributes: [["xmlns", TRUSTED_URI], ["xmlns:#{prefix}", TRUSTED_URI]],
          children: [
            withdrawn,
            RawElement.new(
              qname: "#{prefix}:#{pick(rng, ELEMENT_LOCALS)}",
              attributes: [["#{prefix}:#{pick(rng, ATTRIBUTE_LOCALS)}", pick(rng, VALUES)]],
            ),
            RawElement.new(
              qname: pick(rng, ELEMENT_LOCALS),
              attributes: [[pick(rng, ATTRIBUTE_LOCALS), pick(rng, VALUES)]],
            ),
          ],
        )
      end

      # Bind two prefixes to the same trusted URI, use both, then rebind
      # one of them in a child so the alias relationship splits.
      def build_prefix_alias(rng)
        first = pick(rng, PREFIXES)
        second = pick(rng, PREFIXES - [first])
        split_uri = pick(rng, OTHER_URIS)
        aliased = RawElement.new(
          qname: "#{first}:#{pick(rng, ELEMENT_LOCALS)}",
          attributes: [["xmlns:#{first}", TRUSTED_URI], ["xmlns:#{second}", TRUSTED_URI]],
          children: [
            RawElement.new(
              qname: "#{first}:#{pick(rng, ELEMENT_LOCALS)}",
              attributes: [
                ["#{first}:#{pick(rng, ATTRIBUTE_LOCALS)}", pick(rng, VALUES)],
              ],
              children: [
                RawElement.new(
                  qname: "#{second}:#{pick(rng, ELEMENT_LOCALS)}",
                  attributes: [["xmlns:#{second}", split_uri]],
                ),
              ],
            ),
            RawElement.new(
              qname: "#{second}:#{pick(rng, ELEMENT_LOCALS)}",
              attributes: [["#{second}:#{pick(rng, ATTRIBUTE_LOCALS)}", pick(rng, VALUES)]],
            ),
          ],
        )
        aliased
      end

      # One local attribute name under three expanded names: trusted
      # prefix, foreign prefix, and no namespace.
      def build_same_local_attributes(rng)
        local = pick(rng, ATTRIBUTE_LOCALS)
        foreign = pick(rng, OTHER_URIS)
        RawElement.new(
          qname: pick(rng, ELEMENT_LOCALS),
          attributes: [
            ["xmlns:p", TRUSTED_URI],
            ["xmlns:q", foreign],
            ["p:#{local}", pick(rng, VALUES)],
            ["q:#{local}", pick(rng, VALUES)],
            [local, pick(rng, VALUES)],
          ],
          children: [
            RawElement.new(
              qname: pick(rng, ELEMENT_LOCALS),
              attributes: [
                ["xmlns:p", TRUSTED_URI],
                ["p:#{local}", pick(rng, VALUES)],
                [local, pick(rng, VALUES)],
              ],
            ),
          ],
        )
      end

      # Rebind default and prefix in an inner scope, use them, then
      # return to the outer scope for a sibling.  A consumer that fails
      # to restore bindings sees the sibling in the wrong namespace.
      def build_sibling_restore(rng)
        prefix = pick(rng, PREFIXES)
        shadow_default = pick(rng, OTHER_URIS)
        shadow_prefix = pick(rng, OTHER_URIS)
        inner_prefix = pick(rng, PREFIXES - [prefix])
        raw = RawElement.new(
          qname: pick(rng, ELEMENT_LOCALS),
          attributes: [["xmlns", TRUSTED_URI], ["xmlns:#{prefix}", TRUSTED_URI]],
          children: [
            RawElement.new(
              qname: pick(rng, ELEMENT_LOCALS),
              attributes: [
                ["xmlns", shadow_default],
                ["xmlns:#{prefix}", shadow_prefix],
              ],
              children: [
                RawElement.new(
                  qname: "#{prefix}:#{pick(rng, ELEMENT_LOCALS)}",
                  attributes: [["#{prefix}:#{pick(rng, ATTRIBUTE_LOCALS)}", pick(rng, VALUES)]],
                  children: [
                    RawElement.new(
                      qname: "#{inner_prefix}:#{pick(rng, ELEMENT_LOCALS)}",
                      attributes: [["xmlns:#{inner_prefix}", pick(rng, OTHER_URIS)]],
                    ),
                  ],
                ),
              ],
            ),
            RawElement.new(
              qname: "#{prefix}:#{pick(rng, ELEMENT_LOCALS)}",
              attributes: [["#{prefix}:#{pick(rng, ATTRIBUTE_LOCALS)}", pick(rng, VALUES)]],
            ),
            RawElement.new(
              qname: pick(rng, ELEMENT_LOCALS),
              attributes: [[pick(rng, ATTRIBUTE_LOCALS), pick(rng, VALUES)]],
            ),
          ],
        )
        raw
      end

      def pick(rng, values)
        values[rng.rand(values.length)]
      end
    end
  end
end
