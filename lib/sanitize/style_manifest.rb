# frozen_string_literal: true

require "digest"

class Sanitize
  # A manifest of the exact inline styles that survived sanitization, suitable
  # for generating precise Content Security Policy (CSP) hash sources.
  #
  # The manifest is built from the *final* sanitized DOM, so each digest covers
  # exactly the text a browser would hash: the decoded value of each `style`
  # attribute and the text content of each `<style>` element, after all CSS
  # allowlist filtering has been applied. Character references in the source
  # HTML, serialization details such as newlines, and declarations removed by
  # the sanitizer can never cause a mismatch, because they never enter the
  # hashed text.
  #
  # Styles inside `<style>` elements and `style` attributes are recorded as
  # separate kinds, since CSP authorizes them through different directives
  # (`style-src-elem` and `style-src-attr`). Identical styles are deduplicated
  # into a single manifest entry, but every occurrence remains traceable
  # through the entry's `positions`.
  #
  # @example
  #   sanitizer = Sanitize.new(Sanitize::Config::RELAXED)
  #   html, manifest = sanitizer.fragment_with_manifest(input)
  #
  #   manifest.csp_header # => "style-src-elem 'sha256-...'; style-src-attr 'sha256-...'"
  #   manifest.verify(html).approved? # => true
  class StyleManifest
    # CSP hash algorithm used for all digests.
    ALGORITHM = "sha256"

    # A single inline style occurrence collected from a document.
    #
    # - `kind` is `:element` for a `<style>` element or `:attribute` for a
    #   `style` attribute.
    # - `content` is the exact final text the browser would hash.
    # - `digest` is the CSP hash source for `content`.
    # - `position` locates the occurrence in the document.
    Item = Struct.new(:kind, :content, :digest, :position)

    # A deduplicated manifest entry. Styles with the same kind and content
    # share a single entry; every occurrence is recorded in `positions`.
    Entry = Struct.new(:kind, :content, :digest, :positions)

    # The result of verifying a document against a manifest.
    #
    # - `unauthorized` lists {Item}s found in the document that the manifest
    #   does not approve (including occurrences beyond the approved count).
    # - `missing` lists approved {Entry}s that no longer appear in the
    #   document as many times as the manifest recorded.
    class Verification < Struct.new(:unauthorized, :missing)
      # Returns `true` only if every style in the document is approved by the
      # manifest and every approved style is still present.
      def approved?
        unauthorized.empty? && missing.empty?
      end
    end

    # An approved style that no longer appears in the verified document as
    # many times as the manifest recorded.
    Missing = Struct.new(:kind, :digest, :count)

    class << self
      # Returns a manifest built from the given sanitized Nokogiri node (a
      # `Document`, `DocumentFragment`, or `Element`).
      def build(node)
        manifest = new

        collect(node).each do |item|
          manifest.add(item.kind, item.content, item.position)
        end

        manifest
      end

      # Returns an array of {Item}s, one for each inline style occurrence in
      # the given node, in document order.
      def collect(node)
        items = []
        index = 0

        walk(node) do |kind, style_node|
          content = (kind == :element) ? style_node.content : style_node["style"].to_s
          path = style_node.path
          path += "/@style" if kind == :attribute

          items << Item.new(kind, content, digest(content), "##{index} #{path}")
          index += 1
        end

        items
      end

      # Returns the CSP hash source for the given final style text.
      def digest(content)
        "#{ALGORITHM}-#{Digest::SHA256.base64digest(content)}"
      end

      private

      # Yields `[:element, node]` for each `<style>` element and
      # `[:attribute, node]` for each element with a `style` attribute, in
      # document order.
      def walk(node, &block)
        return if node.nil?

        if node.element?
          yield :element, node if node.name.downcase == "style"
          yield :attribute, node if node.key?("style")
        end

        node.children.each { |child| walk(child, &block) }
      end
    end

    attr_reader :entries

    def initialize
      @entries = []
      @entries_by_key = {}
    end

    # Records one occurrence of a style. Styles that are identical to an
    # existing entry are deduplicated; the position is appended to the shared
    # entry so every occurrence remains traceable.
    def add(kind, content, position)
      digest = self.class.digest(content)
      key = [kind, digest]
      entry = @entries_by_key[key]

      if entry.nil?
        entry = Entry.new(kind, content, digest, [])
        @entries_by_key[key] = entry
        @entries << entry
      end

      entry.positions << position
      entry
    end

    # Returns CSP directives that authorize exactly the styles in this
    # manifest, as a hash mapping directive names to arrays of hash sources.
    # `<style>` elements map to `style-src-elem` and `style` attributes map to
    # `style-src-attr`.
    def csp_directives
      directives = {}

      element_digests = digests_for(:element)
      attribute_digests = digests_for(:attribute)

      directives["style-src-elem"] = element_digests unless element_digests.empty?
      directives["style-src-attr"] = attribute_digests unless attribute_digests.empty?

      directives
    end

    # Returns a CSP policy fragment authorizing exactly the styles in this
    # manifest, e.g.:
    #
    #   style-src-elem 'sha256-...'; style-src-attr 'sha256-...'
    def csp_header
      csp_directives.map do |name, digests|
        sources = digests.map { |digest| "'#{digest}'" }.join(" ")
        "#{name} #{sources}"
      end.join("; ")
    end

    # Returns a serializable representation of this manifest.
    def to_h
      {
        "algorithm" => ALGORITHM,
        "entries" => @entries.map do |entry|
          {
            "kind" => entry.kind.to_s,
            "digest" => entry.digest,
            "content" => entry.content,
            "positions" => entry.positions
          }
        end
      }
    end

    # Verifies that every inline style in _target_ (a Nokogiri node or an HTML
    # string) is approved by this manifest, and that every approved style is
    # still present. Returns a {Verification}.
    #
    # If any authorized style in the output is modified, its digest changes
    # and it is reported as unauthorized, so this manifest can no longer prove
    # it was approved.
    def verify(target)
      target = Nokogiri::HTML5.fragment(target) if target.is_a?(String)
      observed = self.class.collect(target)

      remaining = Hash.new(0)
      @entries.each do |entry|
        remaining[[entry.kind, entry.digest]] = entry.positions.size
      end

      unauthorized = []

      observed.each do |item|
        key = [item.kind, item.digest]

        if remaining[key] > 0
          remaining[key] -= 1
        else
          unauthorized << item
        end
      end

      missing = @entries.filter_map do |entry|
        count = remaining[[entry.kind, entry.digest]]
        Missing.new(entry.kind, entry.digest, count) if count > 0
      end

      Verification.new(unauthorized, missing)
    end

    private

    def digests_for(kind)
      @entries.select { |entry| entry.kind == kind }.map(&:digest)
    end
  end
end
