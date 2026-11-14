# frozen_string_literal: true

require "rexml/document"
require "rexml/parsers/streamparser"
require "rexml/streamlistener"
require "stringio"

require_relative "model"

module StreamDomConsistency
  # A normalized view of one implementation's result.
  #
  # `nodes` is the sequence of character-data nodes after the normalisation
  # XML itself implies: adjacent text collapses into one Text node, while a
  # CDATA section stays a separate node.  `raw_events` is retained only for
  # diagnostics; it never participates in a comparison.
  class Observation
    Node = Struct.new(:kind, :text, keyword_init: true)

    attr_reader :ok, :nodes, :attributes, :raw_events, :error_kind,
                :error_message, :adapter

    def initialize(ok:, nodes: [], attributes: {}, raw_events: [], first_text: nil,
                   error_kind: nil, error_message: nil, adapter:)
      @ok = ok
      @nodes = nodes
      @attributes = attributes
      @raw_events = raw_events
      @error_kind = error_kind
      @error_message = error_message
      @adapter = adapter
    end

    def channel(name)
      case name
      when :text
        nodes.select { |node| node.kind == :text }.map(&:text).join
      when :cdata
        nodes.select { |node| node.kind == :cdata }.map(&:text).join
      when :combined
        nodes.map(&:text).join
      when :first_node, :element_text
        nodes.first&.text
      when :attributes
        attributes
      else
        raise "unknown channel: #{name.inspect}"
      end
    end

    # Include attribute values because filters commonly inspect them too.
    def policy_strings
      [channel(:combined), *attributes.values]
    end

    def describe
      if ok
        "nodes=#{nodes.map { |node| [node.kind, node.text] }.inspect} " \
          "attrs=#{attributes.inspect}"
      else
        "ERROR #{error_kind}: #{error_message}"
      end
    end
  end

  # Merge consecutive text events/nodes the same way the DOM does, so the
  # comparison is over character sequences, not event chunking.
  module NodeNormalizer
    module_function

    def from_segments(segments)
      builder = []
      segments.each do |kind, text|
        if kind == :text && builder.last && builder.last.kind == :text
          builder.last.text << text
        else
          builder << Observation::Node.new(kind: kind, text: +text)
        end
      end
      builder
    end

    def from_dom_children(children)
      nodes = []
      children.each do |child|
        case child
        when REXML::CData
          nodes << Observation::Node.new(kind: :cdata, text: child.value.to_s)
        when REXML::Text
          nodes << Observation::Node.new(kind: :text, text: child.value.to_s)
        when REXML::Element
          nodes.concat(from_dom_children(child.children))
        end
      end
      nodes
    end
  end

  module Adapters
    module SourceBuilder
      module_function

      def build(kase)
        bytes = kase.xml_bytes
        case kase.source_form
        when :string, :bytes
          bytes
        when :stringio, :io
          StringIO.new(bytes)
        else
          raise "unknown source form: #{kase.source_form.inspect}"
        end
      end
    end

    # Exactly the character data a streaming filter sees.
    module StreamAdapter
      class Collector
        include REXML::StreamListener

        attr_reader :segments, :attributes

        def initialize
          @segments = []
          @attributes = {}
        end

        def tag_start(name, attributes)
          return unless name == "r"

          attributes.each { |key, value| @attributes[key] = value }
        end

        def text(value)
          @segments << [:text, value.to_s]
        end

        def cdata(value)
          @segments << [:cdata, value.to_s]
        end
      end

      module_function

      def run(kase)
        collector = Collector.new
        begin
          REXML::Parsers::StreamParser.new(SourceBuilder.build(kase), collector).parse
          Observation.new(
            ok: true,
            nodes: NodeNormalizer.from_segments(collector.segments),
            attributes: collector.attributes,
            raw_events: collector.segments,
            adapter: :stream,
          )
        rescue Exception => error # rubocop:disable Lint/RescueException
          Observation.new(
            ok: false,
            raw_events: collector.segments,
            attributes: collector.attributes,
            error_kind: error.class.name,
            error_message: error.message.to_s.lines.first.to_s.strip,
            adapter: :stream,
          )
        end
      end
    end

    # The DOM as downstream business code reads it.
    module DomAdapter
      module_function

      def run(kase)
        begin
          document = REXML::Document.new(SourceBuilder.build(kase))
          root = document.root
          raise "no root element" if root.nil?

          attributes = {}
          root.attributes.each_attribute do |attribute|
            attributes[attribute.name] = attribute.value
          end
          Observation.new(
            ok: true,
            nodes: NodeNormalizer.from_dom_children(root.children),
            attributes: attributes,
            adapter: :dom,
          )
        rescue Exception => error # rubocop:disable Lint/RescueException
          Observation.new(
            ok: false,
            error_kind: error.class.name,
            error_message: error.message.to_s.lines.first.to_s.strip,
            adapter: :dom,
          )
        end
      end
    end
  end
end
