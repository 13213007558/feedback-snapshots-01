# frozen_string_literal: true

module Loofah
  module XML # :nodoc:
    #
    #  Subclass of Nokogiri::XML::DocumentFragment.
    #
    #  See Loofah::ScrubBehavior for additional methods.
    #
    class DocumentFragment < Nokogiri::XML::DocumentFragment
      class << self
        def parse(tags, evidence: nil, **_options)
          recorder = Loofah::Evidence.resolve(evidence)
          recorder&.note_input(tags, format: :xml_documentfragment)

          doc = Loofah::XML::Document.new
          doc.encoding = tags.encoding.name if tags.respond_to?(:encoding)
          fragment = new(doc, tags)
          recorder&.capture_parser_diagnostics(fragment)
          fragment
        end
      end
    end
  end
end
