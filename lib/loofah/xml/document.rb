# frozen_string_literal: true

module Loofah
  module XML # :nodoc:
    #
    #  Subclass of Nokogiri::XML::Document.
    #
    #  See Loofah::ScrubBehavior and Loofah::DocumentDecorator for additional methods.
    #
    class Document < Nokogiri::XML::Document
      include Loofah::ScrubBehavior::Node
      include Loofah::DocumentDecorator

      class << self
        def parse(*args, evidence: nil, **kwargs, &block)
          recorder = Loofah::Evidence.resolve(evidence)
          recorder&.note_input(args.first, format: :xml_document)
          recorder&.parser_diagnostics_unavailable!

          doc = kwargs.empty? ? super(*args, &block) : super(*args, **kwargs, &block)
          recorder&.capture_parser_diagnostics(doc)
          doc
        end
      end
    end
  end
end
