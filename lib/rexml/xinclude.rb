# frozen_string_literal: false
require_relative "document"
require_relative "text"
require_relative "cdata"
require_relative "comment"
require_relative "instruction"
require_relative "parseexception"

module REXML
  # XInclude processing for REXML documents.
  #
  # Unlike many XInclude implementations, this one never opens a file path or
  # URL on its own.  Every piece of included content is supplied by a
  # caller-provided +resolver+, so embedding applications keep full control
  # over which resources may be read.  There is no built-in +File+, +open-uri+
  # or network access anywhere in this module.
  #
  # == Security model
  #
  # The resolver is asked for permission (+authorized?+) before it is asked
  # for content (+read+).  A denied resource is never read.  Cycles, nesting
  # limits, size limits and authorization denials are fatal errors: an
  # +xi:fallback+ child cannot be used to retry the same inclusion through a
  # different address.  Fallback content only runs when a resource is simply
  # missing.
  #
  # == Resolver contract
  #
  # A resolver is any object responding to:
  #
  # +read(uri)+::       (required) returns the resource content as a String.
  #                     Raising REXML::XInclude::ResourceError via
  #                     +ResourceError.missing!(uri)+ means the resource does
  #                     not exist and an +xi:fallback+ may run.  Any other
  #                     failure is fatal.
  # +authorized?(uri)+:: (optional) returns a truthy value when the caller is
  #                     allowed to read +uri+.  When it returns false (or
  #                     raises REXML::XInclude::AuthorizationDenied) the
  #                     inclusion fails without calling +read+.
  #
  # A Proc answering +call(uri)+ may be used as a resolver; it is treated as
  # the +read+ operation and everything is considered authorized.
  #
  # == Example
  #
  #   resolver = lambda do |uri|
  #     store.fetch(uri) # e.g. an in-memory table
  #   end
  #   result = REXML::XInclude.include(document, resolver)
  #   result.document            # expanded copy
  #   result.sources             # where each inserted node came from
  module XInclude
    # Namespace URI for XInclude elements as defined by the W3C XInclude 1.0
    # recommendation ({https://www.w3.org/TR/xinclude/}).
    XINCLUDE_NAMESPACE = "http://www.w3.org/2001/XInclude".freeze

    # Base class for every error raised by XInclude processing.
    class Error < StandardError; end

    # The +xi:include+ element is malformed or uses an unsupported feature.
    # Always fatal; fallback is not allowed.
    class ConfigurationError < Error; end

    # A limit (nesting depth, number of includes or accumulated text size)
    # was exceeded.  Always fatal; fallback is not allowed.
    class LimitExceeded < Error; end

    # An include chain loops back to a resource that is still being expanded.
    # Always fatal; fallback is not allowed.
    class IncludeCycle < Error; end

    # The resolver refused access to a resource.  The resolver's +read+ method
    # is guaranteed not to have been called.  Always fatal; fallback is not
    # allowed.
    class AuthorizationDenied < Error; end

    # A resource could not be retrieved.  When the resource is missing the
    # +xi:fallback+ child is allowed to run; transport-level failures of other
    # kinds remain fatal.  Use the class methods +missing!+ / +missing?+ to
    # distinguish the two.
    class ResourceError < Error
      # Error kind reported when a resource does not exist; only this kind
      # permits fallback processing.
      MISSING = :missing

      # Error kind reported for a transport/IO failure while the resource
      # exists.  Always fatal.
      FETCH_FAILED = :fetch_failed

      # @return [Symbol] one of {MISSING} or {FETCH_FAILED}
      attr_reader :kind

      def initialize(message, kind = FETCH_FAILED)
        super(message)
        @kind = kind
      end

      # Builds a "resource missing" error, the only kind that allows fallback.
      def self.missing!(uri)
        new("XInclude resource not found: #{uri}", MISSING)
      end

      # @return [Boolean] whether this error permits fallback processing
      def missing?
        @kind == MISSING
      end
    end

    # Included content could not be parsed as well-formed XML.  Always fatal.
    class MalformedResource < Error
      # @return [String] URI of the unparseable resource
      attr_reader :uri

      def initialize(uri, cause)
        super("XInclude resource #{uri.inspect} is not well-formed XML: #{cause.message}")
        @uri = uri
      end
    end

    # Records the origin of one piece of inserted content.
    #
    # @!attribute uri
    #   @return [String] absolute URI the content was resolved from
    # @!attribute mode
    #   @return [Symbol] +:xml+ for parsed XML, +:text+ for literal text
    # @!attribute href
    #   @return [String] raw +href+ as written on the +xi:include+ element
    # @!attribute base
    #   @return [String] effective base URI in scope when including
    # @!attribute encoding
    #   @return [String, nil] requested text encoding, if any
    # @!attribute target
    #   @return [REXML::Node] first node inserted for this inclusion
    # @!attribute included_by
    #   @return [Source, nil] origin of the resource that contained the
    #     +xi:include+ element, forming the inclusion chain
    Source = Struct.new(:uri, :mode, :href, :base, :encoding, :target,
                        :included_by, keyword_init: true) do
      # @return [Array<String>] URIs from the outermost document down to this
      #   resource
      def chain
        list = []
        node = self
        while node
          list << node.uri
          node = node.included_by
        end
        list.reverse
      end
    end

    # Outcome of a successful expansion.
    #
    # @!attribute document
    #   @return [REXML::Document] expanded document; the input document is
    #     never mutated
    # @!attribute sources
    #   @return [Hash{REXML::Node => Source}] origin record for every inserted
    #     node, keyed by node identity
    # @!attribute events
    #   @return [Array<Hash>] ordered audit trail of every resolver interaction
    class Result
      # @return [REXML::Document]
      attr_reader :document

      # @return [Hash{REXML::Node => Source}]
      attr_reader :sources

      # @return [Array<Hash>]
      attr_reader :events

      def initialize(document, sources, events)
        @document = document
        @sources = sources
        @events = events
      end

      # @param node [REXML::Node]
      # @return [Source, nil] origin recorded for +node+, if any
      def source_of(node)
        @sources[node]
      end
    end

    # Default maximum number of nested XML includes.
    DEFAULT_MAX_DEPTH = 20

    # Default maximum total number of +xi:include+ elements processed.
    DEFAULT_MAX_INCLUDES = 1000

    # Default maximum number of bytes accumulated through text includes.
    DEFAULT_MAX_TEXT_BYTES = 1_000_000

    # Drives one XInclude expansion against a controlled resolver.
    class Processor
      # @return [Object] the caller supplied resolver
      attr_reader :resolver

      # @return [Array<Hash>] ordered audit trail of resolver interactions
      attr_reader :events

      # @return [Hash{REXML::Node => Source}]
      attr_reader :sources

      # @param resolver [Object, Proc] object responding to +read+ and
      #   optionally +authorized?+; a Proc is treated as +read+
      # @param base_uri [String, nil] base URI of the top-level document
      # @param max_depth [Integer] nested XML include limit
      # @param max_includes [Integer] total include element limit
      # @param max_text_bytes [Integer] accumulated text include size limit
      def initialize(resolver, base_uri: nil,
                     max_depth: DEFAULT_MAX_DEPTH,
                     max_includes: DEFAULT_MAX_INCLUDES,
                     max_text_bytes: DEFAULT_MAX_TEXT_BYTES)
        @resolver = resolver
        @base_uri = base_uri
        @max_depth = max_depth
        @max_includes = max_includes
        @max_text_bytes = max_text_bytes
        @events = []
        @sources = {}
        @include_count = 0
        @text_bytes = 0
      end

      # Expands every XInclude element in +document+.
      #
      # @param document [REXML::Document]
      # @return [Result]
      # @raise [Error] on any fatal condition; the input document is left
      #   untouched in that case
      def process(document)
        raise ArgumentError, "expected a REXML::Document" unless document.is_a?(REXML::Document)

        working = document.deep_clone
        context = Context.new(@base_uri, nil, 0)
        walk(working, context)
        Result.new(working, @sources, @events)
      end

      private

      # Mutable expansion context carried through recursion.
      class Context
        attr_accessor :base_uri, :included_by, :depth

        def initialize(base_uri, included_by, depth)
          @base_uri = base_uri
          @included_by = included_by
          @depth = depth
        end
      end

      # Pre-order walk over every element below +node+.  +node+ may be the
      # document itself or any container element.
      def walk(node, context)
        # to_a returns a detached copy, which is required because include
        # processing mutates the real child list while we iterate.
        node.to_a.dup.each do |child|
          next unless child.is_a?(REXML::Element)

          child_base = resolve_element_base(child, context.base_uri)
          child_context =
            if child_base == context.base_uri
              context
            else
              Context.new(child_base, context.included_by, context.depth)
            end

          if xinclude_element?(child)
            expand_include(node, child, child_context)
          else
            walk(child, child_context)
          end
        end
      end

      def expand_include(parent, include_element, context)
        validate_include_element(include_element)

        @include_count += 1
        if @include_count > @max_includes
          raise LimitExceeded,
                "XInclude include count limit (#{@max_includes}) exceeded"
        end

        href = include_element.attributes["href"]
        parse = (include_element.attributes["parse"] || "xml").downcase
        encoding = include_element.attributes["encoding"]
        base = resolve_element_base(include_element, context.base_uri)
        target_uri = resolve_reference(base, href)

        # Cycles are detected before any resolver interaction, so a loop can
        # never be retried through fallback against another address.
        if active_chain_contains?(context, target_uri)
          raise IncludeCycle,
                "XInclude cycle detected for #{target_uri}"
        end

        depth = context.depth
        if parse == "xml"
          depth += 1
          if depth > @max_depth
            raise LimitExceeded,
                  "XInclude nesting depth limit (#{@max_depth}) exceeded at #{target_uri}"
          end
        end

        authorize!(target_uri)
        content = fetch(target_uri)

        if parse == "xml"
          nodes = build_xml_nodes(content, target_uri)
          source = record_source(target_uri, :xml, href, base, encoding,
                                 nodes, context.included_by)
          insert_xml(parent, include_element, nodes, source, target_uri, depth, base)
        else
          text_node = REXML::Text.new(content, true, nil, false)
          @text_bytes += content.bytesize
          if @text_bytes > @max_text_bytes
            raise LimitExceeded,
                  "XInclude text size limit (#{@max_text_bytes} bytes) exceeded"
          end
          source = record_source(target_uri, :text, href, base, encoding,
                                 [text_node], context.included_by)
          replace_node(parent, include_element, [text_node], source)
        end
      rescue ResourceError, MalformedResource
        # A missing resource is the only condition that may use fallback.
        raise unless $!.is_a?(ResourceError) && $!.missing?
        apply_fallback(parent, include_element, context, target_uri)
      end

      # Runs the xi:fallback child of a missing include.  Every other failure
      # type propagates and never reaches here.
      def apply_fallback(parent, include_element, context, target_uri)
        fallback = include_element.children.find do |child|
          xinclude_named?(child, "fallback")
        end
        unless fallback
          raise ResourceError.missing!(target_uri)
        end

        nodes = fallback.children.map do |child|
          clone_node(child)
        end
        inserted = replace_node(parent, include_element, nodes, nil)
        inserted.each do |node|
          if node.is_a?(REXML::Element)
            element_base = resolve_element_base(node, context.base_uri)
            node_context = Context.new(element_base, context.included_by, context.depth)
            walk(node, node_context)
          end
        end
      end

      def build_xml_nodes(content, uri)
        begin
          included_doc = REXML::Document.new(content)
        rescue REXML::ParseException => error
          raise MalformedResource.new(uri, error)
        rescue => error
          raise MalformedResource.new(uri, error)
        end

        nodes = included_doc.children.reject do |child|
          child.is_a?(REXML::XMLDecl)
        end
        if nodes.empty?
          raise ConfigurationError,
                "XInclude resource #{uri.inspect} contains no usable XML content"
        end
        nodes.map { |node| clone_node(node) }
      end

      def insert_xml(parent, include_element, nodes, source, target_uri, depth, base)
        # Base URI fixup (XInclude 4.5.1).  Any xml:base already present on an
        # included top-level element is resolved against the resource URI to
        # an absolute reference, so later relative includes resolve from the
        # included resource rather than the include site.  When the element
        # had no xml:base but the resource differs from the include-site base,
        # record the resource URI explicitly.
        first_element = nodes.find { |node| node.is_a?(REXML::Element) }
        if first_element
          existing = first_element.attributes["xml:base"]
          if existing
            first_element.attributes["xml:base"] =
              normalize_uri(resolve_reference(target_uri, existing))
          elsif target_uri != base
            first_element.attributes["xml:base"] = target_uri
          end
        end

        replace_node(parent, include_element, nodes, source)

        nodes.each do |node|
          next unless node.is_a?(REXML::Element)
          node_base = effective_element_base(node, target_uri)
          node_context = Context.new(node_base, source, depth)
          walk(node, node_context)
        end
      end

      # Base URI of an inserted element after base URI fixup: an explicit
      # xml:base is resolved against the resource URI, otherwise the resource
      # URI itself is the element's base.
      def effective_element_base(element, resource_uri)
        attribute = element.attributes["xml:base"]
        attribute ? resolve_reference(resource_uri, attribute) : resource_uri
      end

      # Replaces +old_node+ (a direct child of +parent+) with +new_nodes+,
      # preserving document order.  Uses REXML's own child-list API because
      # Parent#children returns a detached copy that cannot be mutated.
      def replace_node(parent, old_node, new_nodes, source)
        index = parent.index(old_node)
        anchor = nil
        parent.delete(old_node)
        inserted = []
        new_nodes.each do |node|
          if anchor.nil?
            if index && index < parent.size
              parent.insert_before(parent[index], node)
            else
              parent.add(node)
            end
          else
            parent.insert_after(anchor, node)
          end
          anchor = node
          inserted << node
          tag_subtree(node, source) if source
        end
        inserted
      end

      def tag_subtree(node, source)
        @sources[node] = source
        if node.is_a?(REXML::Parent)
          node.children.each { |child| tag_subtree(child, source) }
        end
      end

      def record_source(uri, mode, href, base, encoding, nodes, included_by)
        Source.new(uri: uri,
                   mode: mode,
                   href: href,
                   base: base,
                   encoding: encoding,
                   target: nodes.first,
                   included_by: included_by)
      end

      def authorize!(uri)
        decision = true
        if @resolver.respond_to?(:authorized?)
          begin
            decision = @resolver.authorized?(uri)
          rescue AuthorizationDenied => error
            @events << event(uri, :denied, error.message)
            raise
          end
        end

        unless decision
          @events << event(uri, :denied, "resolver refused access")
          raise AuthorizationDenied,
                "XInclude access denied by resolver for #{uri}"
        end
      end

      def fetch(uri)
        unless @resolver.respond_to?(:read) || @resolver.respond_to?(:call)
          raise ConfigurationError,
                "XInclude resolver must respond to #read (or be a Proc)"
        end

        begin
          content = @resolver.respond_to?(:read) ?
            @resolver.read(uri) : @resolver.call(uri)
        rescue ResourceError
          @events << event(uri, $!.missing? ? :missing : :error, $!.message)
          raise
        rescue AuthorizationDenied
          @events << event(uri, :denied, $!.message)
          raise
        rescue => error
          @events << event(uri, :error, error.message)
          raise ResourceError.new(
            "XInclude failed to read #{uri}: #{error.class}: #{error.message}")
        end

        unless content.is_a?(String)
          raise ResourceError,
                "XInclude resolver returned #{content.class} for #{uri}, expected String"
        end
        @events << event(uri, :read, nil, content.bytesize)
        content
      end

      def event(uri, status, message, bytes = nil)
        entry = { uri: uri, status: status }
        entry[:message] = message if message
        entry[:bytes] = bytes if bytes
        entry
      end

      def validate_include_element(include_element)
        unless include_element.attributes["href"]
          raise ConfigurationError,
                "xi:include without href (xpointer-only includes are not supported)"
        end
        if split_uri(include_element.attributes["href"])[:fragment]
          raise ConfigurationError,
                "xi:include fragment identifiers are not supported: " \
                "#{include_element.attributes['href'].inspect}"
        end
        if include_element.attributes["xpointer"]
          raise ConfigurationError,
                "xi:include xpointer attribute is not supported"
        end
        parse = include_element.attributes["parse"]
        if parse && !%w[xml text].include?(parse.downcase)
          raise ConfigurationError,
                "xi:include parse must be 'xml' or 'text', got #{parse.inspect}"
        end

        fallbacks = include_element.children.select do |child|
          xinclude_named?(child, "fallback")
        end
        if fallbacks.size > 1
          raise ConfigurationError,
                "xi:include has #{fallbacks.size} fallback children, at most one is allowed"
        end
        include_element.children.each do |child|
          next unless child.is_a?(REXML::Element)
          unless xinclude_named?(child, "fallback")
            raise ConfigurationError,
                  "xi:include may only contain xi:fallback elements, " \
                  "found <#{child.expanded_name}>"
          end
        end
      end

      def xinclude_element?(element)
        xinclude_named?(element, "include")
      end

      def xinclude_named?(node, local_name)
        node.is_a?(REXML::Element) &&
          node.namespace == XINCLUDE_NAMESPACE &&
          node.local_name == local_name
      end

      def active_chain_contains?(context, uri)
        node = context.included_by
        while node
          return true if node.uri == uri
          node = node.included_by
        end
        false
      end

      def resolve_element_base(element, parent_base)
        attribute = element.attributes["xml:base"]
        return parent_base unless attribute
        # A base URI is itself a normalized URI reference (RFC 3986 5.3.3),
        # so resolve and strip dot segments before it becomes the new base.
        normalized = resolve_reference(parent_base, attribute)
        normalize_uri(normalized)
      end

      def normalize_uri(uri)
        parts = split_uri(uri)
        parts[:path] = remove_dot_segments(parts[:path])
        join_uri(parts)
      end

      # RFC 3986 Section 5 reference resolution.  Implemented locally instead
      # of relying on URI.join so custom in-memory schemes and relative bases
      # behave exactly like ordinary HTTP URIs.
      def resolve_reference(base, reference)
        return reference if base.nil? || base.empty?

        reference = reference.to_s
        if reference.empty?
          return remove_fragment(base)
        end

        base_parts = split_uri(base)
        ref_parts = split_uri(reference)

        if ref_parts[:scheme]
          target = ref_parts.merge(path: remove_dot_segments(ref_parts[:path]))
        else
          target = base_parts.dup
          target[:query] = ref_parts[:query]
          target[:fragment] = ref_parts[:fragment]
          if ref_parts[:authority]
            target[:authority] = ref_parts[:authority]
            target[:path] = remove_dot_segments(ref_parts[:path])
          else
            if ref_parts[:path].empty?
              target[:path] = base_parts[:path]
            else
              target[:path] = remove_dot_segments(
                ref_parts[:path].start_with?("/") ?
                  ref_parts[:path] : merge_path(base_parts, ref_parts[:path]))
            end
            target[:authority] = base_parts[:authority]
          end
          target[:scheme] = base_parts[:scheme]
        end
        join_uri(target)
      end

      # RFC 3986 Section 5.3 component split: scheme, authority, path, query,
      # fragment.
      URI_SPLIT =
        /\A(?:([^:\/?#]+):)?(?:\/\/([^\/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?\z/

      def split_uri(uri)
        match = URI_SPLIT.match(uri)
        {
          scheme: match[1],
          authority: match[2],
          path: match[3] || "",
          query: match[4],
          fragment: match[5],
        }
      end

      def join_uri(parts)
        uri = +""
        uri << "#{parts[:scheme]}:" if parts[:scheme]
        if parts[:authority]
          uri << "//#{parts[:authority]}"
        end
        uri << parts[:path]
        uri << "?#{parts[:query]}" if parts[:query]
        uri << "##{parts[:fragment]}" if parts[:fragment]
        uri
      end

      def merge_path(base_parts, reference_path)
        if base_parts[:authority] && base_parts[:path].empty?
          "/#{reference_path}"
        else
          index = base_parts[:path].rindex("/")
          prefix = index ? base_parts[:path][0, index + 1] : ""
          "#{prefix}#{reference_path}"
        end
      end

      # RFC 3986 Section 5.2.4 remove_dot_segments.
      def remove_dot_segments(path)
        output = []
        input = path.dup
        while input != ""
          case
          when input.start_with?("../")
            input = input[3..]
          when input.start_with?("./")
            input = input[2..]
          when input.start_with?("/./")
            input = "/" + input[3..]
          when input == "/."
            input = "/"
          when input.start_with?("/../")
            input = "/" + input[4..]
            output.pop
          when input == "/.."
            input = "/"
            output.pop
          when input == ".", input == ".."
            input = ""
          else
            segment_end = input.index("/", 1)
            if segment_end
              output << input[0, segment_end]
              input = input[segment_end..]
            else
              output << input
              input = ""
            end
          end
        end
        output.join
      end

      def remove_fragment(uri)
        uri.sub(/#.*/, "")
      end

      def clone_node(node)
        node.is_a?(REXML::Parent) ? node.deep_clone : node.clone
      end
    end

    module_function

    # Expands all XInclude elements in a copy of +document+.
    #
    # @param document [REXML::Document] document containing xi:include elements
    # @param resolver [Object, Proc] resource provider; see XInclude overview
    # @param options [Hash] processor options, see Processor#initialize
    # @return [Result]
    # @raise [Error] on fatal XInclude errors
    def include(document, resolver, **options)
      Processor.new(resolver, **options).process(document)
    end
  end
end
