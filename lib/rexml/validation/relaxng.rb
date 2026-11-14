# frozen_string_literal: false
require_relative "validation"
require_relative "../parsers/baseparser"

module REXML
  module Validation
    # Implemented:
    # * empty
    # * element
    # * attribute
    # * text
    # * optional
    # * choice
    # * oneOrMore
    # * zeroOrMore
    # * group
    # * value
    # * interleave
    # * mixed
    # * ref
    # * grammar
    # * start
    # * define
    #
    # Not implemented:
    # * data
    # * param
    # * include
    # * externalRef
    # * notAllowed
    # * anyName
    # * nsName
    # * except
    # * name
    #
    # Pass <tt>strict: true</tt> to enable strict compilation.  The default
    # (permissive) mode silently ignores constructs that it does not
    # implement.  That is dangerous when a schema is used as an admission
    # control: a constraint such as <tt>data</tt> or <tt>notAllowed</tt> is
    # dropped and the corresponding XML is accepted.
    #
    # Strict mode compiles the whole schema before any XML is validated and
    # raises RelaxNG::CompileError for every construct or composition that
    # this validator cannot enforce faithfully, instead of treating it as an
    # empty rule.  In particular it refuses:
    #
    # * unimplemented constructs such as <tt>data</tt>, <tt>param</tt>,
    #   <tt>notAllowed</tt>, <tt>anyName</tt>, <tt>nsName</tt>,
    #   <tt>except</tt>, <tt>include</tt>, and <tt>externalRef</tt>;
    # * constraints it knows are dropped or mis-executed, such as
    #   <tt>ns</tt>, narrowed <tt>value</tt>, <tt>mixed</tt> content other
    #   than one element, <tt>group</tt> under a repetition, and
    #   <tt>choice</tt> under a repetition;
    # * undefined and non-productive recursive references;
    # * RELAX NG constructs in the wrong namespace.
    #
    # Foreign-namespace elements are treated as annotations only when they
    # are not RELAX NG constructs.  Errors report the construct, its line and
    # column, and its path in the schema:
    #
    #   begin
    #     RelaxNG.new(schema, strict: true)
    #   rescue RelaxNG::CompileError => error
    #     error.construct # => "data"
    #     error.line      # => 6
    #     error.path      # => "/grammar/start/element/attribute/data"
    #   end
    #
    class RelaxNG
      include Validator

      class CompileError < ValidationException
        attr_reader :construct, :line, :column, :path

        def initialize( message, construct=nil, line=nil, column=nil, path=nil )
          @construct = construct
          @line = line
          @column = column
          @path = path
          location = +""
          location << " at line #{line}, column #{column}" if line
          location << " (schema path: #{path})" if path
          super("#{message}#{location}")
        end
      end

      INFINITY = 1.0 / 0.0
      EMPTY = Event.new( nil )
      TEXT = [:start_element, "text"]
      attr_accessor :current
      attr_accessor :count
      attr_reader :references

      def initialize( source, strict: false )
        @strict = strict ? true : false
        if @strict
          build_from_ast( StrictCompiler.new(source).compile )
        else
          build( source )
        end
        self
      end

      def strict?
        @strict
      end

      private def build( source )
        parser = REXML::Parsers::BaseParser.new( source )
        events = []
        loop do
          event = parser.pull
          events << event
          break if event[0] == :end_document
        end
        build_events( events )
      end
      private :build

      private def build_from_ast( root )
        events = []
        serialize_ast( root, events )
        events << [ :end_document ]
        build_events( events )
      end

      private def serialize_ast( node, events )
        case node.kind
        when "grammar", "start", "define", "element", "attribute",
             "optional", "choice", "oneOrMore", "zeroOrMore", "group",
             "interleave", "mixed", "ref"
          attributes = {}
          attributes["name"] = node.attributes["name"] if node.attributes["name"]
          events << [ :start_element, node.kind, attributes ]
          node.children.each { |child| serialize_ast( child, events ) }
          events << [ :end_element, node.kind ]
        when "text", "empty"
          events << [ :start_element, node.kind, {} ]
          events << [ :end_element, node.kind ]
        when "value"
          events << [ :start_element, node.kind, {} ]
          events << [ :text, node.value.to_s ]
          events << [ :end_element, node.kind ]
        end
      end

      private def build_events( events )
        @count = 0
        @references = {}
        @root = @current = Sequence.new(self)
        @root.previous = true
        states = [ @current ]
        events.each do |event|
          case event[0]
          when :start_element
            case event[1]
            when "empty"
            when "element", "attribute", "text", "value"
              states[-1] << event
            when "optional"
              states << Optional.new( self )
              states[-2] << states[-1]
            when "choice"
              states << Choice.new( self )
              states[-2] << states[-1]
            when "oneOrMore"
              states << OneOrMore.new( self )
              states[-2] << states[-1]
            when "zeroOrMore"
              states << ZeroOrMore.new( self )
              states[-2] << states[-1]
            when "group"
              states << Sequence.new( self )
              states[-2] << states[-1]
            when "interleave"
              states << Interleave.new( self )
              states[-2] << states[-1]
            when "mixed"
              states << Interleave.new( self )
              states[-2] << states[-1]
              states[-1] << TEXT
            when "define"
              states << [ event[2]["name"] ]
            when "ref"
              states[-1] << Ref.new( event[2]["name"] )
            when "anyName"
              states << AnyName.new( self )
              states[-2] << states[-1]
            when "nsName"
            when "except"
            when "name"
            when "data"
            when "param"
            when "include"
            when "grammar"
            when "start"
            when "externalRef"
            when "notAllowed"
            end
          when :end_element
            case event[1]
            when "element", "attribute"
              states[-1] << event
            when "zeroOrMore", "oneOrMore", "choice", "optional",
              "interleave", "group", "mixed"
              states.pop
            when "define"
              ref = states.pop
              @references[ ref.shift ] = ref
            #when "empty"
            end
          when :end_document
            states[-1] << event
          when :text
            states[-1] << event
          end
        end
      end
      private :build_events

      def receive event
        validate( event )
      end

      # Compiles a RELAX NG schema into the small AST that this validator
      # can execute faithfully.  It refuses everything else.
      class StrictCompiler
        RNG_NAMESPACE = "http://relaxng.org/ns/structure/1.0"

        SUPPORTED_CONSTRUCTS = %w[
          element attribute text value empty optional choice oneOrMore
          zeroOrMore group interleave mixed ref grammar start define
        ].freeze

        UNSUPPORTED_CONSTRUCTS = %w[
          data param include externalRef notAllowed anyName nsName except
          name list string token
        ].freeze

        Node = Struct.new( :kind, :attributes, :children, :value,
                           :line, :column, :path )
        Frame = Struct.new( :node, :skip )

        def initialize( source )
          @source = source
          if source.respond_to?(:to_str)
            @raw_source = source.to_str
          else
            @raw_source = nil
          end
        end

        def compile
          root = parse
          unless root
            raise_compile_error("No RELAX NG schema pattern found", nil)
          end
          if root.kind == "grammar"
            validate_grammar(root)
          else
            scope = Scope.new({})
            validate_node(root, scope, :element_content)
            check_recursion(root, scope, [])
          end
          root
        end

        private
        Scope = Struct.new( :defines )

        def parse
          parser = REXML::Parsers::BaseParser.new(@source)
          namespaces = [ { "xml" => "http://www.w3.org/XML/1998/namespace" } ]
          stack = []
          root = nil

          loop do
            offset = parser.position
            event = parser.pull
            case event[0]
            when :start_element
              raw_name = event[1]
              prefix, local_name = split_name(raw_name)
              parent_namespaces = namespaces[-1]
              merged_namespaces = parent_namespaces.dup
              event[2].each do |key, value|
                if key == "xmlns"
                  merged_namespaces[""] = value
                elsif key.start_with?("xmlns:")
                  merged_namespaces[key[6..-1]] = value
                end
              end
              namespaces << merged_namespaces
              namespace = merged_namespaces[prefix || ""]

              parent_frame = stack[-1]
              if parent_frame and parent_frame.skip
                stack << Frame.new( nil, true )
                next
              end

              if namespace == RNG_NAMESPACE
                unless SUPPORTED_CONSTRUCTS.include?(local_name)
                  raise_compile_error(
                    "Unsupported RELAX NG construct <#{local_name}>: " \
                    "strict mode cannot enforce it and will not ignore it",
                    nil, nil, nil, nil, local_name, offset, stack
                  )
                end
                node = Node.new( local_name, clean_attributes(event[2]),
                                 [], nil, nil, nil, nil )
                node.line, node.column = line_and_column(offset)
                node.path = schema_path(stack, local_name)
                parent_node = parent_frame ? parent_frame.node : nil
                if parent_node
                  parent_node.children << node
                elsif root
                  raise_compile_error(
                    "Multiple top-level RELAX NG patterns are not supported " \
                    "in strict mode",
                    node, nil, nil, nil, local_name, offset, stack
                  )
                else
                  root = node
                end
                stack << Frame.new( node, false )
              else
                if (SUPPORTED_CONSTRUCTS + UNSUPPORTED_CONSTRUCTS).include?(local_name)
                  raise_compile_error(
                    "RELAX NG construct <#{local_name}> is not in the " \
                    "RELAX NG namespace (resolved namespace: " \
                    "#{namespace.inspect}); strict mode cannot enforce it",
                    nil, nil, nil, nil, local_name, offset, stack
                  )
                end
                # Foreign elements are annotation; their contents are not
                # RELAX NG constraints.
                stack << Frame.new( nil, true )
              end
            when :text
              frame = stack[-1]
              if frame and frame.node and frame.node.kind == "value"
                frame.node.value ||= +""
                frame.node.value << event[1]
              end
            when :end_element
              namespaces.pop
              stack.pop
            when :end_document
              break
            end
          end

          root
        end

        def split_name( name )
          if name.include?(":")
            name.split(":", 2)
          else
            [ nil, name ]
          end
        end

        def clean_attributes( attributes )
          attributes.each_with_object({}) do |(key, value), cleaned|
            next if key == "xmlns" or key.start_with?("xmlns:")
            cleaned[key] = value
          end
        end

        def line_and_column( offset )
          return [ nil, nil ] unless @raw_source
          prefix = @raw_source.byteslice(0, offset) || ""
          line = prefix.count("\n") + 1
          last_newline = prefix.rindex("\n")
          column = offset - (last_newline ? last_newline + 1 : 0) + 1
          [ line, column ]
        end

        def schema_path( stack, kind )
          parts = stack.collect do |frame|
            frame.node.kind if frame.node
          end.compact
          parts << kind
          "/" + parts.join("/")
        end

        def validate_grammar( grammar )
          start = nil
          defines = {}
          grammar.children.each do |child|
            case child.kind
            when "start"
              if start
                raise_compile_error(
                  "A <grammar> must contain exactly one <start>",
                  child
                )
              end
              validate_no_attributes( child, [ "combine" ] )
              if child.attributes.key?("combine")
                raise_compile_error(
                  "The <start combine=\"...\"> constraint is not supported " \
                  "in strict mode",
                  child
                )
              end
              start = child
            when "define"
              name = required_name( child, "define" )
              if defines.key?(name)
                raise_compile_error(
                  "Duplicate RELAX NG definition #{name.inspect}",
                  child, name
                )
              end
              if child.attributes.key?("combine")
                raise_compile_error(
                  "The <define combine=\"...\"> constraint is not supported " \
                  "in strict mode for definition #{name.inspect}",
                  child, name
                )
              end
              validate_no_attributes( child, [ "name" ] )
              if child.children.empty?
                raise_compile_error(
                  "Definition #{name.inspect} is empty; strict mode will " \
                  "not treat it as an empty rule",
                  child, name
                )
              end
              defines[name] = child
            else
              raise_compile_error(
                "<#{child.kind}> is not allowed directly in <grammar>; " \
                "only <start> and <define> are supported in strict mode",
                child
              )
            end
          end

          unless start
            raise_compile_error(
              "A <grammar> must contain a <start> pattern",
              grammar
            )
          end
          if start.children.empty?
            raise_compile_error(
              "The <start> pattern is empty; strict mode will not accept " \
              "an empty document rule",
              start
            )
          end

          scope = Scope.new(defines)
          defines.each_value do |define|
            validate_sequence( define.children, scope, :element_content )
          end
          validate_sequence( start.children, scope, :element_content )

          start.children.each { |child| check_recursion( child, scope, [] ) }
          defines.each do |name, define|
            define.children.each do |child|
              check_recursion( child, scope, [ name ] )
            end
          end
        end

        def validate_node( node, scope, context )
          case node.kind
          when "grammar", "start", "define"
            raise_compile_error(
              "<#{node.kind}> is only allowed directly in <grammar>",
              node
            )
          when "element", "attribute"
            validate_element_or_attribute( node, scope, context )
          when "text"
            unless context == :element_content or context == :attribute_content
              raise_compile_error(
                "<text> is not supported in this position in strict mode",
                node
              )
            end
            validate_leaf( node )
          when "empty"
            validate_leaf( node )
          when "value"
            unless context == :element_content or context == :attribute_content
              raise_compile_error(
                "<value> is not supported in this position in strict mode",
                node
              )
            end
            validate_value( node )
          when "ref"
            validate_ref( node, scope )
          when "group"
            validate_no_attributes( node, [] )
            validate_sequence( node.children, scope, :element_content )
          when "optional"
            validate_no_attributes( node, [] )
            if node.children.empty?
              raise_compile_error(
                "<optional> must contain a pattern",
                node
              )
            end
            validate_sequence( node.children, scope, :element_content )
          when "oneOrMore", "zeroOrMore"
            validate_repetition( node, scope )
          when "choice"
            validate_choice( node, scope, context )
          when "interleave"
            validate_interleave( node, scope, context )
          when "mixed"
            unless context == :sole_element_content
              raise_compile_error(
                "<mixed> is only supported as the sole content of an " \
                "element in strict mode; in a sequence the compiled rule " \
                "makes text mandatory and would reject valid documents",
                node
              )
            end
            validate_mixed( node, scope )
          else
            raise_compile_error(
              "Unsupported RELAX NG construct <#{node.kind}>",
              node
            )
          end
        end

        def validate_leaf( node )
          validate_no_attributes( node, [] )
          unless node.children.empty?
            raise_compile_error(
              "<#{node.kind}> cannot contain child patterns in strict mode",
              node
            )
          end
        end

        def validate_element_or_attribute( node, scope, context )
          name = required_name( node, node.kind )
          if name.include?(":")
            raise_compile_error(
              "The #{node.kind} name #{name.inspect} uses a namespace " \
              "prefix; this validator enforces only unprefixed names and " \
              "strict mode will not silently drop the namespace constraint",
              node, name
            )
          end
          if node.attributes.key?("ns")
            raise_compile_error(
              "The #{node.kind} namespace constraint " \
              "ns=#{node.attributes["ns"].inspect} is not supported in " \
              "strict mode for #{name.inspect}",
              node, name
            )
          end
          validate_no_attributes( node, [ "name" ] )

          if node.kind == "attribute"
            if context == :attribute_content
              raise_compile_error(
                "An <attribute> cannot appear inside attribute content " \
                "in strict mode",
                node, name
              )
            end
            validate_attribute_content( node, scope )
            return
          end

          if node.children.empty?
            # <element name="X"/> is an explicit empty element in RELAX NG
            # (shorthand for <empty/>); the compiled rule enforces that.
            return
          end
          if node.children.length == 1 and
             node.children[0].kind == "empty"
            validate_leaf( node.children[0] )
            return
          end
          if node.children.length > 1 and
             node.children.all? { |c| c.kind == "empty" }
            raise_compile_error(
              "Element #{name.inspect} has only empty content patterns; " \
              "strict mode will not reduce them to an unconstrained rule",
              node, name
            )
          end
          if node.children.length == 1 and node.children[0].kind == "mixed"
            validate_node( node.children[0], scope, :sole_element_content )
            return
          end
          if node.children.length == 1 and node.children[0].kind == "optional" and
             node.children[0].children.length == 1 and
             node.children[0].children[0].kind == "mixed"
            validate_no_attributes( node.children[0], [] )
            validate_node( node.children[0].children[0], scope,
                           :sole_element_content )
            return
          end
          validate_sequence( node.children, scope, :element_content )
        end

        def validate_attribute_content( node, scope )
          content = node.children
          if content.empty?
            # <attribute name="X"/> accepts any value for X.
            return
          end
          unless content.length == 1
            raise_compile_error(
              "Attribute #{node.attributes["name"].inspect} has multiple " \
              "content patterns; strict mode cannot enforce attribute " \
              "content built from a sequence",
              node, node.attributes["name"]
            )
          end
          validate_attribute_content_pattern(
            content[0], node, scope, :attribute_content
          )
        end

        def validate_attribute_content_pattern( child, attribute, scope, context )
          case child.kind
          when "text"
            validate_leaf( child )
          when "value"
            validate_value( child )
          when "choice"
            validate_choice( child, scope, :attribute_content )
          when "ref"
            raise_compile_error(
              "Attribute #{attribute.attributes["name"].inspect} uses a " \
              "<ref> for its content; this validator crashes on attribute " \
              "references, so strict mode rejects the schema instead of " \
              "accepting values it cannot check",
              child
            )
          when "oneOrMore"
            if child.children.length == 1 and
               child.children[0].kind == "value" and
               child.children[0].attributes.empty?
              validate_value( child.children[0] )
            else
              raise_compile_error(
                "Attribute #{attribute.attributes["name"].inspect} has a " \
                "repetition that accepts values other than one literal; " \
                "strict mode cannot enforce its content",
                child
              )
            end
          when "group"
            if child.children.length == 1
              validate_attribute_content_pattern(
                child.children[0], attribute, scope, context
              )
            else
              raise_compile_error(
                "Attribute #{attribute.attributes["name"].inspect} has a " \
                "sequence of content patterns; the compiled rule does not " \
                "concatenate attribute values, so strict mode rejects it",
                child
              )
            end
          when "zeroOrMore", "optional", "empty", "interleave"
            raise_compile_error(
              "Attribute #{attribute.attributes["name"].inspect} has " \
              "<#{child.kind}> content; the compiled rule accepts values " \
              "other than the literal alternatives, so strict mode rejects it",
              child
            )
          else
            raise_compile_error(
              "Attribute #{attribute.attributes["name"].inspect} has " \
              "<#{child.kind}> content that cannot be enforced faithfully " \
              "in strict mode",
              child
            )
          end
        end


        def validate_value( node )
          unless node.attributes.empty?
            attribute = node.attributes.keys.first
            raise_compile_error(
              "The <value> #{attribute}=#{node.attributes[attribute].inspect} " \
              "constraint is not supported in strict mode; only literal " \
              "values can be enforced",
              node, attribute
            )
          end
          unless node.children.empty?
            raise_compile_error(
              "<value> cannot contain child patterns in strict mode",
              node
            )
          end
          if node.value.nil? or node.value.empty?
            raise_compile_error(
              "An empty <value> cannot be enforced by this validator; the " \
              "compiled rule never matches an empty string",
              node
            )
          end
        end

        def validate_ref( node, scope )
          name = required_name( node, "ref" )
          validate_no_attributes( node, [ "name" ] )
          unless scope.defines.key?(name)
            raise_compile_error(
              "Undefined RELAX NG reference #{name.inspect}; strict mode " \
              "will not silently ignore it",
              node, name
            )
          end
        end

        def validate_sequence( children, scope, context )
          seen_non_attributes = false
          children.each do |child|
            if child.kind == "attribute"
              if seen_non_attributes
                raise_compile_error(
                  "An <attribute> appears after element or text content; " \
                  "the validator cannot enforce it in that position",
                  child, child.attributes["name"]
                )
              end
            elsif child.kind != "empty"
              seen_non_attributes = true
            end
            validate_node( child, scope, context )
          end
        end

        def validate_repetition( node, scope )
          validate_no_attributes( node, [] )
          if node.children.empty?
            raise_compile_error(
              "<#{node.kind}> must contain a pattern",
              node
            )
          end
          if node.children.length > 1
            # Multiple children form a sequence repeated as a unit, which
            # matches RELAX NG. The compiled engine handles that for
            # element, attribute, text, and value children.
            node.children.each do |child|
              case child.kind
              when "element", "attribute"
                validate_node( child, scope, :element_content )
              when "ref"
                validate_node( child, scope, :element_content )
              when "text"
                validate_leaf( child )
              when "value"
                validate_value( child )
              else
                raise_compile_error(
                  "<#{child.kind}> inside a multi-pattern " \
                  "<#{node.kind}> cannot be repeated faithfully in strict " \
                  "mode; wrap the sequence in <group> to make the repetition " \
                  "intent explicit, or use one pattern",
                  child
                )
              end
            end
            return
          end
          child = node.children[0]
          case child.kind
          when "element", "attribute"
            validate_node( child, scope, :element_content )
          when "ref"
            validate_node( child, scope, :element_content )
          when "group"
            validate_repeatable_group( child, scope )
          when "choice"
            raise_compile_error(
              "A <choice> directly inside <#{node.kind}> cannot be " \
              "enforced faithfully by this validator; repeat each " \
              "alternative separately",
              child
            )
          when "text"
            validate_leaf( child )
          when "value"
            validate_value( child )
          when "optional", "empty"
            raise_compile_error(
              "<#{child.kind}> inside <#{node.kind}> cannot be enforced " \
              "faithfully in strict mode",
              child
            )
          else
            raise_compile_error(
              "<#{child.kind}> inside <#{node.kind}> cannot be enforced " \
              "faithfully in strict mode",
              child
            )
          end
        end

        def validate_repeatable_group( node, scope )
          raise_compile_error(
            "A <group> inside <oneOrMore> or <zeroOrMore> cannot be " \
            "enforced faithfully by this validator; put the repetition " \
            "inside the group instead",
            node
          )
        end

        def validate_choice( node, scope, context )
          validate_no_attributes( node, [] )
          if node.children.empty?
            raise_compile_error(
              "<choice> must contain at least one pattern",
              node
            )
          end

          signatures = {}
          node.children.each do |child|
            case child.kind
            when "optional", "zeroOrMore", "oneOrMore", "empty", "mixed"
              raise_compile_error(
                "<#{child.kind}> as a <choice> alternative can match no " \
                "event or be partially optional; strict mode cannot enforce " \
                "this ordering",
                child
              )
            end
            if leading_nullable?( child, scope, [] )
              raise_compile_error(
                "A <choice> alternative beginning with <#{child.kind}> can " \
                "match no event; strict mode cannot enforce this ordering",
                child
              )
            end
            starts = start_signatures( child, scope, [] )
            if starts.nil? or starts.empty?
              raise_compile_error(
                "Cannot determine the starting event of a <choice> " \
                "alternative",
                child
              )
            end
            starts.each do |signature|
              if signatures.key?(signature)
                raise_compile_error(
                  "Ambiguous <choice>: multiple alternatives can start with " \
                  "#{describe_signature(signature)}",
                  child
                )
              end
              signatures[signature] = child
            end
            validate_node( child, scope, context )
          end
        end

        def validate_interleave( node, scope, context )
          validate_no_attributes( node, [] )
          if node.children.empty?
            raise_compile_error(
              "<interleave> must contain at least one pattern",
              node
            )
          end
          if context == :attribute_content
            raise_compile_error(
              "<interleave> inside attribute content cannot be enforced " \
              "faithfully in strict mode",
              node
            )
          end
          signatures = {}
          node.children.each do |child|
            case child.kind
            when "element", "attribute", "text"
              starts = start_signatures( child, scope, [] )
              starts.each do |signature|
                if signatures.key?(signature)
                  raise_compile_error(
                    "Ambiguous <interleave>: multiple branches can start " \
                    "with #{describe_signature(signature)}",
                    child
                  )
                end
                signatures[signature] = child
              end
              validate_node( child, scope, context )
            when "ref"
              validate_ref( child, scope )
              validate_interleave_definition(
                scope.defines[child.attributes["name"]], node, scope, []
              )
            else
              raise_compile_error(
                "<#{child.kind}> as an <interleave> branch cannot be " \
                "enforced faithfully in strict mode",
                child
              )
            end
          end
        end

        def validate_interleave_definition( define, node, scope, seen )
          return if define.nil?
          if seen.include?(define)
            raise_compile_error(
              "Recursive definition #{define.attributes["name"].inspect} " \
              "inside <interleave> cannot be enforced faithfully",
              define, define.attributes["name"]
            )
          end
          seen = seen + [ define ]
          define.children.each do |child|
            case child.kind
            when "element", "attribute"
              # Each top-level pattern is an independent interleave branch.
            when "ref"
              target = scope.defines[child.attributes["name"]]
              validate_interleave_definition( target, node, scope, seen )
            else
              raise_compile_error(
                "Definition #{define.attributes["name"].inspect} contains " \
                "<#{child.kind}>, which cannot be interleaved faithfully " \
                "in strict mode",
                child, define.attributes["name"]
              )
            end
          end
        end


        def validate_mixed( node, scope )
          validate_no_attributes( node, [] )
          if node.children.length != 1 or node.children[0].kind != "element"
            raise_compile_error(
              "<mixed> must contain exactly one <element> in strict mode; " \
              "empty, text, value, multiple, and attribute content " \
              "cannot be enforced faithfully",
              node
            )
          end
          validate_element_or_attribute( node.children[0], scope, :mixed )
        end

        def validate_no_attributes( node, allowed )
          node.attributes.each_key do |name|
            next if allowed.include?(name)
            raise_compile_error(
              "Unsupported RELAX NG attribute " \
              "#{name}=#{node.attributes[name].inspect} on <#{node.kind}> " \
              "in strict mode",
              node, node.attributes["name"] || name
            )
          end
        end

        def required_name( node, construct )
          name = node.attributes["name"]
          if name.nil? or name.empty?
            raise_compile_error(
              "<#{construct}> requires a non-empty name attribute in strict " \
              "mode",
              node
            )
          end
          name
        end

        def leading_nullable?( node, scope, seen )
          case node.kind
          when "element", "attribute", "text", "value"
            false
          when "empty", "optional", "zeroOrMore"
            true
          when "oneOrMore"
            node.children.empty? or leading_nullable?( node.children[0], scope, seen )
          when "group"
            node.children.each do |child|
              next if child.kind == "empty"
              return leading_nullable?( child, scope, seen )
            end
            true
          when "choice"
            node.children.any? { |child| leading_nullable?( child, scope, seen ) }
          when "interleave", "mixed"
            false
          when "ref"
            define = scope.defines[node.attributes["name"]]
            return true if define.nil? or seen.include?(define)
            if define.children.empty?
              true
            else
              leading_nullable?( define.children[0], scope, seen + [ define ] )
            end
          else
            true
          end
        end

        def start_signatures( node, scope, seen )
          case node.kind
          when "element"
            [ [ :element, node.attributes["name"] ] ]
          when "attribute"
            [ [ :attribute, node.attributes["name"] ] ]
          when "value"
            [ [ :text, node.value.to_s ] ]
          when "text"
            [ [ :text, nil ] ]
          when "empty"
            []
          when "group"
            node.children.each do |child|
              next if child.kind == "empty"
              return start_signatures( child, scope, seen )
            end
            []
          when "choice"
            node.children.collect { |child| start_signatures( child, scope, seen ) }.flatten(1)
          when "interleave"
            node.children.collect { |child| start_signatures( child, scope, seen ) }.flatten(1)
          when "optional", "zeroOrMore", "oneOrMore"
            node.children.collect { |child| start_signatures( child, scope, seen ) }.flatten(1)
          when "mixed"
            []
          when "ref"
            define = scope.defines[node.attributes["name"]]
            return nil if define.nil? or seen.include?(define)
            define.children.collect do |child|
              start_signatures( child, scope, seen + [ define ] )
            end.flatten(1)
          else
            nil
          end
        end

        def describe_signature( signature )
          type, argument = signature
          case type
          when :element
            "element <#{argument}>"
          when :attribute
            "attribute #{argument.inspect}"
          when :text
            argument.nil? ? "text" : "value #{argument.inspect}"
          else
            signature.inspect
          end
        end

        # Returns true when the pattern always consumes at least one event.
        # "consumed" tracks whether input has already been consumed on the
        # current path, so recursive references after an element, attribute,
        # text, or value are allowed; recursion that can expand without
        # consuming input is refused.
        def check_recursion( node, scope, active, consumed=false )
          case node.kind
          when "element", "attribute"
            node.children.each do |child|
              check_recursion( child, scope, active, true )
            end
            true
          when "text", "value"
            true
          when "empty"
            false
          when "ref"
            name = node.attributes["name"]
            define = scope.defines[name]
            return false if define.nil?
            if active.include?(define) and !consumed
              raise_compile_error(
                "Recursive reference to definition #{name.inspect} can " \
                "expand without consuming input; strict mode will not accept " \
                "a schema that cannot make progress",
                node, name
              )
            end
            return false if active.include?(define)
            define.children.any? do |child|
              check_recursion( child, scope, active + [ define ], consumed )
            end
          when "group"
            children = node.children
            result = false
            current_consumed = consumed
            children.each do |child|
              child_consumes =
                check_recursion( child, scope, active, current_consumed )
              result ||= child_consumes
              current_consumed ||= child_consumes
            end
            result
          when "oneOrMore"
            node.children.any? do |child|
              check_recursion( child, scope, active, consumed )
            end
          when "optional", "zeroOrMore"
            node.children.each do |child|
              check_recursion( child, scope, active, consumed )
            end
            false
          when "choice", "interleave", "mixed"
            node.children.any? do |child|
              check_recursion( child, scope, active, consumed )
            end
          else
            false
          end
        end

        def raise_compile_error( message, node, construct=nil,
                                 line=nil, column=nil, kind=nil,
                                 offset=nil, stack=nil )
          path = nil
          if node
            path = node.path
            line ||= node.line
            column ||= node.column
            kind ||= node.kind
          elsif offset
            line, column = line_and_column( offset )
            path = schema_path( stack || [], kind )
          end
          raise CompileError.new( message, kind, line, column, path )
        end
      end
    end

    class State
      def initialize( context )
        @previous = []
        @events = []
        @current = 0
        @count = context.count += 1
        @references = context.references
        @value = false
      end

      def reset
        return if @current == 0
        @current = 0
        @events.each {|s| s.reset if s.kind_of? State }
      end

      def previous=( previous )
        @previous << previous
      end

      def next( event )
        #print "In next with #{event.inspect}.  "
        #p @previous
        return @previous.pop.next( event ) if @events[@current].nil?
        expand_ref_in( @events, @current ) if @events[@current].class == Ref
        if ( @events[@current].kind_of? State )
          @current += 1
          @events[@current-1].previous = self
          return @events[@current-1].next( event )
        end
        if ( @events[@current].matches?(event) )
          @current += 1
          if @events[@current].nil?
            @previous.pop
          elsif @events[@current].kind_of? State
            @current += 1
            @events[@current-1].previous = self
            @events[@current-1]
          else
            self
          end
        else
          nil
        end
      end

      def to_s
        # Abbreviated:
        self.class.name =~ /(?:::)(\w)\w+$/
        # Full:
        #self.class.name =~ /(?:::)(\w+)$/
        "#$1.#@count"
      end

      def inspect
        "< #{to_s} #{@events.collect{|e|
          pre = e == @events[@current] ? '#' : ''
          pre + e.inspect unless self == e
        }.join(', ')} >"
      end

      def expected
        [@events[@current]]
      end

      def <<( event )
        add_event_to_arry( @events, event )
      end


      protected
      def expand_ref_in( arry, ind )
        new_events = []
        @references[ arry[ind].to_s ].each{ |evt|
          add_event_to_arry(new_events,evt)
        }
        arry[ind,1] = new_events
      end

      def add_event_to_arry( arry, evt )
        evt = generate_event( evt )
        if evt.kind_of? String
          arry[-1].event_arg = evt if arry[-1].kind_of? Event and @value
          @value = false
        else
          arry << evt
        end
      end

      def generate_event( event )
        return event if event.kind_of? State or event.class == Ref
        evt = nil
        arg = nil
        case event[0]
        when :start_element
          case event[1]
          when "element"
            evt = :start_element
            arg = event[2]["name"]
          when "attribute"
            evt = :start_attribute
            arg = event[2]["name"]
          when "text"
            evt = :text
          when "value"
            evt = :text
            @value = true
          end
        when :text
          return event[1]
        when :end_document
          return Event.new( event[0] )
        else # then :end_element
          case event[1]
          when "element"
            evt = :end_element
          when "attribute"
            evt = :end_attribute
          end
        end
        Event.new( evt, arg )
      end
    end


    class Sequence < State
      def matches?(event)
        @events[@current].matches?( event )
      end
    end


    class Optional < State
      def next( event )
        if @current == 0
          rv = super
          return rv if rv
          @prior = @previous.pop
          @prior.next( event )
        else
          super
        end
      end

      def matches?(event)
        @events[@current].matches?(event) ||
        (@current == 0 and @previous[-1].matches?(event))
      end

      def expected
        return [ @prior.expected, @events[0] ].flatten if @current == 0
        [@events[@current]]
      end
    end


    class ZeroOrMore < Optional
      def next( event )
        expand_ref_in( @events, @current ) if @events[@current].class == Ref
        if ( @events[@current].matches?(event) )
          @current += 1
          if @events[@current].nil?
            @current = 0
            self
          elsif @events[@current].kind_of? State
            @current += 1
            @events[@current-1].previous = self
            @events[@current-1]
          else
            self
          end
        else
          @prior = @previous.pop
          return @prior.next( event ) if @current == 0
          nil
        end
      end

      def expected
        return [ @prior.expected, @events[0] ].flatten if @current == 0
        [@events[@current]]
      end
    end


    class OneOrMore < State
      def initialize context
        super
        @ord = 0
      end

      def reset
        super
        @ord = 0
      end

      def next( event )
        expand_ref_in( @events, @current ) if @events[@current].class == Ref
        if ( @events[@current].matches?(event) )
          @current += 1
          @ord += 1
          if @events[@current].nil?
            @current = 0
            self
          elsif @events[@current].kind_of? State
            @current += 1
            @events[@current-1].previous = self
            @events[@current-1]
          else
            self
          end
        else
          return @previous.pop.next( event ) if @current == 0 and @ord > 0
          nil
        end
      end

      def matches?( event )
        @events[@current].matches?(event) ||
        (@current == 0 and @ord > 0 and @previous[-1].matches?(event))
      end

      def expected
        if @current == 0 and @ord > 0
          [@previous[-1].expected, @events[0]].flatten
        else
          [@events[@current]]
        end
      end
    end


    class Choice < State
      def initialize context
        super
        @choices = []
      end

      def reset
        super
        @events = []
        @choices.each { |c| c.each { |s| s.reset if s.kind_of? State } }
      end

      def <<( event )
        add_event_to_arry( @choices, event )
      end

      def next( event )
        # Make the choice if we haven't
        if @events.size == 0
          c = 0 ; max = @choices.size
          while c < max
            if @choices[c][0].class == Ref
              expand_ref_in( @choices[c], 0 )
              @choices += @choices[c]
              @choices.delete( @choices[c] )
              max -= 1
            else
              c += 1
            end
          end
          @events = @choices.find { |evt| evt[0].matches? event }
          # Remove the references
          # Find the events
        end
        unless @events
          @events = []
          return nil
        end
        super
      end

      def matches?( event )
        return @events[@current].matches?( event ) if @events.size > 0
        !@choices.find{|evt| evt[0].matches?(event)}.nil?
      end

      def expected
        return [@events[@current]] if @events.size > 0
        @choices.collect do |x|
          if x[0].kind_of? State
            x[0].expected
          else
            x[0]
          end
        end.flatten
      end

      def inspect
        "< #{to_s} #{@choices.collect{|e| e.collect{|f|f.to_s}.join(', ')}.join(' or ')} >"
      end

      protected
      def add_event_to_arry( arry, evt )
        if evt.kind_of? State or evt.class == Ref
          arry << [evt]
        elsif evt[0] == :text
         if arry[-1] and
            arry[-1][-1].kind_of?( Event ) and
            arry[-1][-1].event_type == :text and @value

            arry[-1][-1].event_arg = evt[1]
            @value = false
         end
        else
          arry << [] if evt[0] == :start_element
          arry[-1] << generate_event( evt )
        end
      end
    end


    class Interleave < Choice
      def initialize context
        super
        @choice = 0
      end

      def reset
        @choice = 0
      end

      def next_current( event )
        # Expand references
        c = 0 ; max = @choices.size
        while c < max
          if @choices[c][0].class == Ref
            expand_ref_in( @choices[c], 0 )
            @choices += @choices[c]
            @choices.delete( @choices[c] )
            max -= 1
          else
            c += 1
          end
        end
        @events = @choices[@choice..-1].find { |evt| evt[0].matches? event }
        @current = 0
        if @events
          # reorder the choices
          old = @choices[@choice]
          idx = @choices.index( @events )
          @choices[@choice] = @events
          @choices[idx] = old
          @choice += 1
        end

        @events = [] unless @events
      end


      def next( event )
        # Find the next series
        next_current(event) unless @events[@current]
        return nil unless @events[@current]

        expand_ref_in( @events, @current ) if @events[@current].class == Ref
        if ( @events[@current].kind_of? State )
          @current += 1
          @events[@current-1].previous = self
          return @events[@current-1].next( event )
        end
        return @previous.pop.next( event ) if @events[@current].nil?
        if ( @events[@current].matches?(event) )
          @current += 1
          if @events[@current].nil?
            return self unless @choices[@choice].nil?
            @previous.pop
          elsif @events[@current].kind_of? State
            @current += 1
            @events[@current-1].previous = self
            @events[@current-1]
          else
            self
          end
        else
          nil
        end
      end

      def matches?( event )
        return @events[@current].matches?( event ) if @events[@current]
        !@choices[@choice..-1].find{|evt| evt[0].matches?(event)}.nil?
      end

      def expected
        return [@events[@current]] if @events[@current]
        @choices[@choice..-1].collect do |x|
          if x[0].kind_of? State
            x[0].expected
          else
            x[0]
          end
        end.flatten
      end

      def inspect
        "< #{to_s} #{@choices.collect{|e| e.collect{|f|f.to_s}.join(', ')}.join(' and ')} >"
      end
    end

    class Ref
      def initialize value
        @value = value
      end
      def to_s
        @value
      end
      def inspect
        "{#{to_s}}"
      end
    end
  end
end
