# frozen_string_literal: false
require_relative "validation"
require_relative "../document"

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
    # The validator consumes parser events as a token stream.  Each state is a
    # set of pattern derivatives (see Brzozowski derivatives), so no mutable
    # backtracking state is shared between documents.  Interleaving is handled
    # by allowing either branch to consume the next token, which keeps every
    # legal permutation and rejects permutations that skip a required branch.
    class RelaxNG
      include Validator

      FAIL = Object.new
      def FAIL.inspect
        "FAIL"
      end

      EMPTY = [:empty].freeze

      attr_accessor :current
      attr_accessor :count
      attr_reader :references

      def initialize source
        @count = 0
        @references = {}
        document = Document.new( source )
        root = document.root
        raise ArgumentError, "RelaxNG schema has no root element" if root.nil?
        if root.name == "grammar"
          root.elements.each( "define" ) do |define|
            @references[ define.attributes["name"] ] = define
          end
          start = root.elements[ "start" ]
          raise ArgumentError, "RelaxNG grammar has no start pattern" if start.nil?
          @root_pattern = compile_children( start, :sequence )
        else
          @root_pattern = compile_pattern( root )
        end
        @resolved = {}
        reset
      end

      def reset
        @current = [ @root_pattern ]
        @document_finished = false
        @depth = 0
        self
      end

      def receive event
        validate( event )
      end

      def dump
        puts @root_pattern.inspect
      end

      def validate event
        case event[0]
        when :start_element
          start_element( event )
        when :end_element
          end_element( event )
        when :text
          advance( [ :text, event[1] ], event )
        when :cdata
          advance( [ :text, event[1] ], event )
        when :end_document
          unless @document_finished and nullable_states?( @current )
            validation_error( event, "end of document" )
          end
        when :comment, :processing_instruction, :xmldecl
          # Comments, PIs and the XML declaration are not part of the grammar.
        else
          validation_error( event, event[0] )
        end
      end

      def expected
        describe( @current )
      end

      def inspect
        "<RelaxNG #{describe( @current )}>"
      end

      private

      def start_element event
        if @document_finished
          validation_error( event, "a second root element" )
        end
        states = step_current( [ :start_element, event[1] ] )
        if states.empty?
          validation_error( event, "element #{event[1].inspect}" )
        end
        states = consume_attributes( states, event[2] || {} )
        if states.empty?
          validation_error( event, "attributes #{event[2].inspect}" )
        end
        @current = states
        @depth += 1
      end

      def end_element event
        if @depth == 0
          validation_error( event, "end of element" )
        end
        advance( [ :end_element ], event )
        @depth -= 1
        @document_finished = true if @depth == 0
      end

      def advance token, event
        states = step_current( token )
        if states.empty?
          got = token[0] == :text ? token[1] : token[0]
          validation_error( event, got )
        end
        @current = states
        @count += 1
      end

      def step_current token
        step_from( @current, [ token ] )
      end

      def step_from states, tokens
        current = states
        tokens.each do |token|
          derived = []
          current.each do |pattern|
            next if pattern.equal?( FAIL )
            expand_alternatives( derive( pattern, token, {} ), derived )
          end
          current = derived.uniq
          return current if current.empty?
        end
        current
      end

      # Attributes are unordered and all appear in the start-element event.
      # Try every order that lets the grammar consume all of them.
      def consume_attributes states, attributes
        tokens = attributes.map do |name, value|
          [ :attribute, name, value ]
        end
        return states if tokens.empty?
        results = []
        visited = {}
        consume_attributes_in( states, tokens, (0...tokens.size).to_a,
                               results, visited )
        results.uniq
      end

      def consume_attributes_in states, tokens, remaining, results, visited
        if remaining.empty?
          results.concat( states )
          return
        end
        key = [ remaining, signature( states ) ]
        return if visited[key]
        visited[key] = true
        remaining.each do |index|
          next_states = step_from( states, [ tokens[index] ] )
          next if next_states.empty?
          consume_attributes_in( next_states, tokens, remaining - [ index ],
                                 results, visited )
        end
      end

      def signature states
        states.map { |pattern| pattern.inspect }.join( " | " )
      end

      def expand_alternatives pattern, into
        return if pattern.equal?( FAIL )
        if pattern[0] == :alt
          pattern[1].each { |child| expand_alternatives( child, into ) }
        else
          into << pattern
        end
      end

      def nullable_states? patterns
        patterns.any? { |pattern| nullable?( pattern ) }
      end

      def nullable? pattern, seen = {}
        case pattern[0]
        when :empty
          true
        when :elem, :attr, :text_any, :text_exact, :end_tag
          false
        when :alt
          pattern[1].any? { |child| nullable?( child, seen ) }
        when :seq
          nullable?( pattern[1], seen ) and nullable?( pattern[2], seen )
        when :ilv
          nullable?( pattern[1], seen ) and nullable?( pattern[2], seen )
        when :star
          true
        when :ref
          key = [ pattern[1], pattern[2] ]
          return false if seen[key]
          nullable?( resolve( pattern[1], pattern[2] ), seen.merge( key => true ) )
        else
          raise ArgumentError, "unknown RelaxNG pattern: #{pattern.inspect}"
        end
      end

      def derive pattern, token, seen
        case pattern[0]
        when :empty
          FAIL
        when :elem
          unless token[0] == :start_element and token[1] == pattern[1]
            return FAIL
          end
          sequence( pattern[2], [ :end_tag ] )
        when :attr
          return FAIL unless token[0] == :attribute and token[1] == pattern[1]
          return FAIL unless attribute_value_matches?( pattern[2], token[2] )
          EMPTY
        when :text_any
          token[0] == :text ? EMPTY : FAIL
        when :text_exact
          (token[0] == :text && token[1] == pattern[1]) ? EMPTY : FAIL
        when :end_tag
          token[0] == :end_element ? EMPTY : FAIL
        when :alt
          results = []
          pattern[1].each do |child|
            expand_alternatives( derive( child, token, seen ), results )
          end
          return FAIL if results.empty?
          return results[0] if results.size == 1
          [ :alt, results ]
        when :seq
          first = derive( pattern[1], token, seen )
          second = nullable?( pattern[1], seen ) ?
                     derive( pattern[2], token, seen ) : FAIL
          alternation( sequence( first, pattern[2] ), second )
        when :star
          sequence( derive( pattern[1], token, seen ), pattern )
        when :ilv
          alternation(
            interleave( derive( pattern[1], token, seen ), pattern[2] ),
            interleave( pattern[1], derive( pattern[2], token, seen ) )
          )
        when :ref
          key = [ pattern[1], pattern[2] ]
          return FAIL if seen[key]
          derive( resolve( pattern[1], pattern[2] ), token,
                  seen.merge( key => true ) )
        else
          raise ArgumentError, "unknown RelaxNG pattern: #{pattern.inspect}"
        end
      end

      def attribute_value_matches? constraint, value
        case constraint
        when nil, :any
          true
        when Array
          constraint.include?( value )
        else
          constraint == value
        end
      end

      def alternation first, second
        return second if first.equal?( FAIL )
        return first if second.equal?( FAIL )
        if first[0] == :alt and second[0] == :alt
          [ :alt, ( first[1] + second[1] ).uniq ]
        elsif first[0] == :alt
          [ :alt, ( first[1] + [ second ] ).uniq ]
        elsif second[0] == :alt
          [ :alt, ( [ first ] + second[1] ).uniq ]
        else
          [ :alt, [ first, second ].uniq ]
        end
      end

      def sequence first, second
        return FAIL if first.equal?( FAIL ) or second.equal?( FAIL )
        return second if first == EMPTY
        return first if second == EMPTY
        [ :seq, first, second ]
      end

      def interleave first, second
        return FAIL if first.equal?( FAIL ) or second.equal?( FAIL )
        return second if first == EMPTY
        return first if second == EMPTY
        [ :ilv, first, second ]
      end

      def repetition pattern
        return EMPTY if pattern.equal?( EMPTY ) or pattern.equal?( FAIL )
        [ :star, pattern ]
      end

      def resolve name, mode
        key = [ name, mode ]
        return @resolved[key] if @resolved.key?( key )
        define = @references[ name ]
        raise ArgumentError, "unknown RelaxNG reference: #{name}" if define.nil?
        @resolved[key] = compile_children( define, mode )
      end

      def compile_children node, mode
        parts = []
        node.elements.each do |child|
          if child.name == "ref"
            parts << [ :ref, child.attributes["name"], mode ]
          else
            parts << compile_pattern( child )
          end
        end
        combine( parts, mode )
      end

      def combine parts, mode
        return EMPTY if parts.empty?
        case mode
        when :choice
          parts.inject { |left, right| alternation( left, right ) }
        when :interleave
          parts.inject { |left, right| interleave( left, right ) }
        else
          parts.inject { |left, right| sequence( left, right ) }
        end
      end

      def compile_pattern node
        name = node.attributes["name"]
        case node.name
        when "element"
          [ :elem, name, compile_children( node, :sequence ) ]
        when "attribute"
          [ :attr, name, compile_attribute_value( node ) ]
        when "text"
          [ :text_any ]
        when "value"
          [ :text_exact, node.texts.map { |text| text.value }.join ]
        when "empty"
          EMPTY
        when "group"
          compile_children( node, :sequence )
        when "choice"
          compile_children( node, :choice )
        when "interleave"
          compile_children( node, :interleave )
        when "optional"
          alternation( EMPTY, compile_children( node, :sequence ) )
        when "zeroOrMore"
          repetition( compile_children( node, :sequence ) )
        when "oneOrMore"
          content = compile_children( node, :sequence )
          sequence( content, repetition( content ) )
        when "mixed"
          interleave( compile_children( node, :sequence ),
                      repetition( [ :text_any ] ) )
        when "ref"
          [ :ref, name, :sequence ]
        when "start", "define"
          compile_children( node, :sequence )
        else
          raise ArgumentError, "unsupported RelaxNG pattern: #{node.name}"
        end
      end

      def compile_attribute_value node
        children = node.elements.to_a
        return nil if children.empty?
        value_options( children )
      end

      def value_options nodes
        options = []
        nodes.each do |node|
          case node.name
          when "value"
            options << node.texts.map { |text| text.value }.join
          when "choice"
            options.concat( value_options( node.elements.to_a ) )
          else
            return :any
          end
        end
        options.empty? ? :any : options
      end

      def validation_error event, got
        raise ValidationException.new(
          "Validation error.  Expected: #{describe( @current )} " \
          "but got #{got.inspect}"
        )
      end

      def describe patterns
        patterns.map { |pattern| describe_pattern( pattern ) }.join( " or " )
      end

      def describe_pattern pattern
        case pattern[0]
        when :empty
          "end of element"
        when :elem
          "element #{pattern[1].inspect}"
        when :attr
          "attribute #{pattern[1].inspect}"
        when :text_any
          "text"
        when :text_exact
          "text #{pattern[1].inspect}"
        when :end_tag
          "end of element"
        when :seq
          "#{describe_pattern( pattern[1] )} then " \
          "#{describe_pattern( pattern[2] )}"
        when :alt
          pattern[1].map { |child| describe_pattern( child ) }.join( " or " )
        when :ilv
          "#{describe_pattern( pattern[1] )} interleaved with " \
          "#{describe_pattern( pattern[2] )}"
        when :star
          "zero or more of #{describe_pattern( pattern[1] )}"
        when :ref
          "reference #{pattern[1]}"
        else
          pattern.inspect
        end
      end
    end
  end
end
