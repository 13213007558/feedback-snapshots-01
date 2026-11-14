# frozen_string_literal: true
require_relative '../class_loader'
require_relative '../scalar_scanner'

module Psych
  module Nodes
    ###
    # The base class for any Node in a YAML parse tree.  This class should
    # never be instantiated.
    class Node
      include Enumerable

      # The children of this node
      attr_reader :children

      # An associated tag
      attr_reader :tag

      # The line number where this node start
      attr_accessor :start_line

      # The column number where this node start
      attr_accessor :start_column

      # The line number where this node ends
      attr_accessor :end_line

      # The column number where this node ends
      attr_accessor :end_column

      # Create a new Psych::Nodes::Node
      def initialize
        @children = []
      end

      ###
      # Iterate over each node in the tree. Yields each node to +block+ depth
      # first.
      def each &block
        return enum_for :each unless block_given?
        Visitors::DepthFirst.new(block).accept self
      end

      ###
      # Convert this node to Ruby.
      #
      # See also Psych::Visitors::ToRuby
      def to_ruby(symbolize_names: false, freeze: false, strict_integer: false, parse_symbols: true)
        Visitors::ToRuby.create(symbolize_names: symbolize_names, freeze: freeze, strict_integer: strict_integer, parse_symbols: parse_symbols).accept(self)
      end
      alias :transform :to_ruby

      ###
      # Validate the tree and only then convert it to Ruby.  Raises
      # Psych::InvalidAST without invoking any object construction hooks when
      # the tree is malformed.  Accepts the same keyword arguments as
      # #to_ruby.
      def validated_to_ruby(**options)
        validate!
        to_ruby(**options)
      end

      ###
      # Convert this node to YAML.
      #
      # See also Psych::Visitors::Emitter
      def yaml io = nil, options = {}
        require "stringio" unless defined?(StringIO)

        real_io = io || StringIO.new(''.encode('utf-8'))

        Visitors::Emitter.new(real_io, options).accept self
        return real_io.string unless io
        io
      end
      alias :to_yaml :yaml

      ###
      # Validate the tree and only then emit it as YAML.  Raises
      # Psych::InvalidAST without writing anything when the tree is malformed.
      # Accepts the same arguments as #yaml.
      def validated_yaml(io = nil, options = {})
        validate!
        yaml(io, options)
      end

      ###
      # Validate the structural invariants of this node and every node reachable
      # through it.  Returns the node when the tree is well formed and raises
      # Psych::InvalidAST otherwise.
      #
      # Parser-produced trees always pass; this is intended for hand-built or
      # plugin-modified trees before they reach object construction or output.
      # See Psych::Nodes::ASTValidator.
      def validate!
        Nodes::ASTValidator.validate!(self)
      end

      ###
      # Returns +true+ when the tree rooted at this node passes structural
      # validation, +false+ otherwise.  Never raises for a malformed tree.
      def valid_ast?
        Nodes::ASTValidator.valid?(self)
      end

      def alias?;    false; end
      def document?; false; end
      def mapping?;  false; end
      def scalar?;   false; end
      def sequence?; false; end
      def stream?;   false; end
    end
  end
end
