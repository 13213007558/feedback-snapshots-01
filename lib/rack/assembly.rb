# frozen_string_literal: true

require 'set'

module Rack
  # Rack::Assembly is an opt-in static safety check for applications built with
  # Rack::Builder. It verifies, before the application is returned, that every
  # request-phase precondition declared by middleware or an endpoint is actually
  # satisfied by an earlier middleware on the same mounted branch.
  #
  # Middleware and applications participate by declaring the *facts* they provide
  # and require. A fact is a simple Symbol describing something that becomes true
  # while a request is being processed, for example +:identity_verified+ or
  # +:body_signature_verified+.
  #
  # Facts are split by the phase in which they become available:
  #
  # * +request+ facts are produced before the downstream app is called, while the
  #   request is travelling down the middleware stack.
  # * +response+ facts are only produced after the downstream app returns, while
  #   the response is travelling back up the stack.
  #
  # A response-phase fact can never satisfy a request-phase precondition: by the
  # time it exists, the request that needed it has already passed.
  #
  # Participation is entirely optional and explicit. A component that does not
  # declare anything stays *unknown* and is never assumed to provide or require a
  # fact. In particular, the name of a class (for example one containing "Auth")
  # is never used as evidence of anything.
  #
  # A component declares itself by implementing +assembly_declaration+ and
  # returning a Rack::Assembly::Declaration, or by using the
  # Rack::Assembly::Declarative helpers:
  #
  #   class Authentication
  #     extend Rack::Assembly::Declarative
  #
  #     provides_request_fact :identity_verified
  #
  #     def initialize(app)
  #       @app = app
  #     end
  #
  #     def call(env)
  #       @app.call(env)
  #     end
  #   end
  module Assembly
    # Raised when an assembled branch fails a safety check. +mount_path+ is the
    # full map path of the offending branch, suitable for pointing users at the
    # exact location of the problem.
    class VerificationError < RuntimeError
      attr_accessor :mount_path, :fact, :component

      def initialize(message = nil, mount_path: nil, fact: nil, component: nil)
        @mount_path = mount_path
        @fact = fact
        @component = component
        super(message)
      end
    end

    # A value object describing the facts a single component provides or
    # requires. Every list defaults to empty so partial declarations are valid.
    class Declaration
      attr_reader :request_provides, :response_provides, :request_requires

      def initialize(request_provides: [], response_provides: [], request_requires: [])
        @request_provides = request_provides.map(&:to_sym)
        @response_provides = response_provides.map(&:to_sym)
        @request_requires = request_requires.map(&:to_sym)
        freeze
      end

      def ==(other)
        other.is_a?(Declaration) &&
          request_provides == other.request_provides &&
          response_provides == other.response_provides &&
          request_requires == other.request_requires
      end
    end

    # Extend a middleware or application class with this module to declare facts
    # declaratively. The class gains a +assembly_declaration+ class method; when
    # the component is instantiated the instance method delegates to it.
    module Declarative
      def provides_request_fact(*facts)
        assembly_declaration_builder.add_request_provides(facts)
      end

      def provides_response_fact(*facts)
        assembly_declaration_builder.add_response_provides(facts)
      end

      def requires_request_fact(*facts)
        assembly_declaration_builder.add_request_requires(facts)
      end

      def assembly_declaration
        assembly_declaration_builder.build
      end

      def assembly_declaration_builder
        @assembly_declaration_builder ||= DeclarationBuilder.new
      end

      def inherited(subclass)
        super
        subclass.instance_variable_set(:@assembly_declaration_builder,
          assembly_declaration_builder.dup)
      end

      # Accumulates declared facts until +build+ freezes them into a Declaration.
      class DeclarationBuilder
        def initialize
          @request_provides = []
          @response_provides = []
          @request_requires = []
        end

        def add_request_provides(facts)
          @request_provides.concat(facts)
        end

        def add_response_provides(facts)
          @response_provides.concat(facts)
        end

        def add_request_requires(facts)
          @request_requires.concat(facts)
        end

        def build
          Declaration.new(
            request_provides: @request_provides,
            response_provides: @response_provides,
            request_requires: @request_requires
          )
        end
      end
    end

    # Read the Declaration of a component without assuming one exists. A class
    # is introspected via its class method, an instance via an instance method
    # when present or otherwise via its class. Returns nil for any component
    # that does not declare anything, leaving it explicitly unknown.
    def self.declaration_of(component)
      if component.respond_to?(:assembly_declaration)
        component.assembly_declaration
      elsif !component.is_a?(Class) &&
            component.class.respond_to?(:assembly_declaration, true)
        component.class.assembly_declaration
      end
    end

    # Join map segments into a single mount path. Empty segments and the root
    # segment collapse so nested maps read naturally, e.g. "/admin" + "/users"
    # becomes "/admin/users".
    def self.join_mount_path(*segments)
      joined = segments.map { |segment| segment.to_s.sub(%r{/\z}, '') }.join
      joined.empty? ? '/' : joined
    end

    # Walk one linear middleware chain (outermost first) followed by its
    # terminal endpoint, checking request-phase preconditions against the facts
    # accumulated so far. +inherited_facts+ are request facts already established
    # by middleware enclosing the current map.
    class Verifier
      def initialize(mount_path)
        @mount_path = mount_path
        @available = Set.new
        @response_only = Set.new
      end

      def verify(chain, endpoint, inherited_facts, endpoint_requires)
        @available.merge(inherited_facts)

        chain.each do |middleware|
          declaration = Assembly.declaration_of(middleware)
          next unless declaration

          check_requires!(declaration.request_requires, middleware)
          @available.merge(declaration.request_provides)

          # Response facts are remembered separately so they can never be used
          # to satisfy a request-phase precondition below.
          @response_only.merge(declaration.response_provides)
        end

        endpoint_declaration = Assembly.declaration_of(endpoint)
        if endpoint_declaration
          check_requires!(endpoint_declaration.request_requires, endpoint)
        end

        check_requires!(endpoint_requires, endpoint)
      end

      private

      def check_requires!(required, component)
        required.each do |fact|
          next if @available.include?(fact)

          phase = @response_only.include?(fact) ? 'response' : 'missing'
          raise VerificationError.new(
            build_message(fact, component, phase),
            mount_path: @mount_path,
            fact: fact,
            component: component
          )
        end
      end

      def build_message(fact, component, phase)
        location = @mount_path == '/' ? 'the root application' : "mount path #{@mount_path}"
        name = component_name(component)
        if phase == 'response'
          "Rack assembly check failed at #{location}: #{name} requires request " \
            "fact :#{fact}, but it is only provided during the response phase, " \
            "after the request has already passed"
        else
          "Rack assembly check failed at #{location}: #{name} requires request " \
            "fact :#{fact}, which no earlier middleware on this branch provides"
        end
      end

      def component_name(component)
        case component
        when Class then component.name || component.inspect
        when nil then 'the endpoint'
        else component.class.name || component.class.inspect
        end
      end
    end
  end
end
