# frozen-string-literal: true

#
class Roda
  module RodaPlugins
    # The dispatch_capabilities plugin allows a route to grant a set of
    # read-only capabilities when dispatching to a downstream rack app,
    # scoped to that single downstream call:
    #
    #   plugin :dispatch_capabilities
    #
    #   route do |r|
    #     r.on "reports" do
    #       r.run_with_capabilities ReportsApp, [:read_reports]
    #     end
    #   end
    #
    # The downstream app can inspect the capabilities it was granted:
    #
    #   route do |r|
    #     if r.capabilities.allows?(:read_reports)
    #       # ...
    #     end
    #   end
    #
    # If no capabilities were granted for the current dispatch, the
    # capabilities are empty, so downstream apps see no authorization by
    # default.
    #
    # The granted capabilities are stored in the rack environment only
    # while the downstream app is being called.  After the downstream app
    # returns (or raises), the previous value is restored, so the
    # capabilities do not leak if the same rack environment is reused for
    # later fallback handling.
    #
    # You can also use a block form to scope capabilities around any code:
    #
    #   r.with_capabilities([:read_reports]) do
    #     r.run ReportsApp
    #   end
    #
    # Note that granting capabilities replaces any capabilities granted by
    # an enclosing scope for the duration of the block, it does not merge
    # with them.  The previous capabilities are restored when the block
    # exits.
    module DispatchCapabilities
      # The rack environment key used to store the granted capabilities.
      ENV_KEY = "roda.capabilities".freeze

      # A read-only set of capabilities granted to a downstream dispatch.
      class Capabilities
        # The granted capabilities, as an array of symbols.
        attr_reader :to_a

        # Freeze the given capabilities into a read-only set.
        def initialize(capabilities)
          @to_a = capabilities.map{|capability| capability.to_sym}.uniq.freeze
          freeze
        end

        # Whether the given capability has been granted.
        def allows?(capability)
          @to_a.include?(capability.to_sym)
        end

        # Whether no capabilities have been granted.
        def empty?
          @to_a.empty?
        end

        # The capabilities used when no capabilities have been granted.
        EMPTY = new([])
      end

      # The capabilities granted for the given rack environment, or the
      # empty capabilities if no capabilities have been granted.
      def self.capabilities(env)
        env[ENV_KEY] || Capabilities::EMPTY
      end

      module RequestMethods
        # The read-only capabilities granted to the current dispatch.
        # Returns the empty capabilities if no capabilities were granted.
        def capabilities
          DispatchCapabilities.capabilities(@env)
        end

        # Grant the given read-only capabilities for the duration of the
        # block.  Restores any previously granted capabilities when the
        # block exits, even if an exception is raised, so the granted
        # capabilities do not leak into later handling of the same
        # request.
        def with_capabilities(capabilities)
          env = @env
          previous = env[ENV_KEY]
          begin
            env[ENV_KEY] = Capabilities.new(capabilities)
            yield
          ensure
            if previous
              env[ENV_KEY] = previous
            else
              env.delete(ENV_KEY)
            end
          end
        end

        # Dispatch to the given rack app, granting the given read-only
        # capabilities for the duration of the dispatch.
        def run_with_capabilities(app, capabilities)
          with_capabilities(capabilities) do
            run(app)
          end
        end
      end
    end

    register_plugin(:dispatch_capabilities, DispatchCapabilities)
  end
end
