# frozen-string-literal: true

module Sequel
  module Plugins
    # The association_dependencies plugin allows you do easily set up before and/or after destroy hooks
    # for destroying, deleting, or nullifying associated model objects.  The following
    # association types support the following dependency actions:
    # 
    # :many_to_many :: :nullify (removes all related entries in join table)
    # :many_to_one :: :delete, :destroy
    # :one_to_many, one_to_one :: :delete, :destroy, :nullify (sets foreign key to NULL for all associated objects)
    #
    # This plugin works directly with the association datasets and does not use any cached association values.
    # The :delete action will delete all associated objects from the database in a single SQL call.
    # The :destroy action will load each associated object from the database and call the destroy method on it.
    #
    # To set up an association dependency, you must provide a hash with association name symbols
    # and dependency action values.  You can provide the hash to the plugin call itself or
    # to the add_association_dependencies method:
    #
    #   Business.plugin :association_dependencies, address: :delete
    #   # or:
    #   Artist.plugin :association_dependencies
    #   Artist.add_association_dependencies albums: :destroy, reviews: :delete, tags: :nullify
    #
    # If the model uses the instance_filters plugin, dependent writes check
    # that the object still matches its instance filters before modifying
    # associated objects.  If the object does not match, no associated objects
    # are modified and a Sequel::NoExistingObject exception is raised.  The
    # check is a query against the object's row, and is performed each time a
    # destroy is attempted, so a failed destroy does not authorize a later
    # retry.  Destroying an object with instance filters always uses a
    # transaction, so dependent modifications are rolled back if the
    # object's delete fails.
    #
    # Filters registered with the instance_filters plugin using
    # #instance_dependency_filter are also applied to the datasets used
    # for dependent :delete and :destroy actions.  This allows a
    # tenant/permission filter to be enforced on both the object and its
    # associated objects:
    #
    #   artist.instance_dependency_filter(tenant_id: 1)
    #   artist.destroy # only deletes albums matching tenant_id = 1
    module AssociationDependencies
      # Mapping of association types to when the dependency calls should be made (either
      # :before for in before_destroy or :after for in after_destroy)
      ASSOCIATION_MAPPING = {:one_to_many=>:before, :many_to_one=>:after, :many_to_many=>:before, :one_to_one=>:before}.freeze

      # The valid dependence actions
      DEPENDENCE_ACTIONS = [:delete, :destroy, :nullify].freeze

      # Initialize the association_dependencies hash for this model.
      def self.apply(model, hash=OPTS)
        model.instance_exec{@association_dependencies = {:before_delete=>[], :before_destroy=>[], :before_nullify=>[], :after_delete=>[], :after_destroy=>[]}}
      end

      # Call add_association_dependencies with any dependencies given in the plugin call.
      def self.configure(model, hash=OPTS)
        model.add_association_dependencies(hash) unless hash.empty?
      end

      module ClassMethods
        # A hash specifying the association dependencies for each model.  The keys
        # are symbols indicating the type of action and when it should be executed
        # (e.g. :before_delete).  Values are an array of method symbols.
        # For before_nullify, the symbols are remove_all_association methods.  For other
        # types, the symbols are association_dataset methods, on which delete or
        # destroy is called.
        attr_reader :association_dependencies

        # Add association dependencies to this model.  The hash should have association name
        # symbol keys and dependency action symbol values (e.g. albums: :destroy).
        def add_association_dependencies(hash)
          hash.each do |association, action|
            raise(Error, "Nonexistent association: #{association}") unless r = association_reflection(association)
            type = r[:type]
            raise(Error, "Invalid dependence action type: association: #{association}, dependence action: #{action}") unless DEPENDENCE_ACTIONS.include?(action)
            raise(Error, "Invalid association type: association: #{association}, type: #{type}") unless time = ASSOCIATION_MAPPING[type]
            association_dependencies[:"#{time}_#{action}"] << if action == :nullify
              case type
              when :one_to_many , :many_to_many
                [r[:remove_all_method]]
              when :one_to_one
                [r[:setter_method], nil]
              else
                raise(Error, "Can't nullify many_to_one associated objects: association: #{association}")
              end
            else
              raise(Error, "Can only nullify many_to_many associations: association: #{association}") if type == :many_to_many
              r[:dataset_method]
            end
          end
        end

        # Freeze association dependencies when freezing model class.
        def freeze
          @association_dependencies.freeze.each_value(&:freeze)

          super
        end

        Plugins.inherited_instance_variables(self, :@association_dependencies=>:hash_dup)
      end

      module InstanceMethods
        # Run the delete and destroy association dependency actions for
        # many_to_one associations.
        def after_destroy
          super
          model.association_dependencies[:after_delete].each{|m| association_dependency_dataset(m).delete}
          model.association_dependencies[:after_destroy].each{|m| association_dependency_dataset(m).destroy}
        end

        # Run the delete, destroy, and nullify association dependency actions for
        # *_to_many associations.
        #
        # If the model uses instance filters, this checks that the object
        # still matches the filters before modifying any associated objects.
        # If it does not match, a Sequel::NoExistingObject exception is
        # raised and no associated objects are modified.  The filters are
        # not cleared, so a later retry must pass the same check.
        def before_destroy
          check_association_dependency_authorization
          model.association_dependencies[:before_delete].each{|m| association_dependency_dataset(m).delete}
          model.association_dependencies[:before_destroy].each{|m| association_dependency_dataset(m).destroy}
          model.association_dependencies[:before_nullify].each{|args| nullify_association_dependency(*args)}
          super
        end

        # Whether the object currently matches all of its instance filters.
        # This is the check used to determine if dependent operations are
        # authorized.  Returns true if the model does not use instance
        # filters.
        def association_dependency_authorized?
          !respond_to?(:instance_filter_matches?, true) || instance_filter_matches?
        end

        # Force a transaction when destroying an object with instance filters
        # and association dependencies, unless a transaction option was
        # explicitly given.  This ensures dependent modifications are rolled
        # back if destroying the object fails, even if the model has
        # transactions disabled.
        def destroy(opts=OPTS)
          if !opts.has_key?(:transaction) && association_dependency_transaction?
            opts = Hash[opts].merge!(:transaction=>true)
          end
          super(opts)
        end

        private

        # Aggregate the association dependency method arrays for the given
        # keys, so multiple checks don't need to duplicate the keys.
        def association_dependency_methods(*keys)
          dep = model.association_dependencies
          keys.each_with_object([]){|k, a| a.concat(dep[k])}
        end

        # Whether a transaction should be forced for the destroy.
        def association_dependency_transaction?
          return false unless respond_to?(:instance_filter_dependents?, true) && instance_filter_dependents?
          !association_dependency_methods(:before_delete, :before_destroy, :before_nullify, :after_delete, :after_destroy).empty?
        end

        # Check that the object matches its instance filters before running
        # dependent actions.  This is a no-op if the model does not use
        # instance filters or has no dependencies to run.
        def check_association_dependency_authorization
          return unless respond_to?(:instance_filter_check!, true)
          return if association_dependency_methods(:before_delete, :before_destroy, :before_nullify).empty?
          instance_filter_check!
        end

        # Return the association dataset for the given dataset method,
        # applying any instance filters registered for dependent writes.
        def association_dependency_dataset(dataset_method)
          ds = public_send(dataset_method)
          if respond_to?(:instance_filter_dependency_dataset, true)
            ds = instance_filter_dependency_dataset(ds)
          end
          ds
        end

        # Run a nullify dependency.  If the model uses instance filters
        # that are also applied to dependent writes, and this is a
        # one_to_many or one_to_one association, update the associated
        # dataset directly, so the dependent filters are applied.
        # Otherwise, call the association's normal remove_all or setter
        # method.
        def nullify_association_dependency(meth, *args)
          if respond_to?(:instance_filter_dependency_filters?, true) && instance_filter_dependency_filters?
            if r = association_dependency_reflection(meth)
              case r[:type]
              when :one_to_many, :one_to_one
                ds = public_send(r.dataset_method)
                ds = instance_filter_dependency_dataset(ds)
                keys = Array(r[:keys])
                ret = ds.update(keys.each_with_object({}){|k, h| h[k] = nil})
                associations[r[:name]] = [] if associations.include?(r[:name])
                return ret
              end
            end
          end
          public_send(meth, *args)
        end

        # Find the association reflection for a dependency method.
        def association_dependency_reflection(meth)
          model.all_association_reflections.find do |r|
            r.dataset_method == meth || r.remove_all_method == meth || r.setter_method == meth
          end
        end
      end

    end
  end
end
