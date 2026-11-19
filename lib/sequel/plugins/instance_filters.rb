# frozen-string-literal: true

module Sequel
  module Plugins
    # This plugin allows you to add filters on a per object basis that
    # restrict updating or deleting the object.  It's designed for cases
    # where you would normally have to drop down to the dataset level
    # to get the necessary control, because you only want to delete or
    # update the rows in certain cases based on the current status of
    # the row in the database.  The main purpose of this plugin is to
    # avoid race conditions by relying on the atomic properties of database
    # transactions.
    # 
    #   class Item < Sequel::Model
    #     plugin :instance_filters
    #   end
    #
    #   # These are two separate objects that represent the same
    #   # database row. 
    #   i1 = Item.first(id: 1, delete_allowed: false)
    #   i2 = Item.first(id: 1, delete_allowed: false)
    #
    #   # Add an instance filter to the object. This filter is in effect
    #   # until the object is successfully updated or deleted.
    #   i1.instance_filter(delete_allowed: true)
    #
    #   # Attempting to delete the object where the filter doesn't
    #   # match any rows raises an error.
    #   i1.delete # raises Sequel::NoExistingObject
    #
    #   # The other object that represents the same row has no
    #   # instance filters, and can be updated normally.
    #   i2.update(delete_allowed: true)
    #
    #   # Even though the filter is now still in effect, since the
    #   # database row has been updated to allow deleting,
    #   # delete now works.
    #   i1.delete
    #
    # This plugin sets the require_modification flag on the model,
    # so if the model's dataset doesn't provide an accurate number
    # of matched rows, this could result in invalid exceptions being raised.
    #
    # The filters are also usable for dependent writes.  The
    # association_dependencies plugin checks that the object still matches
    # its instance filters before running dependent operations, and can
    # apply filters registered with #instance_dependency_filter to the
    # dependent datasets.  This allows a tenant/permission filter to be
    # enforced in the same way for the object and for objects that are
    # deleted or destroyed because of it.
    #
    # A dependent write is authorized only if the object still matches all
    # instance filters.  If it does not, the dependent writes are not run and
    # a Sequel::NoExistingObject exception is raised.  The filters are not
    # cleared when a destroy fails, so retrying the destroy requires the
    # filters to match again.
    module InstanceFilters
      # Exception class raised when updating or deleting an object does
      # not affect exactly one row.
      Error = Sequel::NoExistingObject
      
      # Set the require_modification flag to true for the model.
      def self.configure(model)
        model.require_modification = true
      end

      module ClassMethods
        Plugins.model_instance_variables(self, :@instance_filters)
      end

      module InstanceMethods
        # Clear the instance filters after successfully destroying the object.
        def after_destroy
          super
          clear_instance_filters
        end
        
        # Clear the instance filters after successfully updating the object.
        def after_update
          super
          clear_instance_filters
        end

        # Freeze the instance filters when freezing the object
        def freeze
          instance_filters.freeze
          super
        end
      
        # Add an instance filter to the array of instance filters
        # Both the arguments given and the block are passed to the
        # dataset's filter method.
        #
        # Filters added with this method are only applied to writes on the
        # object itself.  See #instance_dependency_filter for filters that
        # are also applied to dependent writes.
        def instance_filter(*args, &block)
          instance_filters << [args, block, false]
        end

        # Add an instance filter that is also applied to the datasets used
        # for dependent writes performed by the association_dependencies
        # plugin (deleting or destroying associated objects).  Arguments and
        # block are handled the same as #instance_filter.
        #
        # This is useful for permission filters shared by an object and its
        # associated objects, such as a tenant filter:
        #
        #   obj.instance_dependency_filter(tenant_id: 1)
        #   obj.destroy # only deletes associated objects matching tenant_id = 1
        #
        # Filters applied to dependent datasets must use columns that exist
        # in the associated table.  The filter is applied on top of the
        # association dataset, so the dependent write is still restricted to
        # the objects associated with this object.
        #
        # Regardless of whether a filter is added with this method,
        # dependent writes check that the object itself matches all instance
        # filters before modifying associated objects.  See
        # #instance_filter_check!.
        def instance_dependency_filter(*args, &block)
          instance_filters << [args, block, true]
        end

        # Whether the object has any instance filters.  Dependent writes use
        # this to determine whether the object's authorization needs to be
        # checked before modifying associated objects.
        def instance_filter_dependents?
          !instance_filters.empty?
        end

        # Whether any instance filters should be applied to dependent
        # datasets.
        def instance_filter_dependency_filters?
          instance_filters.any?{|i| i[2]}
        end

        # Whether the object's row currently matches all instance filters.
        # This is the query dependent writes should use to determine if the
        # object is currently authorized.  Returns true if there are no
        # instance filters.  Note that this queries the database, it does not
        # use the cached values in the object.
        #
        # The dataset given should be a dataset restricted to the object, and
        # defaults to the object's dataset.
        def instance_filter_matches?(dataset=this)
          instance_filters.empty? || !apply_instance_filters(dataset).get(1).nil?
        end

        # Check that the object's row currently matches all instance filters,
        # raising a Sequel::NoExistingObject exception if it does not.
        # Dependent writes call this before modifying associated objects, so
        # associated objects are not modified if the object is not currently
        # authorized.  Returns true if the object matches all instance
        # filters.
        #
        # The instance filters are not cleared when this raises, so a later
        # retry checks the permissions again.
        def instance_filter_check!
          return true if instance_filter_matches?
          raise Error, "Attempt to modify dependent objects for an object that does not match the instance filters"
        end

        # Return the given dataset with all instance filters applied.  This
        # allows dependent writes to use the same restrictions as writes to
        # the object, when the dataset uses the same columns as the object.
        def instance_filter_dataset(dataset)
          apply_instance_filters(dataset)
        end

        # Return the given dataset with instance filters applicable to
        # dependent writes applied.  This is the dataset the
        # association_dependencies plugin uses for dependent deletes and
        # destroys.
        def instance_filter_dependency_dataset(dataset)
          apply_instance_dependency_filters(dataset)
        end
      
        # Clear instance filters when saving changes even if the
        # object wasn't modified.
        def save_changes(opts=OPTS)
          ret = super
          clear_instance_filters if ret.nil?
          ret
        end

        private
        
        # If there are any instance filters, make sure not to use the
        # instance delete optimization.
        def _delete_without_checking
          if @instance_filters && !@instance_filters.empty?
            _delete_dataset.delete 
          else
            super
          end
        end

        # Duplicate internal structures when duplicating model instance.
        def initialize_copy(other)
          super
          @instance_filters = other.send(:instance_filters).dup
          self
        end

        # Lazily initialize the instance filter array.
        def instance_filters
          @instance_filters ||= []
        end

        # Apply the instance filters to the given dataset
        def apply_instance_filters(ds)
          instance_filters.inject(ds) do |ds1, i|
            block = i[1]
            ds1.where(*i[0], &block)
          end
        end

        # Apply the instance filters usable for dependent datasets to the
        # given dataset.
        def apply_instance_dependency_filters(ds)
          instance_filters.inject(ds) do |ds1, i|
            next ds1 unless i[2]
            block = i[1]
            ds1.where(*i[0], &block)
          end
        end
        
        # Clear the instance filters.
        def clear_instance_filters
          instance_filters.clear
        end
        
        # Apply the instance filters to the dataset returned by super.
        def _delete_dataset
          apply_instance_filters(super)
        end
        
        # Apply the instance filters to the dataset returned by super.
        def _update_dataset
          apply_instance_filters(super)
        end

        # Only use prepared statements for update and delete queries
        # if there are no instance filters.
        def use_prepared_statements_for?(type)
          if type == :update && !instance_filters.empty?
            false
          else
            super if defined?(super)
          end
        end
      end
    end
  end
end
