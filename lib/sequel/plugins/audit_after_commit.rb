# frozen-string-literal: true

module Sequel
  module Plugins
    # The audit_after_commit plugin publishes a summary of an object's
    # approved field changes to a configurable sink (such as an audit
    # system), but only after the database transaction committing the
    # changes has finished successfully.  Summaries for changes that are
    # rolled back are never published, so the sink only ever sees
    # durable, publicly visible changes.
    #
    # The plugin is built on Database#after_commit and
    # Database#after_rollback with the :savepoint option, so it behaves
    # correctly with nested transactions:
    #
    # * If an inner transaction (savepoint) is rolled back, summaries
    #   for changes made inside it are discarded, even if the outer
    #   transaction commits.
    # * If the outer transaction is rolled back, all pending summaries
    #   are discarded.
    # * If the same object is changed more than once before the outer
    #   transaction commits, only the summary for the final surviving
    #   change is published.
    #
    # The sink can be any object that responds to +call+ with a single
    # argument.  It receives a summary hash for each committed change:
    #
    #   {
    #     :model => 'FinancialModel', # model class name
    #     :pk => 42,                  # primary key of the changed record
    #     :changes => {:amount => [100, 150]} # column => [before, after]
    #   }
    #
    # The plugin uses the dirty plugin's previous_changes to build the
    # summary, and loads the dirty plugin automatically.
    #
    # Usage:
    #
    #   # Publish all field changes for the model to an audit sink:
    #   FinancialModel.plugin :audit_after_commit, sink: AuditSink
    #
    #   # Only publish changes to specific columns:
    #   FinancialModel.plugin :audit_after_commit, sink: AuditSink,
    #     columns: %i[amount status]
    module AuditAfterCommit
      # Automatically load the dirty plugin, since the change summaries
      # are built from previous_changes.
      def self.apply(model, opts=OPTS)
        model.plugin :dirty
      end

      # Require and store the :sink option, and store the optional
      # :columns option.
      def self.configure(model, opts=OPTS)
        sink = opts[:sink]
        unless sink.respond_to?(:call)
          raise Error, "must provide :sink option responding to call when using the audit_after_commit plugin"
        end
        model.audit_sink = sink
        model.audit_columns = opts[:columns].freeze if opts[:columns]
      end

      module ClassMethods
        # The object called with the change summary after the committing
        # transaction finishes.  Must respond to +call+.
        attr_accessor :audit_sink

        # The columns audited by the plugin, or nil to audit all columns.
        attr_accessor :audit_columns

        Plugins.inherited_instance_variables(self, :@audit_sink=>nil, :@audit_columns=>nil)
        Plugins.model_instance_variables(self, :@audit_pending_changes)
      end

      module InstanceMethods
        # After each update, record a change summary and register
        # transaction hooks so that the summary is published to the sink
        # only if the enclosing transaction commits.  The :savepoint
        # option is required so that summaries for changes inside a
        # rolled back savepoint are discarded instead of being published
        # when the outer transaction commits.
        def after_update
          super
          changes = audit_changes
          return if changes.empty?

          entry = {
            :model=>model.name,
            :pk=>pk,
            :changes=>changes
          }
          pending = (@audit_pending_changes ||= [])
          pending << entry

          db.after_rollback(:savepoint=>true) do
            pending.delete(entry)
          end
          db.after_commit(:savepoint=>true) do
            # Only publish if this is the final surviving change for the
            # object; earlier changes in the same transaction are
            # superseded by later ones.
            model.audit_sink.call(entry) if pending.last.equal?(entry)
            pending.delete(entry)
          end
        end

        private

        # The changes to publish, restricted to the audited columns if
        # the :columns option was used.
        def audit_changes
          changes = previous_changes || OPTS
          if (columns = model.audit_columns)
            changes = changes.select{|column, _| columns.include?(column)}
          end
          changes
        end
      end
    end
  end
end
