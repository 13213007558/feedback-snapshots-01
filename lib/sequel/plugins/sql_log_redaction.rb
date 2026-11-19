# frozen-string-literal: true

module Sequel
  module Plugins
    # The sql_log_redaction plugin declares which columns and SQL comment
    # fields for a model must not be shown in SQL log messages.  The
    # declarations are stored in the model's database, so they apply to
    # all queries against the model's table, including queries issued
    # through datasets and prepared statements.
    #
    #   class Account < Sequel::Model
    #     plugin :sql_log_redaction, :columns=>[:password, :ssn], :comment_fields=>[:email]
    #   end
    #
    # The plugin loads the sql_log_redaction Database extension if it has
    # not already been loaded.
    #
    # The :columns option supports :only and :except entries.  If :only is
    # given, only the listed columns are sensitive.  If :except is given,
    # all model columns other than the listed columns are sensitive.  If
    # neither is given, the array contains the full list of sensitive
    # columns:
    #
    #   class Account < Sequel::Model
    #     plugin :sql_log_redaction, :columns=>{:except=>[:id, :name]}
    #   end
    #
    # This plugin only controls the values written to the log.  It does
    # not change the SQL or arguments sent to the database.
    #
    # Usage:
    #
    #   # Make all model subclasses support SQL log redaction
    #   Sequel::Model.plugin :sql_log_redaction
    #
    #   # Make the Account class support SQL log redaction
    #   Account.plugin :sql_log_redaction, :columns=>[:password]
    module SqlLogRedaction
      # Load the database extension into the model's database.
      def self.apply(model, opts=OPTS)
        model.db.extension(:sql_log_redaction) unless model.db.respond_to?(:sql_log_redaction_mode)
      end

      # Set the model's redaction declarations.
      def self.configure(model, opts=OPTS)
        return unless model.instance_variable_get(:@dataset)
        model.send(:set_sql_log_redaction, opts)
      end

      module ClassMethods
        Plugins.after_set_dataset(self, :register_sql_log_redaction)
        Plugins.inherited_instance_variables(self, :@sql_log_redaction=>lambda{|v| {:columns=>v[:columns].dup, :comment_fields=>v[:comment_fields].dup}})

        # The model's current SQL log redaction declarations.
        def sql_log_redaction
          @sql_log_redaction ||= {:columns=>[], :comment_fields=>[]}
        end

        # The sensitive columns for the model.
        def sql_log_redaction_columns
          sql_log_redaction[:columns]
        end

        # The sensitive comment fields for the model.
        def sql_log_redaction_comment_fields
          sql_log_redaction[:comment_fields]
        end

        # Change the model's redaction declarations, merging them with
        # the existing declarations.
        def set_sql_log_redaction(opts=OPTS)
          columns = private_sql_log_redaction_columns(opts[:columns])
          comment_fields = Array(opts[:comment_fields]).map(&:to_sym)
          sql_log_redaction[:columns] |= columns
          sql_log_redaction[:comment_fields] |= comment_fields
          register_sql_log_redaction if @dataset
          sql_log_redaction
        end

        # Register the current declarations in the database, after
        # set_dataset has been called.
        def register_sql_log_redaction
          return if sql_log_redaction[:columns].empty? && sql_log_redaction[:comment_fields].empty?
          db.register_sql_log_redaction(
            table_name,
            :columns=>sql_log_redaction[:columns],
            :comment_fields=>sql_log_redaction[:comment_fields],
            :model=>self
          )
        end

        private

        # Convert the given column spec to an array of column symbols.
        def private_sql_log_redaction_columns(spec)
          return [] unless spec
          case spec
          when Hash
            if only = spec[:only]
              Array(only)
            elsif except = spec[:except]
              columns - Array(except)
            else
              []
            end
          else
            Array(spec)
          end
        end
      end
    end
  end
end
