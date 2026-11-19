# frozen-string-literal: true

module Rodauth
  Feature.define(:audit_logging, :AuditLogging) do
    auth_value_method :audit_logging_account_id_column, :account_id
    auth_value_method :audit_logging_message_column, :message
    auth_value_method :audit_logging_metadata_column, :metadata
    auth_value_method :audit_logging_status_column, :status
    auth_value_method :audit_logging_table, :account_authentication_audit_logs
    auth_value_method :audit_log_metadata_default, nil
    auth_value_method :audit_log_status_committed, 'committed'
    auth_value_method :audit_log_status_attempted, 'attempted'
    auth_value_method :audit_log_status_failed, 'failed'

    auth_methods(
      :add_audit_log,
      :audit_log_insert_hash,
      :audit_log_message,
      :audit_log_message_default,
      :audit_log_metadata,
      :audit_log_metadata_for_action,
      :serialize_audit_log_metadata,
    )

    configuration_module_eval do
      [:audit_log_message_for, :audit_log_metadata_for].each do |method|
        define_method(method) do |action, value=nil, &block|
          block ||= proc{value}
          meth = :"#{method}_#{action}"
          @auth.send(:define_method, meth, &block)
          @auth.send(:private, meth)
        end
      end
    end

    def hook_action(hook_type, action)
      super

      if action == :logout
        # Logout/clear_session runs before after_logout and does not clear
        # @account, so audit logout before the session is cleared.
        return unless hook_type == :before
        audit_log_successful_action(:logout)
      elsif hook_type == :after
        if action.to_s.end_with?('_failure') || action == :no_matching_login
          audit_log_failed_action(action)
        else
          audit_log_successful_action(action)
        end
      end
    end

    def add_audit_log(account_id, action, metadata=audit_log_metadata(action))
      if hash = audit_log_insert_hash(account_id, action, metadata)
        safe_audit_log_insert(hash)
      end
    end

    def audit_log_insert_hash(account_id, action, metadata=audit_log_metadata(action))
      if message = audit_log_message(action)
        hash = {
          audit_logging_account_id_column => account_id,
          audit_logging_message_column => message,
          audit_logging_metadata_column => serialize_audit_log_metadata(metadata)
        }
        if audit_logging_status && audit_logging_status_column?
          hash[audit_logging_status_column] = audit_logging_status
        end
        hash
      end
    end

    def audit_log_metadata_for_action(action, status, account_id)
      audit_log_metadata(action)
    end

    def serialize_audit_log_metadata(metadata)
      metadata.to_json unless metadata.nil?
    end

    def audit_log_message_default(action)
      action.to_s
    end

    def audit_log_message(action)
      meth = :"audit_log_message_for_#{action}"
      if respond_to?(meth, true)
        send(meth)
      else
        audit_log_message_default(action)
      end
    end

    def audit_log_metadata(action)
      meth = :"audit_log_metadata_for_#{action}"
      if respond_to?(meth, true)
        send(meth)
      else
        audit_log_metadata_default
      end
    end

    private

    # The status of the audit log entry currently being added, if any.
    attr_reader :audit_logging_status

    def transaction(opts=OPTS, &block)
      # Only the outermost Rodauth transaction for the request is tracked.
      # Nested transactions are part of the same unit of work. Skip internal
      # savepoint-only probes, which are not action transactions.
      return super if @audit_logging_transaction || opts[:savepoint] == :only

      # If an enclosing transaction is open (for example, in the test suite),
      # use a savepoint so the boundary of the action's transaction can be
      # observed independently.
      if db.in_transaction? && !opts.key?(:savepoint) && db.supports_savepoints?
        opts = opts.merge(:savepoint=>true)
      end

      entries = []
      @audit_logging_transaction = entries
      rolled_back = false
      begin
        super(opts) do
          # The callback only changes a local variable. Writing to the audit
          # table here could run outside the action transaction and affect
          # the success of the request.
          db.after_rollback(:savepoint=>true){rolled_back = true}
          block.call
        end
      ensure
        @audit_logging_transaction = nil
        audit_log_attempted_entries(entries) if rolled_back
      end
    end

    def audit_log_attempted_entries(entries)
      # The action transaction was rolled back. The committed audit entries
      # were rolled back with it, so record the attempts after the rollback.
      if entries.empty? && (action = @current_route)
        # The transaction may roll back before the after hook runs, such as
        # when a configured after hook raises inside the transaction. In
        # that case, still record the attempt for the current action.
        entries = [[account_id_or_session_value, action, audit_log_status_attempted]]
      end

      entries.each do |account_id, action, status|
        next unless account_id
        status = audit_log_status_attempted unless status == audit_log_status_failed
        metadata = audit_log_metadata_for_action(action, status, account_id)
        insert_audit_log(account_id, action, metadata, status)
      end
    end

    def audit_log_successful_action(action)
      audit_log_action(action, audit_log_status_committed)
    end

    def audit_log_failed_action(action)
      audit_log_action(action, audit_log_status_failed)
    end

    def audit_log_action(action, status)
      return unless account_id = account_id_or_session_value
      return unless audit_log_message(action)

      metadata = audit_log_metadata_for_action(action, status, account_id)
      insert_audit_log(account_id, action, metadata, status)
    rescue StandardError
      # Audit logging must not change the result of the requested action.
      nil
    end

    def insert_audit_log(account_id, action, metadata, status)
      if (status == audit_log_status_committed || status == audit_log_status_failed) && @audit_logging_transaction
        @audit_logging_transaction << [account_id, action, status]
      end

      @audit_logging_status = status
      add_audit_log(account_id, action, metadata)
    rescue StandardError
      # Audit logging must not change the result of the requested action.
      nil
    ensure
      @audit_logging_status = nil
    end

    def safe_audit_log_insert(hash)
      if db.in_transaction?
        # Use a savepoint so a failed audit insert does not abort the
        # transaction used by the action being audited.
        db.transaction(:savepoint=>:only){audit_log_ds.insert(hash)}
      else
        audit_log_ds.insert(hash)
      end
    rescue StandardError
      # Audit logging must not change the result of the requested action.
      nil
    end

    def audit_logging_status_column?
      return @audit_logging_status_column if defined?(@audit_logging_status_column)

      @audit_logging_status_column = begin
        column = audit_logging_status_column
        if column && !audit_log_ds.columns.include?(column)
          # Older audit logging tables may not have the status column. In
          # that case, write audit entries without a status.
          nil
        else
          column
        end
      rescue StandardError
        audit_logging_status_column
      end
    end

    def audit_log_ds
      ds = db[audit_logging_table]
      # simplecov:disable
      if db.database_type == :postgres
      # simplecov:enable
        # For PostgreSQL, use RETURNING NULL. This allows the feature
        # to be used with INSERT but not SELECT permissions on the
        # table, useful for audit logging where the database user
        # the application is running as should not need to read the
        # logs.
        ds = ds.returning(nil)
      end
      ds
    end
  end
end
