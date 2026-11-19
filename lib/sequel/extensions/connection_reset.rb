# frozen-string-literal: true
#
# The connection_reset extension modifies a database's connection pool
# to run a configurable reset on each connection when it is checked back
# into the pool, before the connection is made available for future
# checkouts.  This is useful for cleaning up per-session state that must
# not leak between checkouts, such as resetting the session role on
# PostgreSQL after a service temporarily changed it with +SET ROLE+:
#
#   DB.extension(:connection_reset)
#   DB.pool.connection_reset = 'RESET ROLE'
#
# The reset can be set to a string, which is treated as SQL to execute
# on the connection, or to a callable object, which is called with the
# connection:
#
#   DB.pool.connection_reset = proc{|conn| conn.execute('RESET ROLE')}
#
# If the reset fails, the connection is not returned to the pool, it is
# disconnected instead, so the next checkout will never receive a
# connection whose session state could not be restored.  The exception
# raised in this case depends on the reason for the failure, so the two
# cases can be distinguished:
#
# * If the reset failed because the connection was lost, a
#   Sequel::DatabaseDisconnectError is raised, the same error used for
#   other cases where the connection is no longer usable.
# * If the reset failed for any other reason, a
#   Sequel::ConnectionReset::ResetError is raised, indicating the
#   connection itself is probably still usable, but the session state
#   (such as the session role) could not be restored.
#
# If an exception is already being raised when the connection is checked
# back into the pool (for example, because a transaction using the
# connection was interrupted), the reset is still attempted and the
# connection is still disconnected if the reset fails, but no
# reset-related exception is raised, so the original exception is not
# hidden.
#
# The reset runs when the connection is checked back into the pool,
# after any transaction using the connection has been committed or
# rolled back.  This extension never retries transactions or other user
# code.  A reset failure after a completed transaction only affects the
# connection, it does not cause the already completed work to be
# repeated.
#
# Note that on the threaded and sharded threaded connection pools, the
# reset is run while the pool mutex is held, so a slow reset can delay
# other threads checking connections in or out.  The timed queue
# connection pools (the default on Ruby 3.2+) do not hold the pool
# mutex while running the reset.
#
# Like the connection_validator extension, this extension does not work
# with the single threaded and sharded single threaded connection pools.
#
# Related module: Sequel::ConnectionReset

#
module Sequel
  module ConnectionReset
    # Error raised when a connection reset fails for a reason other than
    # the connection being disconnected.  This indicates the connection
    # itself is probably still usable, but the session state on the
    # connection could not be restored, so the connection was removed
    # from the pool instead of being reused.
    class ResetError < DatabaseError
      # The underlying exception raised by the reset attempt.
      attr_accessor :database_error
    end

    # The reset to run on each connection checked back into the pool.
    # Can be a string, which is treated as SQL to execute on the
    # connection, or a callable object, which is called with the
    # connection.  Defaults to nil, which does not run any reset.
    attr_accessor :connection_reset

    # Make sure the extension is not loaded into an unsupported
    # connection pool.
    def self.extended(pool)
      case pool.pool_type
      when :single, :sharded_single
        raise Error, "cannot load connection_reset extension if using single or sharded_single connection pool"
      end
    end

    private

    # Run the configured reset on the connection before returning it to
    # the pool.  If the reset fails, disconnect the connection instead of
    # returning it to the pool, so the next checkout will not receive a
    # connection with unrestored session state.
    def checkin_connection(*a)
      if @connection_reset
        case pool_type
        when :sharded_threaded
          conn = a[1]
        when :sharded_timed_queue
          conn, server = a
        else
          conn = a[0]
        end

        # Capture any exception currently being raised, since the reset
        # failure handling below should not hide it.
        in_flight_exception = $!

        begin
          reset_connection(conn)
        rescue ::StandardError => e
          disconnect_failed_reset_connection(conn, server)

          unless in_flight_exception
            if disconnect_error?(e)
              # The connection itself is no longer usable.
              raise Sequel.convert_exception_class(e, Sequel::DatabaseDisconnectError)
            else
              # The connection is probably still usable, but the session
              # state could not be restored.
              error = ResetError.new("connection reset failed: #{e.class}: #{e.message}")
              error.database_error = e
              error.set_backtrace(e.backtrace)
              raise error
            end
          end

          return nil
        end
      end

      super
    end

    # Disconnect a connection whose reset failed, making sure the pool
    # no longer accounts for the connection.
    def disconnect_failed_reset_connection(conn, server)
      if pool_type == :sharded_timed_queue
        disconnect_pool_connection(conn, server)
      else
        disconnect_connection(conn)
      end
    end

    # Execute the configured reset on the connection.
    def reset_connection(conn)
      case reset = @connection_reset
      when ::String
        db.send(:log_connection_execute, conn, reset)
      else
        reset.call(conn)
      end
    end
  end

  Database.register_extension(:connection_reset){|db| db.pool.extend(ConnectionReset)}
end
