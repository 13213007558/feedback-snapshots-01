# -*- ruby encoding: utf-8 -*-

# RFC 5805 - Lightweight Directory Access Protocol (LDAP) Transactions.
#
# A transaction groups a number of directory update operations (Add, Modify,
# Delete, and ModifyDN/Rename) into a single atomic unit of interaction:
#
#   result = ldap.transaction do |txn_ldap|
#     txn_ldap.add(...)
#     txn_ldap.modify(...)
#     txn_ldap.delete(...)
#     txn_ldap.rename(...)
#   end
#
# The coordinator obtains a transaction identifier with the Start Transaction
# extended operation, attaches the Transaction Specification control to every
# participating update request, and settles the transaction with the End
# Transaction extended operation. All traffic for a transaction is pinned to
# the single LDAP association on which it was started because transaction
# identifiers are not valid across connections (RFC 5805 section 5).
class Net::LDAP::Transaction
  # Update operations that may participate in a transaction. Search and Bind
  # are deliberately excluded: the control is only appropriate for updates,
  # and a Bind aborts any outstanding transaction (RFC 5805 section 3.5).
  UPDATE_OPERATIONS = [:add, :modify, :delete, :rename].freeze

  # The outcome of a transaction. Callers discriminate the three-way state
  # they can act upon (#committed?, #rolled_back?, #unknown?) while #reason
  # records precisely how that state was reached.
  class Result
    # Final, three-way classification of the transaction outcome.
    #
    # :committed    - the server confirmed every update was applied.
    # :rolled_back  - the server confirmed no updates were applied.
    # :unknown      - settlement could not be confirmed; the real outcome is
    #                 unknowable from the client and must be re-queried.
    # :not_started  - no transaction was established, so nothing ran.
    STATUSES = [:committed, :rolled_back, :unknown, :not_started].freeze

    # Precise reason the status was reached.
    REASONS = [
      :committed,               # successful commit response
      :start_failed,            # Start Transaction extension failed
      :operation_failed,        # an update returned a non-success result
      :block_exception,         # the caller's block raised an exception
      :commit_failed,           # End Transaction (commit) was refused
      :commit_response_missing, # no valid response to the commit request
      :abort_failed,            # End Transaction (abort) could not be confirmed
    ].freeze

    attr_reader :status, :reason, :code, :message, :response, :error, :operation

    def initialize(status:, reason: nil, code: nil, message: nil,
                   response: nil, error: nil, operation: nil)
      unless STATUSES.include?(status)
        raise ArgumentError, "unknown transaction status #{status.inspect}"
      end
      if reason && !REASONS.include?(reason)
        raise ArgumentError, "unknown transaction reason #{reason.inspect}"
      end

      @status = status
      @reason = reason
      @code = code
      @message = message
      @response = response
      @error = error
      @operation = operation
    end

    # The server confirmed the transaction was committed atomically.
    def committed?
      status == :committed
    end

    # The server confirmed the transaction was aborted/rolled back and that
    # none of the requested updates were applied.
    def rolled_back?
      status == :rolled_back
    end

    # The transaction's real outcome cannot be determined from the client.
    def unknown?
      status == :unknown
    end

    # No transaction was ever started, so no updates were attempted.
    def not_started?
      status == :not_started
    end

    # True only for a confirmed commit, mirroring the boolean convention used
    # by the other Net::LDAP operation methods.
    def success?
      committed?
    end

    def failure?
      !success?
    end

    def to_h
      {
        status: status,
        reason: reason,
        code: code,
        message: message,
        operation: operation,
      }
    end
  end

  def initialize(ldap, connection)
    @ldap = ldap
    @connection = connection
    @identifier = nil
  end

  # Runs the transaction around the caller's block. Never raises for
  # protocol-level failures (they are encoded in the returned Result); only
  # non-StandardError system exceptions are allowed to propagate.
  def run
    # Mark the transaction active before the Start request so nesting and
    # other coordination guards are enforced for its entire lifetime.
    @ldap.current_transaction = self

    start_failure = start
    return start_failure if start_failure

    begin
      yield @ldap
    rescue Net::LDAP::TransactionOperationError => e
      return settle(:operation_failed,
                    operation: e.operation,
                    operation_result: e.operation_result,
                    error: e)
    rescue Net::LDAP::TransactionError
      # Coordination failures (nested transaction, bind inside a
      # transaction, connection swap) are programming errors and must surface
      # to the caller rather than being mistaken for a block exception.
      raise
    rescue StandardError => e
      return settle(:block_exception, error: e)
    end
    settle_commit
  ensure
    @ldap.current_transaction = nil
  end

  # Wraps a single participating update. Verifies the operation stays on the
  # transaction's connection, attaches the Transaction Specification control,
  # and turns a non-success update response into a TransactionOperationError
  # so the coordinator can abort the transaction.
  def run_operation(operation, args)
    unless UPDATE_OPERATIONS.include?(operation)
      raise Net::LDAP::OperationNotAllowedInTransactionError,
            "only #{UPDATE_OPERATIONS.join(', ')} updates may join a " \
            "transaction (got #{operation.inspect})"
    end

    ensure_same_connection!
    inject_transaction_control(args)

    result = yield

    if result.nil? || !result.respond_to?(:success?) || !result.success?
      raise Net::LDAP::TransactionOperationError.new(
        "transaction update '#{operation}' failed", operation, result)
    end

    result
  end

  # The RFC 5805 Transaction Specification control. Criticality is TRUE and
  # the control value is the transaction identifier.
  def specification_control
    [
      Net::LDAP::TransactionSpecificationOid.to_ber,
      true.to_ber,
      @identifier.to_ber,
    ].to_ber_sequence
  end

  private

  # Issues the Start Transaction extended request and stores the identifier.
  # Returns nil on success, otherwise a :not_started Result.
  def start
    pdu = @connection.start_transaction

    if pdu.result_code == Net::LDAP::ResultCodeSuccess
      @identifier = pdu.extended_response
      nil
    else
      build_result(:not_started, reason: :start_failed, response: pdu)
    end
  rescue Net::LDAP::Error => e
    build_result(:not_started, reason: :start_failed, error: e)
  end

  # Commits the transaction and classifies the settlement.
  def settle_commit
    pdu = @connection.end_transaction(@identifier, true)

    if pdu.result_code == Net::LDAP::ResultCodeSuccess
      build_result(:committed, reason: :committed, response: pdu)
    else
      # A definite, non-success settlement answer means nothing was applied.
      build_result(:rolled_back, reason: :commit_failed, response: pdu)
    end
  rescue Net::LDAP::Error => e
    # The request may have committed before the response was lost, so the
    # outcome genuinely cannot be determined.
    build_result(:unknown, reason: :commit_response_missing, error: e)
  end

  # Aborts the transaction after a specification failure or a block
  # exception. A confirmed abort is a definite roll-back; an unconfirmed
  # abort leaves the outcome unknown.
  def settle(origin_reason, error:, operation: nil, operation_result: nil)
    pdu = @connection.end_transaction(@identifier, false)

    if pdu.result_code == Net::LDAP::ResultCodeSuccess
      build_result(:rolled_back, reason: origin_reason, response: pdu,
                   error: error, operation: operation,
                   operation_result: operation_result)
    else
      build_result(:unknown, reason: :abort_failed, response: pdu,
                   error: error, operation: operation,
                   operation_result: operation_result)
    end
  rescue Net::LDAP::Error => abort_error
    build_result(:unknown, reason: :abort_failed,
                 error: error || abort_error, operation: operation,
                 operation_result: operation_result)
  end

  def inject_transaction_control(args)
    args[:controls] = Array(args[:controls]).dup << specification_control
  end

  def ensure_same_connection!
    return if @ldap.connection.equal?(@connection)

    raise Net::LDAP::TransactionConnectionError,
          "a transaction cannot move to another connection; its identifier " \
          "is only valid on the connection where it was started"
  end

  def build_result(status, reason:, response: nil, error: nil, operation: nil,
                   operation_result: nil)
    attrs = {
      status: status,
      reason: reason,
      response: response,
      error: error,
      operation: operation,
    }

    # Prefer the failing update's result so callers see why the transaction
    # was abandoned rather than the (typically successful) abort response.
    source = operation_result || response
    if source.respond_to?(:result_code)
      attrs[:code] = source.result_code
      attrs[:message] = source.error_message
    elsif error
      attrs[:message] = error.message
    end

    Result.new(**attrs)
  end
end
