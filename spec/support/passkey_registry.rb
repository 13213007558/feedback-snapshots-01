# frozen_string_literal: true

require "securerandom"

# Integrator-side passkey flow with an explicit registration lifecycle:
#
#   pending  -- registration session opened, ceremony not verified yet
#   verified -- attestation verified against the original session challenge,
#               but the credential is NOT persisted and cannot authenticate
#   active   -- credential committed to the credential store, usable for login
#
# Capacity is enforced at commit time against already committed (active)
# records only, so a failed write can be retried and two parallel
# verifications cannot both squeeze into the last remaining slot.
class PasskeyRegistry
  class CapacityExceededError < StandardError; end
  class StorageError < StandardError; end
  class UnknownCredentialError < StandardError; end
  class InvalidSessionStateError < StandardError; end

  CredentialRecord = Struct.new(:id, :user_handle, :public_key, :sign_count, keyword_init: true)

  class RegistrationSession
    attr_reader :id, :user_handle, :challenge
    attr_accessor :state, :verified_credential

    def initialize(id:, user_handle:, challenge:)
      @id = id
      @user_handle = user_handle
      @challenge = challenge
      @state = :pending
    end
  end

  # In-memory stand-in for the integrator's database. Writes can be
  # forced to fail in order to exercise the commit retry path.
  class CredentialStore
    def initialize
      @records = []
      @pending_failures = 0
    end

    def fail_next_write!
      @pending_failures += 1
    end

    def insert(record)
      if @pending_failures.positive?
        @pending_failures -= 1
        raise StorageError, "credential insert failed"
      end

      @records << record
    end

    def all
      @records.dup
    end
  end

  attr_reader :credential_limit, :credential_store

  def initialize(relying_party:, credential_limit:, credential_store: CredentialStore.new)
    @relying_party = relying_party
    @credential_limit = credential_limit
    @credential_store = credential_store
    @sessions = {}
  end

  def begin_registration(user_handle)
    session = RegistrationSession.new(
      id: SecureRandom.uuid,
      user_handle: user_handle,
      challenge: relying_party.encoder.encode(SecureRandom.random_bytes(32))
    )
    @sessions[session.id] = session
    session
  end

  # Verifies the ceremony against the challenge of the original
  # registration session. Marks the session as verified but persists
  # nothing, so the credential cannot be used for authentication yet.
  def verify_registration(session_id, public_key_credential)
    session = registration_session(session_id)
    ensure_state(session, :pending)

    public_key_credential.verify(session.challenge)

    session.verified_credential = {
      id: public_key_credential.id,
      public_key: public_key_credential.public_key,
      sign_count: public_key_credential.sign_count
    }
    session.state = :verified
    session.verified_credential
  end

  # Persists a verified credential. Capacity counts committed records
  # only. A storage failure leaves the session in :verified state so the
  # commit can be retried; a capacity rejection does the same.
  def commit_registration(session_id)
    session = registration_session(session_id)
    ensure_state(session, :verified)

    if committed_credentials.size >= credential_limit
      raise CapacityExceededError, "credential limit of #{credential_limit} reached"
    end

    credential = session.verified_credential
    record = CredentialRecord.new(
      id: credential[:id],
      user_handle: session.user_handle,
      public_key: credential[:public_key],
      sign_count: credential[:sign_count]
    )

    credential_store.insert(record)
    session.state = :active
    record
  end

  def session_state(session_id)
    registration_session(session_id).state
  end

  def begin_authentication(user_handle)
    {
      challenge: relying_party.encoder.encode(SecureRandom.random_bytes(32)),
      allow_credentials: active_credentials_for(user_handle).map(&:id)
    }
  end

  # Only persisted (active) credentials can build a login. A credential
  # that was verified but never committed is unknown to this lookup.
  def verify_authentication(user_handle, challenge, public_key_credential)
    record = active_credentials_for(user_handle).find { |candidate| candidate.id == public_key_credential.id }
    raise UnknownCredentialError, "credential is not registered for this user" unless record

    public_key_credential.verify(challenge, public_key: record.public_key, sign_count: record.sign_count)
    record.sign_count = public_key_credential.sign_count
    record
  end

  def committed_credentials
    credential_store.all
  end

  def remaining_capacity
    credential_limit - committed_credentials.size
  end

  private

  attr_reader :relying_party

  def registration_session(session_id)
    @sessions.fetch(session_id)
  end

  def ensure_state(session, expected)
    return if session.state == expected

    raise InvalidSessionStateError, "session #{session.id} is #{session.state}, expected #{expected}"
  end

  def active_credentials_for(user_handle)
    committed_credentials.select { |record| record.user_handle == user_handle }
  end
end
