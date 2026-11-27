require 'spec_helper'

begin
  require 'active_record'
  require 'sqlite3'
  require 'devise/orm/active_record'
  require 'rack/mock'
  BACKUP_AUDIT_INTEGRATION_AVAILABLE = true
rescue LoadError
  BACKUP_AUDIT_INTEGRATION_AVAILABLE = false
end

if BACKUP_AUDIT_INTEGRATION_AVAILABLE
  AUDIT_FIXTURE_PASSWORD = 'synthetic-fixture-password'.freeze
  AUDIT_FIXTURE_OTP_SEED = 'JBSWY3DPEHPK3PXP'.freeze
  AUDIT_FIXTURE_SCOPE    = :audit_user
  SHORTCUT_FIXTURE_SCOPE = :shortcut_user
  SILENT_FIXTURE_SCOPE   = :silent_user

  ActiveRecord::Base.establish_connection(adapter: 'sqlite3', database: ':memory:')
  ActiveRecord::Schema.verbose = false
  ActiveRecord::Schema.define do
    create_table :audit_users, force: true do |table|
      table.string  :email
      table.string  :encrypted_password
      table.string  :otp_secret
      table.text    :otp_backup_codes
      table.integer :consumed_timestep
      table.boolean :otp_required_for_login, default: true, null: false
    end
  end

  ActiveRecord::Encryption.configure(
    primary_key: 'a' * 32,
    deterministic_key: 'b' * 32,
    key_derivation_salt: 'c' * 32
  )
  Devise.stretches = 1

  class AuditUser < ActiveRecord::Base
    self.table_name = 'audit_users'

    class_attribute :fail_consumption_storage, default: false

    devise :two_factor_authenticatable, :two_factor_backupable
    serialize :otp_backup_codes, coder: JSON

    after_update do
      if self.class.fail_consumption_storage && saved_change_to_otp_backup_codes?
        raise ActiveRecord::RecordNotSaved, 'synthetic consumption storage failure'
      end
    end
  end

  # A deliberately unsafe double: it treats a successful comparison as a
  # completed consumption and returns true while writing the same code set
  # back. It also emits the same audit phases as the real implementation, so
  # detection has to come from the committed storage and the real session
  # rather than from the audit labels alone.
  class ShortcutAuditUser < ActiveRecord::Base
    self.table_name = 'audit_users'

    devise :two_factor_authenticatable, :two_factor_backupable
    serialize :otp_backup_codes, coder: JSON

    def invalidate_otp_backup_code!(code)
      identifier = audit_security_identifier
      [:started, :verified].each do |phase|
        DeviseTwoFactor::Audit.publish(
          event: DeviseTwoFactor::Audit::CONSUMPTION,
          phase: phase.to_s,
          security_identifier: identifier
        )
      end

      stored = otp_backup_codes || []
      return false unless stored.any? { |hash| Devise::Encryptor.compare(self.class, hash, code) }

      self.otp_backup_codes = stored.dup
      save!(validate: false)
      DeviseTwoFactor::Audit.publish(
        event: DeviseTwoFactor::Audit::CONSUMPTION,
        phase: DeviseTwoFactor::Audit::STORED,
        security_identifier: identifier
      )
      true
    end
  end

  # An even quieter double: it reports success from verification alone and
  # publishes no audit facts, so only the committed storage can expose it.
  class SilentAuditUser < ActiveRecord::Base
    self.table_name = 'audit_users'

    devise :two_factor_authenticatable, :two_factor_backupable
    serialize :otp_backup_codes, coder: JSON

    def invalidate_otp_backup_code!(code)
      stored = otp_backup_codes || []
      stored.any? { |hash| Devise::Encryptor.compare(self.class, hash, code) }
    end
  end

  Devise.add_mapping(:audit_users, class_name: 'AuditUser', failure_app: ->(_env) { [401, {}, []] })
  Devise.add_mapping(:shortcut_users, class_name: 'ShortcutAuditUser', failure_app: ->(_env) { [401, {}, []] })
  Devise.add_mapping(:silent_users, class_name: 'SilentAuditUser', failure_app: ->(_env) { [401, {}, []] })

  Warden::Manager.serialize_into_session(AUDIT_FIXTURE_SCOPE) { |user| AuditUser.serialize_into_session(user) }
  Warden::Manager.serialize_from_session(AUDIT_FIXTURE_SCOPE) { |key| AuditUser.serialize_from_session(*key) }
  Warden::Manager.serialize_into_session(SHORTCUT_FIXTURE_SCOPE) { |user| ShortcutAuditUser.serialize_into_session(user) }
  Warden::Manager.serialize_from_session(SHORTCUT_FIXTURE_SCOPE) { |key| ShortcutAuditUser.serialize_from_session(*key) }
  Warden::Manager.serialize_into_session(SILENT_FIXTURE_SCOPE) { |user| SilentAuditUser.serialize_into_session(user) }
  Warden::Manager.serialize_from_session(SILENT_FIXTURE_SCOPE) { |key| SilentAuditUser.serialize_from_session(*key) }

  describe 'recovery-code audit evidence' do
    before :each do
      AuditUser.delete_all
      @account_sequence = 0
    end

    def create_user(klass = AuditUser, email: nil)
      @account_sequence = (@account_sequence || 0) + 1
      klass.create!(
        email: email || "synthetic.audit.user.#{@account_sequence}@example.invalid",
        password: AUDIT_FIXTURE_PASSWORD,
        otp_secret: AUDIT_FIXTURE_OTP_SEED,
        otp_required_for_login: true
      )
    end

    def codes_match?(hashes, plaintext_codes)
      hashes.length == plaintext_codes.length &&
        plaintext_codes.all? do |code|
          hashes.any? { |hash| Devise::Encryptor.compare(AuditUser, hash, code) }
        end
    end

    def issue_codes(user)
      codes = user.generate_otp_backup_codes!
      user.save!
      codes
    end

    def login(scope, email, code, session, password: AUDIT_FIXTURE_PASSWORD)
      env = Rack::MockRequest.env_for("/#{scope}/sign_in", method: 'POST', params: {
        scope => { email: email, password: password, otp_attempt: code }
      })
      env[Rack::RACK_REQUEST_QUERY_HASH] = ActiveSupport::HashWithIndifferentAccess.new
      env['devise.allow_params_authentication'] = true
      env['rack.session'] = session
      proxy = env['warden'] = Warden::Proxy.new(env, Warden::Manager.new(nil))
      proxy.authenticate(:two_factor_backupable, scope: scope)
      proxy
    end

    def session_key(scope)
      "warden.user.#{scope}.key"
    end

    def session_user(scope, session)
      env = Rack::MockRequest.env_for("/#{scope}/account")
      env['rack.session'] = session
      Warden::Proxy.new(env, Warden::Manager.new(nil)).user(scope)
    end

    def stored_codes(user)
      raw = user.class.connection.select_value(
        "SELECT otp_backup_codes FROM audit_users WHERE id = #{Integer(user.id)}"
      )
      raw.nil? ? [] : JSON.parse(raw)
    end

    # Records every audit fact together with the session state and the
    # committed code count at the instant the fact was published. This makes
    # the audit sequence verifiable against real storage and the real Warden
    # session rather than against labels alone.
    def capture_audit(session: {}, store: nil)
      observations = []
      subscriber = ActiveSupport::Notifications.subscribe(DeviseTwoFactor::Audit::EVENT_NAME) do |*args|
        event = ActiveSupport::Notifications::Event.new(*args)
        observations << {
          event: event,
          session_stored: [AUDIT_FIXTURE_SCOPE, SHORTCUT_FIXTURE_SCOPE, SILENT_FIXTURE_SCOPE].any? do |scope|
            session.key?(session_key(scope))
          end,
          stored_count: store ? store.call.length : nil
        }
      end
      yield observations
      observations
    ensure
      ActiveSupport::Notifications.unsubscribe(subscriber) if subscriber
    end

    def events_of(observations)
      observations.map { |observation| observation[:event] }
    end

    def phases_for(events, identifier, category: DeviseTwoFactor::Audit::CONSUMPTION)
      events.select do |event|
        event.payload[:event] == category && event.payload[:security_identifier] == identifier.to_s
      end.map { |event| event.payload[:phase] }
    end

    # Compares the claimed outcome with the evidence that is observable
    # outside the audit stream: the committed code set and the serialized
    # Warden session.
    def verdict(events:, identifier:, session:, before_count:, after_count:, scope: AUDIT_FIXTURE_SCOPE)
      phases = phases_for(events, identifier)
      claimed_stored = phases.include?(DeviseTwoFactor::Audit::STORED)
      storage_changed = after_count == before_count - 1
      session_completed = session.key?(session_key(scope))
      {
        phases: phases,
        claimed_stored: claimed_stored,
        storage_changed: storage_changed,
        session_completed: session_completed,
        complete: claimed_stored && storage_changed && session_completed,
        # A completed session with an unchanged code set, or a storage claim
        # without a real write, is the signature of the verification shortcut.
        inconsistent: (claimed_stored || session_completed) && !storage_changed,
        partial: session_completed != storage_changed
      }
    end

    it 'keeps audit payloads limited to the security identifier, category and phase' do
      user = create_user
      codes = nil
      session = {}

      observations = capture_audit(session: session, store: -> { stored_codes(user) }) do
        codes = issue_codes(user)
        login(AUDIT_FIXTURE_SCOPE, user.email, codes.last, session)
      end
      events = events_of(observations)

      expect(events).not_to be_empty
      events.each do |event|
        expect(event.payload.keys).to contain_exactly(:security_identifier, :event, :phase)
        expect(event.payload[:security_identifier]).to eq(user.id.to_s)
        serialized = event.payload.inspect
        codes.each { |code| expect(serialized).not_to include(code) }
        expect(serialized).not_to include(AUDIT_FIXTURE_OTP_SEED)
        expect(serialized).not_to include(user.email)
      end

      expect do
        DeviseTwoFactor::Audit.publish(
          event: DeviseTwoFactor::Audit::CONSUMPTION,
          phase: DeviseTwoFactor::Audit::STARTED,
          security_identifier: user.id,
          code: codes.first
        )
      end.to raise_error(ArgumentError, /unsupported audit fields/)

      expect do
        DeviseTwoFactor::Audit.publish(
          event: DeviseTwoFactor::Audit::CONSUMPTION,
          phase: DeviseTwoFactor::Audit::STARTED,
          security_identifier: user.id,
          otp_secret: AUDIT_FIXTURE_OTP_SEED
        )
      end.to raise_error(ArgumentError, /unsupported audit fields/)

      # Stored phases are only published once the write is visible. The
      # observation log records the committed count at that instant.
      stored_observations = observations.select do |observation|
        observation[:event].payload[:phase] == DeviseTwoFactor::Audit::STORED
      end
      expect(stored_observations).not_to be_empty
      stored_observations.each do |observation|
        expect(observation[:stored_count]).to be_a(Integer)
      end
      consumption_stored = stored_observations.find do |observation|
        observation[:event].payload[:event] == DeviseTwoFactor::Audit::CONSUMPTION
      end
      expect(consumption_stored[:stored_count]).to eq(4)
    end

    it 'verifies an old code, interleaves a regeneration, and refuses to overwrite the new set' do
      user = create_user
      old_codes = issue_codes(user)

      regenerated_codes = nil
      interleaved = false
      session = {}

      observations = capture_audit(session: session) do
        interleaver = ActiveSupport::Notifications.subscribe(DeviseTwoFactor::Audit::EVENT_NAME) do |*args|
          event = ActiveSupport::Notifications::Event.new(*args)
          payload = event.payload
          next unless payload[:event] == DeviseTwoFactor::Audit::CONSUMPTION
          next unless payload[:phase] == DeviseTwoFactor::Audit::VERIFIED
          next unless payload[:security_identifier] == user.id.to_s
          next if interleaved

          interleaved = true
          generator = AuditUser.find(user.id)
          regenerated_codes = generator.generate_otp_backup_codes!
          generator.save!
        end

        begin
          login(AUDIT_FIXTURE_SCOPE, user.email, old_codes.first, session)
        ensure
          ActiveSupport::Notifications.unsubscribe(interleaver)
        end
      end

      expect(interleaved).to be true
      expect(session).not_to have_key(session_key(AUDIT_FIXTURE_SCOPE))
      expect(codes_match?(stored_codes(user), regenerated_codes)).to be true
      expect(stored_codes(user).length).to eq(regenerated_codes.length)
      events = events_of(observations)
      expect(phases_for(events, user.id)).to eq(%w[started verified superseded])
      expect(phases_for(events, user.id, category: DeviseTwoFactor::Audit::REGENERATION))
        .to eq(%w[started generated stored])
    end

    it 'records a failed consumption storage write without claiming storage or session completion' do
      user = create_user
      codes = issue_codes(user)
      before_codes = stored_codes(user)
      session = {}

      AuditUser.fail_consumption_storage = true
      begin
        observations = capture_audit(session: session) do
          expect do
            login(AUDIT_FIXTURE_SCOPE, user.email, codes.first, session)
          end.to raise_error(ActiveRecord::RecordNotSaved, /synthetic consumption storage failure/)
        end
      ensure
        AuditUser.fail_consumption_storage = false
      end

      expect(session).not_to have_key(session_key(AUDIT_FIXTURE_SCOPE))
      expect(session_user(AUDIT_FIXTURE_SCOPE, session)).to be_nil
      expect(stored_codes(user)).to match_array(before_codes)
      failed_events = events_of(observations)
      expect(phases_for(failed_events, user.id)).to eq(%w[started verified failed])
      expect(failed_events.map { |event| event.payload[:phase] })
        .not_to include(DeviseTwoFactor::Audit::STORED)

      retry_session = {}
      retry_observations = capture_audit(session: retry_session) do
        login(AUDIT_FIXTURE_SCOPE, user.email, codes.first, retry_session)
      end
      retry_phases = phases_for(events_of(retry_observations), user.id)

      expect(retry_session).to have_key(session_key(AUDIT_FIXTURE_SCOPE))
      expect(session_user(AUDIT_FIXTURE_SCOPE, retry_session).id).to eq(user.id)
      expect(stored_codes(user).length).to eq(before_codes.length - 1)
      expect(retry_phases).to eq(%w[started verified stored session_established])
    end

    it 'records storage and session completion for a newly regenerated code' do
      user = create_user
      fresh_codes = nil
      before_codes = nil
      session = {}

      observations = capture_audit(session: session, store: -> { stored_codes(user) }) do
        fresh_codes = issue_codes(user)
        before_codes = stored_codes(user)
        login(AUDIT_FIXTURE_SCOPE, user.email, fresh_codes.sample, session)
      end
      events = events_of(observations)

      expect(session).to have_key(session_key(AUDIT_FIXTURE_SCOPE))
      expect(session_user(AUDIT_FIXTURE_SCOPE, session).id).to eq(user.id)
      after_codes = stored_codes(user)
      expect(after_codes.length).to eq(before_codes.length - 1)
      expect(after_codes & before_codes).to eq(after_codes)

      result = verdict(
        events: events,
        identifier: user.id,
        session: session,
        before_count: before_codes.length,
        after_count: after_codes.length
      )

      expect(result[:phases]).to eq(%w[started verified stored session_established])
      expect(result[:complete]).to be true
      expect(result[:inconsistent]).to be false

      consumption_observations = observations.select do |observation|
        observation[:event].payload[:event] == DeviseTwoFactor::Audit::CONSUMPTION
      end
      stored_observation = consumption_observations.find do |observation|
        observation[:event].payload[:phase] == DeviseTwoFactor::Audit::STORED
      end
      session_observation = consumption_observations.find do |observation|
        observation[:event].payload[:phase] == DeviseTwoFactor::Audit::SESSION_ESTABLISHED
      end
      expect(stored_observation[:stored_count]).to eq(before_codes.length - 1)
      expect(stored_observation[:session_stored]).to be false
      expect(session_observation[:stored_count]).to eq(before_codes.length - 1)
      expect(session_observation[:session_stored]).to be true
      expect(phases_for(events, user.id, category: DeviseTwoFactor::Audit::REGENERATION))
        .to eq(%w[started generated stored])
    end

    it 'separates a stored consumption from a completed session when the password is wrong' do
      user = create_user
      codes = issue_codes(user)
      before_codes = stored_codes(user)
      session = {}

      observations = capture_audit(session: session) do
        login(AUDIT_FIXTURE_SCOPE, user.email, codes.first, session, password: 'wrong-synthetic-password')
      end
      events = events_of(observations)

      result = verdict(
        events: events,
        identifier: user.id,
        session: session,
        before_count: before_codes.length,
        after_count: stored_codes(user).length
      )

      expect(session).not_to have_key(session_key(AUDIT_FIXTURE_SCOPE))
      expect(stored_codes(user).length).to eq(before_codes.length - 1)
      expect(result[:phases]).to eq(%w[started verified stored])
      expect(result[:claimed_stored]).to be true
      expect(result[:storage_changed]).to be true
      expect(result[:session_completed]).to be false
      expect(result[:complete]).to be false
      expect(result[:inconsistent]).to be false

      # The consumed code cannot be retried; a sibling code signs in normally.
      retry_session = {}
      retry_observations = capture_audit(session: retry_session) do
        login(AUDIT_FIXTURE_SCOPE, user.email, codes.last, retry_session)
      end

      expect(retry_session).to have_key(session_key(AUDIT_FIXTURE_SCOPE))
      expect(phases_for(events_of(retry_observations), user.id))
        .to eq(%w[started verified stored session_established])
      expect(stored_codes(user).length).to eq(before_codes.length - 2)
    end

    it 'detects a silent double that returns success from verification alone' do
      user = create_user(SilentAuditUser, email: 'synthetic.silent.user@example.invalid')
      codes = issue_codes(user)
      before_codes = stored_codes(user)
      session = {}

      observations = capture_audit(session: session) do
        login(SILENT_FIXTURE_SCOPE, user.email, codes.first, session)
      end
      events = events_of(observations)

      result = verdict(
        events: events,
        identifier: user.id,
        session: session,
        before_count: before_codes.length,
        after_count: stored_codes(user).length,
        scope: SILENT_FIXTURE_SCOPE
      )

      # The generic strategy path still reports the session phase because the
      # double returned true; the missing storage claim is what exposes it.
      expect(phases_for(events, user.id)).to eq(%w[session_established])
      expect(session).to have_key(session_key(SILENT_FIXTURE_SCOPE))
      expect(session_user(SILENT_FIXTURE_SCOPE, session).id).to eq(user.id)
      expect(stored_codes(user)).to match_array(before_codes)
      expect(result[:claimed_stored]).to be false
      expect(result[:session_completed]).to be true
      expect(result[:inconsistent]).to be true
      expect(result[:complete]).to be false
    end

    it 'detects an audited double that reports consumption complete from verification alone' do
      user = create_user(ShortcutAuditUser, email: 'synthetic.shortcut.user@example.invalid')
      codes = issue_codes(user)
      before_codes = stored_codes(user)
      session = {}

      observations = capture_audit(session: session) do
        login(SHORTCUT_FIXTURE_SCOPE, user.email, codes.first, session)
      end
      events = events_of(observations)

      result = verdict(
        events: events,
        identifier: user.id,
        session: session,
        before_count: before_codes.length,
        after_count: stored_codes(user).length,
        scope: SHORTCUT_FIXTURE_SCOPE
      )

      expect(session).to have_key(session_key(SHORTCUT_FIXTURE_SCOPE))
      expect(stored_codes(user)).to match_array(before_codes)
      # The double's own audit labels and the Warden session both claim a
      # completed consumption; only the committed code set contradicts it.
      expect(result[:phases]).to eq(%w[started verified stored session_established])
      expect(result[:claimed_stored]).to be true
      expect(result[:storage_changed]).to be false
      expect(result[:session_completed]).to be true
      expect(result[:inconsistent]).to be true
      expect(result[:complete]).to be false
      expect(result[:partial]).to be true
    end
  end
else
  RSpec.describe 'recovery-code audit evidence' do
    it 'needs activerecord, sqlite3 and rack to exercise the real login strategy' do
      skip 'activerecord/sqlite3 are not available in this bundle'
    end
  end
end
