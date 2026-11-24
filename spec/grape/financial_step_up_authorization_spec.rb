# frozen_string_literal: true

require 'securerandom'

# Executable reference for route-declared two-step authorization.
#
# Financial routes list both steps in `auth_steps`: service authentication and
# a short-lived ("step-up") finance approval. The endpoint only receives an
# AuthContext carrying both identities after every declared step succeeds.
# Other routes declare the service step alone and get a service-only context.
#
# A single Recorder is shared with a rack RecordingMiddleware and every
# collaborator, so each example can assert the exact order and outcome of the
# authentication work and prove whether or not business code was reached.
module FinancialStepUp
  SERVICE_STEP = 'service_authentication'
  APPROVAL_STEP = 'finance_approval'
  AUTH_CONTEXT_KEY = 'financial_step_up.auth_context'

  ServiceIdentity = Data.define(:id, :name)
  Approval = Data.define(:id, :token, :service_id, :scope, :expires_at)
  Challenge = Data.define(:status, :body, :headers)
  Verdict = Data.define(:approval, :reason) do
    def granted?
      reason.nil?
    end
  end

  # Append-only audit sink shared across one example's requests.
  class Recorder
    attr_reader :events

    def initialize
      @events = []
      @sequence = 0
    end

    def record(actor, result = nil, **fields)
      @sequence += 1
      events << fields.merge(seq: @sequence, actor:, result:).compact
    end

    def business(path, context)
      record(
        'business', 'invoked',
        path:,
        service: context.service.id,
        finance_authorized: context.finance_authorized?
      )
    end

    def trace
      events.map { |event| [event[:actor], event[:result] || event[:phase]] }
    end

    def finance_denials
      events.select { |event| event[:actor] == APPROVAL_STEP && event[:result] == 'denied' }
    end
  end

  class FakeClock
    def initialize(start)
      @current = start
    end

    def now
      @current
    end

    def advance(seconds)
      @current += seconds
    end
  end

  # Outermost probe: records request entry and the final response status.
  class RecordingMiddleware
    def initialize(app, recorder)
      @app = app
      @recorder = recorder
    end

    def call(env)
      @recorder.record(
        'middleware', nil,
        phase: 'enter',
        method: env['REQUEST_METHOD'],
        path: env['PATH_INFO']
      )
      status, headers, body = @app.call(env)
      @recorder.record(
        'middleware', nil,
        phase: 'leave',
        method: env['REQUEST_METHOD'],
        path: env['PATH_INFO'],
        status:
      )
      [status, headers, body]
    end
  end

  # First step: resolves the Bearer service credential to a ServiceIdentity.
  class ServiceAuthenticator
    BEARER_PREFIX = 'Bearer '

    def initialize(identities:, recorder:)
      @identities = identities
      @recorder = recorder
    end

    def authenticate(header_value)
      identity = @identities[bearer_token(header_value)]
      return success(identity) if identity

      reason = header_value.nil? ? 'missing_credentials' : 'invalid_credentials'
      @recorder.record(SERVICE_STEP, 'failure', reason:)
      nil
    end

    private

    def success(identity)
      @recorder.record(SERVICE_STEP, 'success', service: identity.id)
      identity
    end

    def bearer_token(header_value)
      return unless header_value&.start_with?(BEARER_PREFIX)

      header_value.delete_prefix(BEARER_PREFIX)
    end
  end

  # Second step: issues and verifies short-lived, service- and scope-bound
  # approvals. Possession of the service credential never implies an approval.
  class ApprovalAuthority
    REAPPLY_PATH = '/auth/finance-approvals'
    DEFAULT_TTL = 60

    MESSAGES = {
      'missing' => 'A short-lived finance approval is required; request one and retry.',
      'unknown' => 'The presented finance approval was not recognized; request a new one.',
      'expired' => 'The finance approval has expired; re-apply for a short-lived approval.',
      'service_mismatch' => 'The finance approval was issued to another service; re-apply.',
      'scope_mismatch' => 'The finance approval does not cover this action; re-apply with the required scope.'
    }.freeze

    def initialize(recorder:, clock: -> { Time.now })
      @recorder = recorder
      @clock = clock
      @issued = {}
      @serial = 0
    end

    def issue(service_id:, scope:, ttl: DEFAULT_TTL)
      @serial += 1
      approval = Approval.new(
        id: format('apr_%04d', @serial),
        token: "finance-approval-#{@serial}-#{SecureRandom.hex(8)}",
        service_id:,
        scope: scope.to_s,
        expires_at: @clock.call + ttl
      )
      @issued[approval.token] = approval
      approval
    end

    def verify(token, service_id:, scope:)
      reason = failure_reason(token, service_id, scope)
      return denied(service_id, reason) if reason

      approval = @issued[token]
      @recorder.record(
        APPROVAL_STEP, 'granted',
        service: service_id,
        approval: approval.id,
        scope: approval.scope
      )
      Verdict.new(approval, nil)
    end

    private

    def denied(service_id, reason)
      @recorder.record(APPROVAL_STEP, 'denied', service: service_id, reason:)
      Verdict.new(nil, reason)
    end

    def failure_reason(token, service_id, scope)
      return 'missing' if token.nil? || token.empty?

      approval = @issued[token]
      return 'unknown' unless approval
      return 'service_mismatch' unless approval.service_id == service_id
      return 'scope_mismatch' unless approval.scope == scope.to_s
      return 'expired' if @clock.call >= approval.expires_at

      nil
    end
  end

  # The authenticated context handed to business code only after all steps pass.
  class AuthContext
    attr_reader :service, :approval

    def initialize(service:, approval: nil)
      @service = service
      @approval = approval
    end

    def finance_authorized?
      !@approval.nil?
    end

    def to_h
      {
        authenticated_service: service.id,
        service_name: service.name,
        finance_authorized: finance_authorized?,
        approval: approval_payload
      }
    end

    private

    def approval_payload
      return unless approval

      { id: approval.id, scope: approval.scope, expires_at: approval.expires_at.utc.iso8601 }
    end
  end

  # Runs the ordered steps declared by `auth_steps` on the current route and
  # returns either an AuthContext or a Challenge describing how to recover.
  class RouteGuard
    def initialize(options:, headers:, authenticator:, authority:)
      @steps = Array(options[:auth_steps]).map(&:to_s)
      @scope = options[:finance_scope]&.to_s
      @headers = headers
      @authenticator = authenticator
      @authority = authority
    end

    def call
      identity = authenticate_service
      return identity if identity.is_a?(Challenge)

      approval = verify_finance_approval(identity)
      return approval if approval.is_a?(Challenge)

      AuthContext.new(service: identity, approval:)
    end

    private

    def authenticate_service
      return unless @steps.include?(SERVICE_STEP)

      @authenticator.authenticate(@headers['authorization']) || service_challenge
    end

    def verify_finance_approval(identity)
      return unless @steps.include?(APPROVAL_STEP)

      verdict = @authority.verify(
        @headers['x-finance-approval'],
        service_id: identity&.id,
        scope: @scope
      )
      return approval_challenge(identity, verdict.reason) unless verdict.granted?

      verdict.approval
    end

    def service_challenge
      Challenge.new(
        401,
        { error: 'service_authentication_failed', message: 'A valid Bearer service credential is required.' },
        { 'www-authenticate' => 'Bearer realm="financial-api"' }
      )
    end

    def approval_challenge(identity, reason)
      Challenge.new(
        403,
        challenge_body(identity, reason),
        {
          'x-finance-approval-status' => reason,
          'x-reapply-approval-url' => ApprovalAuthority::REAPPLY_PATH
        }
      )
    end

    def challenge_body(identity, reason)
      {
        error: 'finance_approval_required',
        reason:,
        message: ApprovalAuthority::MESSAGES.fetch(reason),
        reapply: {
          method: 'POST',
          path: ApprovalAuthority::REAPPLY_PATH,
          header: 'X-Finance-Approval',
          scope: @scope,
          ttl_seconds: ApprovalAuthority::DEFAULT_TTL
        },
        diagnostic: { phase: APPROVAL_STEP, authenticated_service: identity&.id }
      }
    end
  end
end

describe FinancialStepUp do
  let(:service_id) { 'svc-payments' }
  let(:service_token) { 'payments-bearer-token' }
  let(:recorder) { described_class::Recorder.new }
  let(:clock) { described_class::FakeClock.new(Time.utc(2026, 11, 24, 12, 0, 0)) }

  let(:authority) do
    described_class::ApprovalAuthority.new(recorder:, clock: clock.method(:now))
  end

  let(:authenticator) do
    identity = described_class::ServiceIdentity.new(service_id, 'Payments Service')
    described_class::ServiceAuthenticator.new(identities: { service_token => identity }, recorder:)
  end

  let(:app) do
    rec = recorder
    svc = authenticator
    apr = authority

    api = Class.new(Grape::API) do
      format :json

      helpers do
        def current_auth
          env[FinancialStepUp::AUTH_CONTEXT_KEY]
        end
      end

      before do
        outcome = FinancialStepUp::RouteGuard.new(
          options: route.options,
          headers:,
          authenticator: svc,
          authority: apr
        ).call

        if outcome.is_a?(FinancialStepUp::Challenge)
          error!(outcome.body, outcome.status, outcome.headers)
        else
          env[FinancialStepUp::AUTH_CONTEXT_KEY] = outcome
        end
      end

      # Phase-one-only route used by callers to obtain (or re-apply for) the
      # short-lived phase-two approval. Deliberately does not require phase two.
      post 'auth/finance-approvals', auth_steps: [FinancialStepUp::SERVICE_STEP] do
        approval = apr.issue(service_id: current_auth.service.id, scope: params[:scope] || 'transfer')
        {
          approval_token: approval.token,
          header: 'X-Finance-Approval',
          scope: approval.scope,
          expires_at: approval.expires_at.utc.iso8601,
          ttl_seconds: FinancialStepUp::ApprovalAuthority::DEFAULT_TTL
        }
      end

      # Ordinary route: normal service authentication only.
      get 'reports', auth_steps: [FinancialStepUp::SERVICE_STEP] do
        rec.business('GET /reports', current_auth)
        { report: 'quarterly-ledger', auth: current_auth.to_h }
      end

      # Financial route: both declared steps must pass.
      post 'finance/transfers',
           auth_steps: [FinancialStepUp::SERVICE_STEP, FinancialStepUp::APPROVAL_STEP],
           finance_scope: 'transfer' do
        rec.business('POST /finance/transfers', current_auth)
        status 200
        { transfer_id: 'tr_1001', accepted: true, auth: current_auth.to_h }
      end

      # A second, distinct financial route for the cross-route leakage check.
      post 'finance/refunds',
           auth_steps: [FinancialStepUp::SERVICE_STEP, FinancialStepUp::APPROVAL_STEP],
           finance_scope: 'refund' do
        rec.business('POST /finance/refunds', current_auth)
        status 200
        { refund_id: 'rf_2002', accepted: true, auth: current_auth.to_h }
      end
    end

    Rack::Builder.new do
      use FinancialStepUp::RecordingMiddleware, rec
      run api
    end
  end

  def service_env
    { 'HTTP_AUTHORIZATION' => "Bearer #{service_token}" }
  end

  def finance_env(approval_token)
    service_env.merge('HTTP_X_FINANCE_APPROVAL' => approval_token)
  end

  def issue_approval(scope: 'transfer')
    authority.issue(service_id:, scope:)
  end

  describe 'recorded authorization outcomes' do
    it 'runs both steps and gives business the composite auth context' do
      approval = issue_approval
      post_with_json '/finance/transfers', { amount: 250 }, finance_env(approval.token)

      expect(last_response).to be_successful
      body = JSON.parse(last_response.body)
      expect(body['accepted']).to be(true)
      expect(body['auth']['authenticated_service']).to eq(service_id)
      expect(body['auth']['finance_authorized']).to be(true)
      expect(body['auth']['approval']['id']).to eq(approval.id)
      expect(body['auth']['approval']['scope']).to eq('transfer')

      expect(recorder.trace).to eq(
        [
          %w[middleware enter],
          [FinancialStepUp::SERVICE_STEP, 'success'],
          [FinancialStepUp::APPROVAL_STEP, 'granted'],
          %w[business invoked],
          %w[middleware leave]
        ]
      )
      expect(recorder.events.last[:status]).to eq(200)
    end

    it 'answers second-phase failure with a clear re-application result' do
      post_with_json '/finance/transfers', { amount: 250 }, finance_env('finance-approval-forged')

      expect(last_response.status).to eq(403)
      body = JSON.parse(last_response.body)
      expect(body['error']).to eq('finance_approval_required')
      expect(body['reason']).to eq('unknown')
      expect(body['message']).to include('new one')
      expect(body['reapply']).to include(
        'method' => 'POST',
        'path' => '/auth/finance-approvals',
        'header' => 'X-Finance-Approval',
        'scope' => 'transfer',
        'ttl_seconds' => 60
      )
      expect(body['diagnostic']).to eq(
        'phase' => FinancialStepUp::APPROVAL_STEP,
        'authenticated_service' => service_id
      )
      expect(last_response.headers['x-finance-approval-status']).to eq('unknown')
      expect(last_response.headers['x-reapply-approval-url']).to eq('/auth/finance-approvals')

      expect(recorder.trace).to eq(
        [
          %w[middleware enter],
          [FinancialStepUp::SERVICE_STEP, 'success'],
          [FinancialStepUp::APPROVAL_STEP, 'denied'],
          %w[middleware leave]
        ]
      )
      expect(recorder.events.last[:status]).to eq(403)
      expect(recorder.events.none? { |event| event[:actor] == 'business' }).to be(true)
    end

    it 'does not let a failed second phase become financial authorization on another route' do
      post_with_json '/finance/transfers', { amount: 250 }, service_env

      expect(last_response.status).to eq(403)
      expect(last_response.headers['set-cookie']).to be_nil

      post_with_json '/finance/refunds', { amount: 80 }, service_env

      expect(last_response.status).to eq(403)
      refund_challenge = JSON.parse(last_response.body)
      expect(refund_challenge['error']).to eq('finance_approval_required')
      expect(refund_challenge['reason']).to eq('missing')
      expect(refund_challenge['reapply']['scope']).to eq('refund')
      expect(recorder.finance_denials.size).to eq(2)
      expect(recorder.events.none? { |event| event[:actor] == 'business' }).to be(true)

      get '/reports', {}, service_env

      expect(last_response).to be_successful
      report = JSON.parse(last_response.body)
      expect(report['auth']['authenticated_service']).to eq(service_id)
      expect(report['auth']['finance_authorized']).to be(false)
      expect(report['auth']['approval']).to be_nil

      reports_business = recorder.events.find { |event| event[:actor] == 'business' }
      expect(reports_business[:path]).to eq('GET /reports')
      expect(reports_business[:finance_authorized]).to be(false)
    end
  end

  describe 'failure and timeout handling' do
    it 'flags a missing approval and points the caller to re-apply' do
      post_with_json '/finance/transfers', {}, service_env

      expect(last_response.status).to eq(403)
      body = JSON.parse(last_response.body)
      expect(body['reason']).to eq('missing')
      expect(body['reapply']['path']).to eq('/auth/finance-approvals')
    end

    it 'turns an expired approval into an explicit timeout result' do
      approval = issue_approval
      clock.advance(FinancialStepUp::ApprovalAuthority::DEFAULT_TTL + 1)

      post_with_json '/finance/transfers', {}, finance_env(approval.token)

      expect(last_response.status).to eq(403)
      body = JSON.parse(last_response.body)
      expect(body['reason']).to eq('expired')
      expect(body['message']).to include('expired')
      expect(last_response.headers['x-finance-approval-status']).to eq('expired')
    end

    it 'rejects an approval minted for another scope' do
      approval = issue_approval(scope: 'refund')

      post_with_json '/finance/transfers', {}, finance_env(approval.token)

      expect(last_response.status).to eq(403)
      expect(JSON.parse(last_response.body)['reason']).to eq('scope_mismatch')
    end

    it 'rejects requests without valid service credentials before phase two' do
      post_with_json '/finance/transfers', {}, 'HTTP_X_FINANCE_APPROVAL' => 'whatever'

      expect(last_response.status).to eq(401)
      body = JSON.parse(last_response.body)
      expect(body['error']).to eq('service_authentication_failed')
      expect(last_response.headers['www-authenticate']).to include('Bearer')
      expect(recorder.trace.map { |pair| pair[1] }).not_to include('granted', 'denied')
      expect(recorder.events.none? { |event| event[:actor] == FinancialStepUp::APPROVAL_STEP }).to be(true)
    end
  end

  describe 're-application' do
    it 'lets the caller obtain a short-lived approval and retry successfully' do
      post_with_json '/auth/finance-approvals', { scope: 'transfer' }, service_env

      expect(last_response).to be_created
      issued = JSON.parse(last_response.body)
      expect(issued['approval_token']).to start_with('finance-approval-')
      expect(issued['ttl_seconds']).to eq(60)

      post_with_json '/finance/transfers', { amount: 250 }, finance_env(issued['approval_token'])

      expect(last_response).to be_successful
      expect(JSON.parse(last_response.body)['auth']['finance_authorized']).to be(true)
    end

    it 'keeps the issuance endpoint on service authentication only' do
      post_with_json '/auth/finance-approvals', {}, service_env

      expect(last_response).to be_created
      issuance_trace = recorder.trace.first(3)
      expect(issuance_trace).to eq(
        [
          %w[middleware enter],
          [FinancialStepUp::SERVICE_STEP, 'success'],
          %w[middleware leave]
        ]
      )
    end
  end
end
