require 'spec_helper'
require 'rack/test'
require 'support/two_factor_test_app'

describe ::Devise::TwoFactorAuthentication::ControllerHelpers do
  include Rack::Test::Methods

  def app
    TwoFactorTestApp.boot
  end

  before(:each) { TwoFactorTestApp.reset! }

  let(:controller_class) do
    Class.new do
      include Devise::TwoFactorAuthentication::ControllerHelpers

      attr_accessor :request

      def self.helper_method(*_names); end

      def two_factor_scope
        :user
      end

      def initialize(env)
        @request = Struct.new(:env).new(env)
      end
    end
  end

  def controller_for(session)
    # Issue a fresh request so the Warden proxy re-fetches the account from
    # the session instead of reusing a cached record from an earlier request.
    session.get '/status'
    controller_class.new(session.last_request.env)
  end

  it 'exposes the real session level through helper methods' do
    user = TwoFactorTestApp.create_user(email: 'helper@example.com', two_factor: false)
    session = Rack::Test::Session.new(app)
    session.post '/sign_in', { user: { email: user.email, password: 'secret' } }
    user.update!(otp_required_for_login: true)

    controller = controller_for(session)
    expect(controller.two_factor_read_only?).to be true
    expect(controller.two_factor_restricted?).to be true
    expect(controller.two_factor_verification_prompt).to eq(:verify_two_factor)
    expect(controller.sensitive_request_submittable?).to be false
  end

  it 'allows confirmation through the helper and reports eligibility' do
    user = TwoFactorTestApp.create_user(email: 'helper-confirm@example.com', two_factor: false)
    session = Rack::Test::Session.new(app)
    session.post '/sign_in', { user: { email: user.email, password: 'secret' } }
    user.update!(otp_required_for_login: true)

    controller = controller_for(session)
    accepted = controller.confirm_two_factor_authentication!(TwoFactorTestApp.otp_for(user.reload))
    expect(accepted).to be true
    expect(controller.two_factor_read_only?).to be false
    expect(controller.sensitive_request_submittable?).to be true
  end
end
