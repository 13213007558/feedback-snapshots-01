# encoding: utf-8
# frozen_string_literal: true
RSpec.describe "on_failed_authentication audit hook" do
  before(:all) do
    load_strategies
  end

  let(:audited_events) { [] }

  let(:message_rendering_failure_app) do
    lambda do |env|
      [401, { "Content-Type" => "text/plain" }, [env["warden.options"][:message].to_s]]
    end
  end

  before(:each) do
    Warden::Manager._on_failed_authentication.clear
    Warden::Manager.on_failed_authentication { |event| audited_events << event }
  end

  after(:each) do
    Warden::Manager._on_failed_authentication.clear
  end

  def call_app(app, path = "/", params = {})
    env = env_with_params(path, params)
    status, headers, body = setup_rack(app, :failure_app => message_rendering_failure_app).call(env)
    [status, headers, body, env]
  end

  it "allows registering failure audit hooks" do
    Warden::Manager.on_failed_authentication { |event| event }
    expect(Warden::Manager._on_failed_authentication.length).to eq(2)
  end

  it "requires a block" do
    expect { Warden::Manager.on_failed_authentication }.to raise_error(Warden::BlockNotGiven)
  end

  it "records only the failure category and scope for failures from different strategies" do
    badge_app = lambda do |env|
      env['warden'].authenticate!(:audit_badge, :scope => :scheduling)
      valid_response
    end
    otp_app = lambda do |env|
      env['warden'].authenticate!(:audit_otp)
      valid_response
    end

    badge_status, _h, badge_body, = call_app(badge_app, "/badge", "password" => "s3cret-input")
    otp_status, _h, otp_body, = call_app(otp_app, "/otp", "otp" => "000000")

    # the audit collector saw exactly two events, carrying only category and scope
    expect(audited_events.map(&:to_h)).to eq([
      { :category => :failure, :scope => :scheduling },
      { :category => :failure, :scope => :default }
    ])
    audited_events.each do |event|
      expect(event).to be_a(Warden::FailedAuthenticationEvent)
      expect(event).not_to respond_to(:message)
      expect(event).not_to respond_to(:env)
      expect(event).not_to respond_to(:params)
      expect(event.inspect).not_to include("rejected", "expired", "s3cret-input")
    end

    # the failure application still receives each strategy's message as usual
    expect(badge_status).to eq(401)
    expect(badge_body.join).to eq("Badge was rejected")
    expect(otp_status).to eq(401)
    expect(otp_body.join).to eq("OTP has expired")
  end

  it "does not record anything for a successful authentication" do
    ok_app = lambda do |env|
      env['warden'].authenticate!(:pass)
      valid_response
    end

    status, _h, body, = call_app(ok_app)

    expect(status).to eq(200)
    expect(body.join).to eq("OK")
    expect(audited_events).to be_empty
  end

  it "can be filtered by scope" do
    scoped_events = []
    Warden::Manager.on_failed_authentication(:scope => :scheduling) { |event| scoped_events << event }

    badge_app = lambda do |env|
      env['warden'].authenticate!(:audit_badge, :scope => :scheduling)
      valid_response
    end
    otp_app = lambda do |env|
      env['warden'].authenticate!(:audit_otp)
      valid_response
    end

    call_app(badge_app)
    call_app(otp_app)

    expect(scoped_events.map(&:to_h)).to eq([{ :category => :failure, :scope => :scheduling }])
    expect(audited_events.length).to eq(2)
  end
end
