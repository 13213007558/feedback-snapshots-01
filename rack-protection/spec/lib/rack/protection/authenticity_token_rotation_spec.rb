# frozen_string_literal: true

# Demonstrates CSRF root token rotation with a controlled clock:
# already-rendered forms get a bounded compatibility window, sensitive
# actions only accept the current generation, per-form tokens stay bound
# to their path/method, and a login identity change invalidates all
# previous generations immediately.
RSpec.describe Rack::Protection::AuthenticityToken, 'token rotation' do
  GRACE_PERIOD = 60
  MAX_PREVIOUS = 1

  let(:clock) { { now: 1_000 } }
  let(:clock_proc) { -> { clock[:now] } }
  let(:policy) do
    ->(env) { env['PATH_INFO'] == '/transfer' ? :strict : :grace }
  end
  let(:middleware_options) do
    {
      rotation_grace_period: GRACE_PERIOD,
      max_previous_generations: MAX_PREVIOUS,
      rotation_policy: policy,
      identity: :user_id,
      clock: clock_proc
    }
  end
  let(:protector) { described_class.new(nil, **middleware_options) }
  let(:session) { { user_id: 1 } }

  def rotate!
    protector.rotate!(session)
  end

  def advance(seconds)
    clock[:now] += seconds
  end

  before do
    options = middleware_options
    mock_app do
      use(Rack::Config) { |e| e['rack.session'] ||= {} }
      use Rack::Protection::AuthenticityToken, **options
      run DummyApp
    end
  end

  def submit(path, token)
    post(path, { 'authenticity_token' => token }, 'rack.session' => session)
    last_response
  end

  it 'accepts an already-open normal form within the grace window' do
    old_masked = described_class.token(session)
    old_raw = session[:csrf]
    rotate!

    advance(30)
    expect(submit('/profile', old_masked)).to be_ok
    expect(submit('/profile', old_raw)).to be_ok
  end

  it 'rejects old generations on strict (sensitive) actions' do
    old_masked = described_class.token(session)
    rotate!
    new_masked = described_class.token(session)

    advance(30)
    expect(submit('/transfer', old_masked)).not_to be_ok
    expect(submit('/transfer', new_masked)).to be_ok
    expect(submit('/profile', old_masked)).to be_ok
  end

  it 'keeps old per-form tokens bound to their path and method' do
    old_per_form = described_class.token(session, path: '/foo')
    rotate!

    advance(30)
    expect(submit('/foo', old_per_form)).to be_ok
    expect(submit('/bar', old_per_form)).not_to be_ok
  end

  it 'does not extend the window when old forms are submitted' do
    old_masked = described_class.token(session)
    rotate!

    advance(30)
    expect(submit('/profile', old_masked)).to be_ok

    advance(GRACE_PERIOD) # now past rotated_at + grace, despite the submit
    expect(submit('/profile', old_masked)).not_to be_ok
  end

  it 'drops the oldest generation after a second rotation' do
    first_masked = described_class.token(session)
    rotate!
    second_masked = described_class.token(session)
    rotate!

    advance(10)
    expect(submit('/profile', second_masked)).to be_ok
    expect(submit('/profile', first_masked)).not_to be_ok
  end

  it 'invalidates all previous generations when the login identity changes' do
    old_masked = described_class.token(session)
    rotate!

    session[:user_id] = 2 # re-authenticated as someone else
    advance(10)
    expect(submit('/profile', old_masked)).not_to be_ok
  end

  it 'prunes expired generations on rotation' do
    described_class.token(session)
    rotate!

    advance(GRACE_PERIOD + 1)
    rotate!

    generations = session['csrf.previous']
    expect(generations.length).to be <= MAX_PREVIOUS
    expect(generations).to all(
      satisfy { |g| clock[:now] - g['rotated_at'] < GRACE_PERIOD }
    )
  end
end
