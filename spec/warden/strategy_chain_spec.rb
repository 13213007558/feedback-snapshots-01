# encoding: utf-8
# frozen_string_literal: true

RSpec.describe "Warden strategy chain semantics" do
  before(:all) do
    load_strategies
  end

  after(:each) do
    Warden::Manager._after_set_user.clear
    Warden::Manager._after_failed_fetch.clear
    Warden::Manager._before_failure.clear
  end

  def chain_entries(env)
    env['warden.spec.chain'] || []
  end

  describe "strategy ordering within one scope" do
    it "runs a skip, a soft deny and a valid user in the configured order" do
      app = lambda do |env|
        user = env['warden'].authenticate(:chain_skip, :chain_soft_deny, :chain_valid_user)
        expect(user).to eq(WardenChainSpec::USER)
        expect(chain_entries(env)).to eq([:chain_skip, :chain_soft_deny, :chain_valid_user])
        valid_response
      end
      setup_rack(app).call(env_with_params)
    end

    it "does not run strategies listed after a successful one" do
      app = lambda do |env|
        env['warden'].authenticate(:chain_valid_user, :chain_skip, :chain_soft_deny)
        expect(env['warden'].user).to eq(WardenChainSpec::USER)
        expect(chain_entries(env)).to eq([:chain_valid_user])
        valid_response
      end
      setup_rack(app).call(env_with_params)
    end

    it "lets the chain continue after a soft (non-halting) deny" do
      app = lambda do |env|
        env['warden'].authenticate(:chain_soft_deny, :chain_valid_user)
        expect(env['warden'].user).to eq(WardenChainSpec::USER)
        expect(env['warden'].winning_strategy).to be_a(Warden::Strategies[:chain_valid_user])
        valid_response
      end
      setup_rack(app).call(env_with_params)
    end

    it "stops the chain after a hard (halting) deny" do
      app = lambda do |env|
        user = env['warden'].authenticate(:chain_skip, :chain_hard_deny, :chain_valid_user)
        expect(user).to be_nil
        expect(env['warden']).not_to be_authenticated
        expect(chain_entries(env)).to eq([:chain_skip, :chain_hard_deny])
        expect(env['warden'].message).to eq("hard deny")
        expect(env['warden'].winning_strategy).to be_a(Warden::Strategies[:chain_hard_deny])
        valid_response
      end
      setup_rack(app).call(env_with_params)
    end

    it "never runs later strategies when the first one halts" do
      app = lambda do |env|
        env['warden'].authenticate(:chain_hard_deny, :chain_skip, :chain_valid_user)
        expect(chain_entries(env)).to eq([:chain_hard_deny])
        valid_response
      end
      setup_rack(app).call(env_with_params)
    end

    it "exposes the last soft failure message when no strategy succeeds" do
      app = lambda do |env|
        user = env['warden'].authenticate(:chain_skip, :chain_soft_deny)
        expect(user).to be_nil
        expect(env['warden'].message).to eq("soft deny")
        expect(chain_entries(env)).to eq([:chain_skip, :chain_soft_deny])
        valid_response
      end
      setup_rack(app).call(env_with_params)
    end

    it "keeps the chain of one scope isolated from other scopes" do
      app = lambda do |env|
        env['warden'].authenticate(:chain_valid_user, :scope => :chain_admin)
        expect(env['warden'].user(:chain_admin)).to eq(WardenChainSpec::USER)
        expect(env['warden'].user).to be_nil
        expect(env['rack.session']['warden.user.chain_admin.key']).to eq(WardenChainSpec::USER)
        expect(env['rack.session']).not_to have_key('warden.user.default.key')
        valid_response
      end
      setup_rack(app).call(env_with_params)
    end
  end

  describe "session" do
    it "stores the user in the session when the chain succeeds" do
      env = env_with_params
      app = lambda do |e|
        e['warden'].authenticate(:chain_skip, :chain_valid_user)
        valid_response
      end
      setup_rack(app).call(env)
      expect(env['rack.session']['warden.user.default.key']).to eq(WardenChainSpec::USER)
    end

    it "stores nothing in the session when the chain fails" do
      env = env_with_params
      app = lambda do |e|
        e['warden'].authenticate(:chain_skip, :chain_soft_deny)
        valid_response
      end
      setup_rack(app).call(env)
      expect(env['rack.session']).not_to have_key('warden.user.default.key')
    end

    it "serves the next request from the session without running strategies" do
      events = []
      Warden::Manager.after_fetch { |user, _auth, _opts| events << [:after_fetch, user] }

      app = lambda do |env|
        env['warden'].authenticate(:chain_valid_user)
        valid_response
      end
      rack = setup_rack(app)

      first_env = env_with_params
      rack.call(first_env)
      expect(chain_entries(first_env)).to eq([:chain_valid_user])

      second_env = env_with_params("/", {}, 'rack.session' => first_env['rack.session'])
      rack.call(second_env)
      expect(second_env['warden'].user).to eq(WardenChainSpec::USER)
      expect(chain_entries(second_env)).to eq([])
      expect(events).to eq([[:after_fetch, WardenChainSpec::USER]])
    end
  end

  describe "repeated queries on the same request" do
    it "runs each business method only once for repeated authenticate calls" do
      app = lambda do |env|
        2.times { env['warden'].authenticate(:chain_skip, :chain_soft_deny, :chain_valid_user) }
        env['warden'].authenticate?(:chain_skip, :chain_soft_deny, :chain_valid_user)
        expect(chain_entries(env)).to eq([:chain_skip, :chain_soft_deny, :chain_valid_user])
        valid_response
      end
      setup_rack(app).call(env_with_params)
    end

    it "does not re-enter a failing strategy on repeated authenticate calls" do
      app = lambda do |env|
        2.times { env['warden'].authenticate(:chain_skip, :chain_soft_deny) }
        expect(chain_entries(env)).to eq([:chain_skip, :chain_soft_deny])
        valid_response
      end
      setup_rack(app).call(env_with_params)
    end

    it "returns the identical user object for repeated user queries" do
      app = lambda do |env|
        env['warden'].authenticate(:chain_valid_user)
        first = env['warden'].user
        second = env['warden'].user
        expect(second).to be(first)
        expect(env['warden']).to be_authenticated
        expect(chain_entries(env)).to eq([:chain_valid_user])
        valid_response
      end
      setup_rack(app).call(env_with_params)
    end
  end

  describe "callback ordering" do
    before(:each) do
      Warden::Manager._after_set_user.clear
      Warden::Manager._after_failed_fetch.clear
      Warden::Manager._before_failure.clear
    end

    after(:each) do
      Warden::Manager._after_set_user.clear
      Warden::Manager._after_failed_fetch.clear
      Warden::Manager._before_failure.clear
    end

    it "runs fetch, set_user and authentication callbacks in order on success" do
      events = []
      Warden::Manager.after_failed_fetch { |*_args| events << :after_failed_fetch }
      Warden::Manager.after_set_user { |_u, _a, opts| events << [:after_set_user, opts[:event]] }
      Warden::Manager.after_authentication { |*_args| events << :after_authentication }
      Warden::Manager.before_failure { |*_args| events << :before_failure }

      app = lambda do |env|
        env['warden'].authenticate(:chain_skip, :chain_valid_user)
        valid_response
      end
      setup_rack(app).call(env_with_params)

      expect(events).to eq([
        :after_failed_fetch,
        [:after_set_user, :authentication],
        :after_authentication
      ])
    end

    it "runs before_failure after a halting deny is enforced with authenticate!" do
      events = []
      Warden::Manager.after_failed_fetch { |*_args| events << :after_failed_fetch }
      Warden::Manager.before_failure { |*_args| events << :before_failure }

      app = lambda do |env|
        env['warden'].authenticate!(:chain_soft_deny)
        valid_response
      end
      response = setup_rack(app).call(env_with_params)

      expect(response.first).to eq(401)
      expect(events).to eq([:after_failed_fetch, :before_failure])
    end
  end
end
