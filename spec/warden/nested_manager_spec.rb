# encoding: utf-8
# frozen_string_literal: true
require 'json'

RSpec.describe "Warden::Manager behind a second Warden layer" do
  before(:each) do
    @existing_before_failure = Warden::Manager._before_failure.dup
    @existing_on_request = Warden::Manager._on_request.dup

    Warden::Strategies.add(:nested_api_token) do
      def valid?
        true
      end

      def authenticate!
        fail!("invalid token")
      end
    end

    Warden::Manager.before_failure do |env, _opts|
      env['warden.spec.before_failure.count'] = env['warden.spec.before_failure.count'].to_i + 1
    end

    Warden::Manager.on_request do |proxy|
      proxy.env['warden.spec.on_request.count'] = proxy.env['warden.spec.on_request.count'].to_i + 1
    end
  end

  after(:each) do
    Warden::Manager._before_failure.replace(@existing_before_failure)
    Warden::Manager._on_request.replace(@existing_on_request)
  end

  let(:json_failure_app) do
    lambda do |env|
      scope = env['warden.options'] && env['warden.options'][:scope]
      [401, { "Content-Type" => "application/json" },
       [JSON.dump({ "error" => "unauthenticated", "scope" => scope && scope.to_s })]]
    end
  end

  let(:browser_failure_app) do
    lambda do |_env|
      [302, { "Location" => "/login", "Content-Type" => "text/html" },
       ["You are being redirected to /login"]]
    end
  end

  # /owned       -> the app owns its JSON 401 itself (custom_failure!)
  # /intercepted -> the app answers a bare 401 after a failed attempt
  # anything else -> the app throws :warden via authenticate!
  let(:api_app) do
    lambda do |env|
      case env['PATH_INFO']
      when '/owned'
        env['warden'].custom_failure!
        [401, { 'Content-Type' => 'application/json' }, [JSON.dump({ 'error' => 'owned' })]]
      when '/intercepted'
        env['warden'].authenticate(:nested_api_token, :scope => :api)
        [401, { 'Content-Type' => 'application/json' }, [JSON.dump({ 'error' => 'raw' })]]
      else
        env['warden'].authenticate!(:nested_api_token, :scope => :api)
      end
    end
  end

  let(:browser_app) do
    lambda do |env|
      env['warden'].authenticate!(:nested_api_token)
    end
  end

  # Session -> outer Warden (browser failure page)
  #         -> /api/* runs behind a second Warden layer (JSON failure app)
  def build_chain(api_app, browser_app, inner_failure_app)
    json_failure = inner_failure_app
    browser_failure = browser_failure_app

    inner = Rack::Builder.new do
      use Warden::Manager do |config|
        config.failure_app = json_failure if json_failure
      end
      run api_app
    end.to_app

    Rack::Builder.new do
      use Warden::Spec::Helpers::Session
      use Warden::Manager do |config|
        config.failure_app = browser_failure
      end
      run Rack::URLMap.new("/api" => inner, "/" => browser_app)
    end.to_app
  end

  def before_failure_count(env)
    env['warden.spec.before_failure.count'].to_i
  end

  describe "internal JSON failure" do
    it "is owned by the second Warden layer and keeps the attempted scope" do
      env = env_with_params("/api/widgets")
      result = build_chain(api_app, browser_app, json_failure_app).call(env)

      expect(result[0]).to eq(401)
      expect(result[1]["Content-Type"]).to eq("application/json")
      expect(JSON.parse(result[2].first)).to eq("error" => "unauthenticated", "scope" => "api")
      expect(env['warden.options'][:scope]).to eq(:api)
      expect(env['warden.options'][:attempted_path]).to eq("/api/widgets")
      expect(before_failure_count(env)).to eq(1)
    end

    it "keeps the attempted scope when intercepting a bare 401 from the app" do
      env = env_with_params("/api/intercepted")
      result = build_chain(api_app, browser_app, json_failure_app).call(env)

      expect(result[0]).to eq(401)
      expect(result[1]["Content-Type"]).to eq("application/json")
      expect(JSON.parse(result[2].first)).to eq("error" => "unauthenticated", "scope" => "api")
      expect(env['warden.options'][:scope]).to eq(:api)
      expect(before_failure_count(env)).to eq(1)
    end
  end

  describe "browser redirect" do
    it "still renders the existing failure page for browser routes" do
      env = env_with_params("/admin")
      result = build_chain(api_app, browser_app, json_failure_app).call(env)

      expect(result[0]).to eq(302)
      expect(result[1]["Location"]).to eq("/login")
      expect(before_failure_count(env)).to eq(1)
    end
  end

  describe "response passing through the second Warden layer" do
    it "passes an app-owned JSON 401 through both layers untouched" do
      env = env_with_params("/api/owned")
      result = build_chain(api_app, browser_app, json_failure_app).call(env)

      expect(result[0]).to eq(401)
      expect(result[1]["Content-Type"]).to eq("application/json")
      expect(JSON.parse(result[2].first)).to eq("error" => "owned")
      expect(env['warden.options']).to be_nil
      expect(before_failure_count(env)).to eq(0)
    end

    it "runs the on_request callbacks only once across both layers" do
      env = env_with_params("/api/widgets")
      build_chain(api_app, browser_app, json_failure_app).call(env)

      expect(env['warden.spec.on_request.count']).to eq(1)
    end

    it "defers to the upstream layer when the second layer has no failure app" do
      env = env_with_params("/api/widgets")
      result = build_chain(api_app, browser_app, nil).call(env)

      expect(result[0]).to eq(302)
      expect(result[1]["Location"]).to eq("/login")
      expect(before_failure_count(env)).to eq(1)
    end
  end
end
