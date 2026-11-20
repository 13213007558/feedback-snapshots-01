# encoding: utf-8
# frozen_string_literal: true

RSpec.describe "directory backed serialization" do
  # Errors raised by the (fake) directory service itself.
  class DirectoryTemporarilyUnavailable < StandardError; end
  class AccountDeactivated < StandardError; end

  # A stand-in for an external directory service. It can be told to fail
  # transiently or to report an account as deactivated, and it records every
  # lookup so specs can assert how often Warden queried it.
  class FakeDirectory
    attr_reader :lookups

    def initialize
      @users = {}
      @unavailable = false
      @deactivated = {}
      @lookups = 0
    end

    def add_user(id, user)
      @users[id] = user
    end

    def make_unavailable!
      @unavailable = true
    end

    def restore!
      @unavailable = false
    end

    def deactivate!(id)
      @deactivated[id] = true
    end

    def find(id)
      @lookups += 1
      raise DirectoryTemporarilyUnavailable, "directory is down" if @unavailable
      raise AccountDeactivated, id if @deactivated[id]
      @users.fetch(id)
    end
  end

  # The application maps the two directory outcomes onto the two Warden
  # signals, and otherwise hands back the user object.
  def build_app(directory)
    login_user = directory_user
    Rack::Builder.new do
      use Warden::Manager do |config|
        config.default_strategies :pass
        config.failure_app = lambda { |_env| [401, { "Content-Type" => "text/plain" }, ["unauthenticated"]] }
      end

      Warden::Manager.serialize_into_session { |user| user[:id] }
      Warden::Manager.serialize_from_session do |id|
        begin
          directory.find(id)
        rescue DirectoryTemporarilyUnavailable => error
          raise Warden::RetryableDeserializationError, error.message
        rescue AccountDeactivated
          raise Warden::InvalidIdentityError, "account #{id} was deactivated"
        end
      end
      # A second scope whose record must never be touched by the default scope.
      Warden::Manager.serialize_into_session(:admin) { |user| user }
      Warden::Manager.serialize_from_session(:admin) { |stored| stored }

      run lambda { |env|
        warden = env["warden"]
        case env["PATH_INFO"]
        when "/login"
          warden.set_user(login_user)
          [200, {}, ["logged in"]]
        when "/business"
          if warden.authenticated?
            [200, {}, ["business for #{warden.user[:name]}"]]
          elsif warden.deserialization_retryable?
            [503, {}, ["retry later: #{warden.deserialization_error.message}"]]
          else
            [401, {}, ["unauthenticated"]]
          end
        else
          [404, {}, ["not found"]]
        end
      }
    end
  end

  let(:directory_user) { { id: 42, name: "Alice" } }
  let(:default_key) { "warden.user.default.key" }
  let(:admin_key) { "warden.user.admin.key" }

  before(:each) do
    @directory = FakeDirectory.new
    @directory.add_user(42, directory_user)
    @app = build_app(@directory)
    # One session hash shared across requests, like a real session store.
    @session = {}
  end

  after(:each) do
    Warden::Manager.serialize_from_session { |k| k }
    Warden::Manager.serialize_into_session { |u| u }
    [:admin_serialize, :admin_deserialize].each do |method|
      Warden::SessionSerializer.send(:remove_method, method)
    rescue StandardError
      nil
    end
  end

  def request(path)
    env = env_with_params(path)
    env["rack.session"] = @session
    @app.call(env)
  end

  def login!
    request("/login")
    expect(@session[default_key]).to eq(42)
  end

  describe "a transient directory failure" do
    it "keeps the identity, blocks business, and retries the directory on the next request" do
      login!
      lookups_after_login = @directory.lookups

      @directory.make_unavailable!

      failing = request("/business")
      expect(failing.first).to eq(503)
      expect(failing.last).to eq(["retry later: directory is down"])
      # The stored identity survives the temporary failure.
      expect(@session[default_key]).to eq(42)
      # The directory was consulted once for this request.
      expect(@directory.lookups).to eq(lookups_after_login + 1)

      @directory.restore!

      recovered = request("/business")
      expect(recovered.first).to eq(200)
      expect(recovered.last).to eq(["business for Alice"])
      # Recovery still consults the directory because the identity was retained.
      expect(@directory.lookups).to eq(lookups_after_login + 2)
      expect(@session[default_key]).to eq(42)
    end

    it "does not fire after_failed_fetch while the failure is retryable" do
      login!
      calls = 0
      Warden::Manager.after_failed_fetch { calls += 1 }

      @directory.make_unavailable!
      request("/business")
      expect(calls).to eq(0)

      @directory.restore!
      request("/business")
      expect(calls).to eq(0)
    ensure
      Warden::Manager._after_failed_fetch.clear
    end
  end

  describe "a deactivated account" do
    it "deletes the saved identity and does not consult the directory again" do
      login!
      # Seed another scope so we can prove cleanup is scope specific.
      @session[admin_key] = { id: 7, name: "Admin" }

      @directory.deactivate!(42)

      deactivated = request("/business")
      expect(deactivated.first).to eq(401)
      expect(deactivated.last).to eq(["unauthenticated"])
      lookups_after_deactivation = @directory.lookups

      # Only the default scope's record is removed.
      expect(@session).not_to have_key(default_key)
      expect(@session[admin_key]).to eq({ id: 7, name: "Admin" })

      follow_up = request("/business")
      expect(follow_up.first).to eq(401)
      # With no stored identity there is nothing to deserialize, so the
      # directory is not queried again.
      expect(@directory.lookups).to eq(lookups_after_deactivation)
      expect(@session).not_to have_key(default_key)
    end

    it "fires after_failed_fetch because the sign out is permanent" do
      login!
      calls = 0
      Warden::Manager.after_failed_fetch { calls += 1 }

      @directory.deactivate!(42)
      request("/business")
      expect(calls).to eq(1)
    ensure
      Warden::Manager._after_failed_fetch.clear
    end
  end

  describe "the normal flow and the legacy hook contract" do
    it "lets a healthy request reach the business logic" do
      login!
      response = request("/business")
      expect(response.first).to eq(200)
      expect(response.last).to eq(["business for Alice"])
    end

    it "treats a hook returning nil as a permanent failure and deletes the record" do
      login!
      Warden::Manager.serialize_from_session { |_id| nil }

      response = request("/business")
      expect(response.first).to eq(401)
      expect(@session).not_to have_key(default_key)
    end

    it "lets unrelated errors propagate instead of swallowing them" do
      login!
      Warden::Manager.serialize_from_session { |_id| raise RuntimeError, "boom" }
      expect { request("/business") }.to raise_error(RuntimeError, "boom")
      expect(@session[default_key]).to eq(42)
    end
  end
end
