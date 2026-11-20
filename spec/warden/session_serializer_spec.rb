# encoding: utf-8
# frozen_string_literal: true
RSpec.describe Warden::SessionSerializer do
  before(:each) do
    @env = env_with_params
    @env['rack.session'] ||= {}
    @session = Warden::SessionSerializer.new(@env)
  end

  it "should store data for the default scope" do
    @session.store("user", :default)
    expect(@env['rack.session']).to eq({ "warden.user.default.key"=>"user" })
  end

  it "should check if a data is stored or not" do
    expect(@session).not_to be_stored(:default)
    @session.store("user", :default)
    expect(@session).to be_stored(:default)
  end

  it "should load an user from store" do
    expect(@session.fetch(:default)).to be_nil
    @session.store("user", :default)
    expect(@session.fetch(:default)).to eq("user")
  end

  it "should store data based on the scope" do
    @session.store("user", :default)
    expect(@session.fetch(:default)).to eq("user")
    expect(@session.fetch(:another)).to be_nil
  end

  it "should delete data from store" do
    @session.store("user", :default)
    expect(@session.fetch(:default)).to eq("user")
    @session.delete(:default)
    expect(@session.fetch(:default)).to be_nil
  end

  it "should delete information from store if user cannot be retrieved" do
    @session.store("user", :default)
    expect(@env['rack.session']).to have_key("warden.user.default.key")
    allow(@session).to receive(:deserialize).and_return(nil)
    @session.fetch(:default)
    expect(@env['rack.session']).not_to have_key("warden.user.default.key")
  end

  it "should support a nil session store" do
    @env['rack.session'] = nil
    expect(@session.fetch(:default)).to be_nil
  end

  describe "deserialization signals" do
    before(:each) do
      @session.store("user", :default)
      @key = "warden.user.default.key"
    end

    it "keeps the stored identity when the hook raises a retryable error" do
      error = Warden::RetryableDeserializationError.new("directory unavailable")
      allow(@session).to receive(:deserialize).and_raise(error)

      expect(@session.fetch(:default)).to be_nil
      expect(@env['rack.session']).to have_key(@key)
      expect(@session).to be_retryable_fetch_error(:default)
      expect(@session.retryable_fetch_error(:default)).to equal(error)
    end

    it "does not report a retryable error for scopes that did not fail" do
      allow(@session).to receive(:deserialize).and_raise(Warden::RetryableDeserializationError)
      @session.fetch(:default)

      expect(@session).not_to be_retryable_fetch_error(:admin)
      expect(@session.retryable_fetch_error(:admin)).to be_nil
    end

    it "starts without any recorded retryable error" do
      expect(@session).not_to be_retryable_fetch_error(:default)
      expect(@session.retryable_fetch_error(:default)).to be_nil
    end

    it "clears the retryable state once a later fetch succeeds" do
      attempts = 0
      allow(@session).to receive(:deserialize) do
        attempts += 1
        raise Warden::RetryableDeserializationError if attempts == 1
        "user"
      end

      @session.fetch(:default)
      expect(@session).to be_retryable_fetch_error(:default)

      expect(@session.fetch(:default)).to eq("user")
      expect(@session).not_to be_retryable_fetch_error(:default)
      expect(@env['rack.session']).to have_key(@key)
    end

    it "deletes the stored identity when the hook raises an invalid identity error" do
      allow(@session).to receive(:deserialize).and_raise(Warden::InvalidIdentityError)

      expect(@session.fetch(:default)).to be_nil
      expect(@env['rack.session']).not_to have_key(@key)
      expect(@session).not_to be_retryable_fetch_error(:default)
    end

    it "handles the signals through a scoped deserialize hook" do
      admin_error = Warden::RetryableDeserializationError.new("timeout")
      Warden::Manager.serialize_from_session(:admin) { |_key| raise admin_error }
      admin = Warden::SessionSerializer.new(@env)
      admin.store("admin-user", :admin)

      expect(admin.fetch(:admin)).to be_nil
      expect(@env['rack.session']).to have_key(admin.key_for(:admin))
      expect(admin.retryable_fetch_error(:admin)).to equal(admin_error)
    ensure
      Warden::SessionSerializer.send(:remove_method, :admin_deserialize)
    end

    it "lets unexpected errors propagate without touching the stored identity" do
      allow(@session).to receive(:deserialize).and_raise(RuntimeError, "boom")

      expect { @session.fetch(:default) }.to raise_error(RuntimeError, "boom")
      expect(@env['rack.session']).to have_key(@key)
      expect(@session).not_to be_retryable_fetch_error(:default)
    end

    it "still deletes the stored identity when the hook returns nil" do
      allow(@session).to receive(:deserialize).and_return(nil)

      expect(@session.fetch(:default)).to be_nil
      expect(@env['rack.session']).not_to have_key(@key)
      expect(@session).not_to be_retryable_fetch_error(:default)
    end
  end
end
