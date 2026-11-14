# frozen_string_literal: true

class FixtureAuthenticator
  extend Rack::Assembly::Declarative
  provides_request_fact :identity_verified

  def initialize(app)
    @app = app
  end

  def call(env)
    @app.call(env)
  end
end

class FixtureProtected
  extend Rack::Assembly::Declarative
  requires_request_fact :identity_verified

  def call(_env)
    [200, { 'content-type' => 'text/plain' }, ['protected']]
  end
end

verify_assembly!

map '/health' do
  run ->(_env) { [200, { 'content-type' => 'text/plain' }, ['ok']] }
end

map '/admin' do
  run FixtureProtected.new
end

map '/secure' do
  use FixtureAuthenticator
  run FixtureProtected.new
end
