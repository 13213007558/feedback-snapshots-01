# frozen_string_literal: true

require_relative 'helper'

separate_testing do
  require_relative '../lib/rack/builder'
  require_relative '../lib/rack/assembly'
  require_relative '../lib/rack/urlmap'
  require_relative '../lib/rack/mock_request'
end

module AssemblySpec
  IDENTITY = :identity_verified
  BODY_SIGNED = :body_signature_verified

  class Authenticator
    extend Rack::Assembly::Declarative
    provides_request_fact :identity_verified

    def initialize(app, **)
      @app = app
    end

    def call(env)
      @app.call(env)
    end
  end

  class ResponseSigner
    extend Rack::Assembly::Declarative
    provides_response_fact :body_signature_verified

    def initialize(app, **)
      @app = app
    end

    def call(env)
      @app.call(env)
    end
  end

  class BodyConsumer
    extend Rack::Assembly::Declarative
    requires_request_fact :identity_verified

    def initialize(app, **)
      @app = app
    end

    def call(env)
      @app.call(env)
    end
  end

  # The name hints at authentication but it declares nothing, so the assembly
  # check must treat it as unknown rather than trust it.
  class AuthLookingMiddleware
    def initialize(app, **)
      @app = app
    end

    def call(env)
      @app.call(env)
    end
  end

  class ProtectedEndpoint
    extend Rack::Assembly::Declarative
    requires_request_fact :identity_verified

    def call(_env)
      [200, { 'content-type' => 'text/plain' }, ['protected']]
    end
  end

  OK_APP = ->(_env) { [200, { 'content-type' => 'text/plain' }, ['OK']] }

  class EndpointThatCounts
    def self.calls
      @calls ||= 0
    end

    def call(_env)
      self.class.calls += 1
      [200, { 'content-type' => 'text/plain' }, ['OK']]
    end
  end
end

describe Rack::Assembly do
  it "exposes a declaration built from the declarative helpers" do
    declaration = AssemblySpec::Authenticator.assembly_declaration

    declaration.must_be_kind_of Rack::Assembly::Declaration
    declaration.request_provides.must_equal [:identity_verified]
    declaration.request_requires.must_equal []
    declaration.response_provides.must_equal []
  end

  it "returns nil for a component without a declaration" do
    Rack::Assembly.declaration_of(AssemblySpec::AuthLookingMiddleware).must_be_nil
    Rack::Assembly.declaration_of(AssemblySpec::OK_APP).must_be_nil
  end

  it "joins mount segments into a readable path" do
    Rack::Assembly.join_mount_path('/', '/api').must_equal '/api'
    Rack::Assembly.join_mount_path('/api', '/admin').must_equal '/api/admin'
    Rack::Assembly.join_mount_path('/', '/').must_equal '/'
  end
end

describe "Rack::Builder assembly verification" do
  def build(&block)
    Rack::Builder.new(verify_assembly: true, &block).to_app
  end

  it "is opt-in and stays silent when not enabled" do
    app = Rack::Builder.new do
      use AssemblySpec::BodyConsumer
      run AssemblySpec::OK_APP
    end.to_app

    app.must_respond_to :call
  end

  it "can be enabled with the verify_assembly! DSL method" do
    app = Rack::Builder.new do
      verify_assembly!
      use AssemblySpec::Authenticator
      requires_request_fact :identity_verified
      run AssemblySpec::OK_APP
    end.to_app

    app.must_respond_to :call
  end

  it "builds a correctly nested configuration without executing an endpoint" do
    before = AssemblySpec::EndpointThatCounts.calls

    app = build do
      use AssemblySpec::Authenticator
      map '/public' do
        run AssemblySpec::OK_APP
      end
      map '/admin' do
        use AssemblySpec::BodyConsumer
        run AssemblySpec::ProtectedEndpoint.new
      end
      run AssemblySpec::EndpointThatCounts.new
    end

    app.must_respond_to :call
    AssemblySpec::EndpointThatCounts.calls.must_equal before
  end

  it "reports the exact mounted branch that is missing authentication" do
    error = proc do
      build do
        map '/public' do
          run AssemblySpec::OK_APP
        end
        map '/admin' do
          use AssemblySpec::BodyConsumer
          run AssemblySpec::OK_APP
        end
      end
    end.must_raise Rack::Assembly::VerificationError

    error.mount_path.must_equal '/admin'
    error.fact.must_equal :identity_verified
    error.message.must_include '/admin'
    error.message.must_include ':identity_verified'
  end

  it "reports the full path for a deeply nested unprotected branch" do
    error = proc do
      build do
        map '/api' do
          map '/admin' do
            use AssemblySpec::BodyConsumer
            run AssemblySpec::OK_APP
          end
          run AssemblySpec::OK_APP
        end
      end
    end.must_raise Rack::Assembly::VerificationError

    error.mount_path.must_equal '/api/admin'
  end

  it "accepts outer request facts for every mapped branch" do
    app = build do
      use AssemblySpec::Authenticator
      map '/api' do
        map '/admin' do
          use AssemblySpec::BodyConsumer
          run AssemblySpec::OK_APP
        end
        run AssemblySpec::OK_APP
      end
    end

    app.must_respond_to :call
  end

  it "flags middleware ordered after the component that needs its fact" do
    error = proc do
      build do
        use AssemblySpec::BodyConsumer
        use AssemblySpec::Authenticator
        run AssemblySpec::OK_APP
      end
    end.must_raise Rack::Assembly::VerificationError

    error.fact.must_equal :identity_verified
    error.mount_path.must_equal '/'
  end

  it "does not let a response-phase fact satisfy a request-phase precondition" do
    error = proc do
      build do
        use AssemblySpec::ResponseSigner
        requires_request_fact :body_signature_verified
        run AssemblySpec::OK_APP
      end
    end.must_raise Rack::Assembly::VerificationError

    error.fact.must_equal :body_signature_verified
    error.message.must_include 'response phase'
  end

  it "does not trust an undeclared middleware based on its name" do
    error = proc do
      build do
        use AssemblySpec::AuthLookingMiddleware
        requires_request_fact :identity_verified
        run AssemblySpec::OK_APP
      end
    end.must_raise Rack::Assembly::VerificationError

    error.fact.must_equal :identity_verified
  end

  it "honours a declaration made directly on the endpoint object" do
    error = proc do
      build do
        run AssemblySpec::ProtectedEndpoint.new
      end
    end.must_raise Rack::Assembly::VerificationError

    error.mount_path.must_equal '/'

    app = build do
      use AssemblySpec::Authenticator
      run AssemblySpec::ProtectedEndpoint.new
    end
    app.must_respond_to :call
  end

  it "runs before the application is returned and leaves the app callable" do
    app = build do
      use AssemblySpec::Authenticator
      run AssemblySpec::OK_APP
    end

    response = Rack::MockRequest.new(app).get('/')
    response.status.must_equal 200
    response.body.to_s.must_equal 'OK'
  end

  describe "parse_file" do
    def config_file(name)
      File.join(File.dirname(__FILE__), 'builder', name)
    end

    it "points at the exact unprotected branch when loading a rackup file" do
      error = proc do
        Rack::Builder.parse_file(config_file('assembly_missing_auth.ru'))
      end.must_raise Rack::Assembly::VerificationError

      error.mount_path.must_equal '/admin'
    end
  end
end
