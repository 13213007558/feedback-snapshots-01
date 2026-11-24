# frozen_string_literal: true

module HelperCallPermissionsSample
  class CallLog
    attr_reader :entries

    def initialize
      @entries = []
    end

    def call(entry)
      entries << entry
    end

    def decisions
      entries.select { |entry| entry[:event] == :helper_call_permission }
    end

    def business_calls
      entries.select { |entry| entry[:event] == :business }
    end

    def last_decision
      decisions.last
    end
  end

  class Business
    attr_reader :calls

    def initialize(name, log)
      @name = name
      @log = log
      @calls = []
    end

    def perform(order)
      calls << order
      @log.call(event: :business, business: @name, order:)
      "#{@name}:#{order}"
    end
  end

  class << self
    attr_reader :log

    def reset!
      @log = CallLog.new
      @businesses = %i[restricted public override_a override_b].to_h do |name|
        [name, Business.new(name, @log)]
      end
      self
    end

    def business(name)
      @businesses.fetch(name)
    end
  end

  module CheckoutWorkflow
    def checkout(order)
      HelperCallPermissionsSample.log.call(event: :ordinary_helper, helper: :checkout)
      "checkout(#{settle(order)})"
    end
  end

  module RestrictedSettlement
    def settle(order)
      HelperCallPermissionsSample.log.call(event: :helper_body, definition: 'RestrictedSettlement#settle')
      HelperCallPermissionsSample.business(:restricted).perform(order)
    end
  end

  module PublicSettlement
    def settle(order)
      HelperCallPermissionsSample.log.call(event: :helper_body, definition: 'PublicSettlement#settle')
      HelperCallPermissionsSample.business(:public).perform(order)
    end
  end

  module MountAOverride
    def settle(order)
      HelperCallPermissionsSample.log.call(event: :helper_body, definition: 'MountAOverride#settle')
      HelperCallPermissionsSample.business(:override_a).perform(order)
    end
  end

  module MountBOverride
    def settle(order)
      HelperCallPermissionsSample.log.call(event: :helper_body, definition: 'MountBOverride#settle')
      HelperCallPermissionsSample.business(:override_b).perform(order)
    end
  end

  module Factory
    def self.branch(policy:, scope:, approved:, override: nil)
      Class.new(Grape::API) do
        namespace :approved do
          helpers CheckoutWorkflow, approved
          enforce_helper_call_permissions policy:, scope:, methods: :settle, recorder: HelperCallPermissionsSample.log
          get(:direct) { settle(params[:order]) }
          get(:via_workflow) { checkout(params[:order]) }
        end

        if override
          namespace :unapproved do
            helpers CheckoutWorkflow, approved, override
            enforce_helper_call_permissions policy:, scope:, methods: :settle, recorder: HelperCallPermissionsSample.log
            get(:direct) { settle(params[:order]) }
            get(:via_workflow) { checkout(params[:order]) }
          end
        end
      end
    end
  end
end

RSpec.describe Grape::HelperCallPermission do
  include Rack::Test::Methods

  let(:app_store) { {} }

  def app
    app_store[:root]
  end

  before { HelperCallPermissionsSample.reset! }

  def expect_allowed_call(path, order:, body:, scope:, definition:, owner:)
    get path, order: order

    expect(last_response).to be_successful
    expect(last_response.body).to eq(body)
    expect(HelperCallPermissionsSample.log.last_decision).to include(allowed: true, scope:, definition:)
    expect(HelperCallPermissionsSample.log.last_decision[:owner]).to eq(owner)
  end

  def expect_denied_call(path, order:, scope:, owner:, fragments:)
    get path, order: order

    expect(last_response.status).to eq(403)
    fragments.each { |fragment| expect(last_response.body).to include(fragment) }
    expect(HelperCallPermissionsSample.log.last_decision).to include(allowed: false, scope:, owner:)
  end

  def expect_resolution_metadata(sample)
    first_decision = sample.log.decisions.first
    expect(first_decision[:source_location][0]).to end_with('helper_call_permissions_spec.rb')
    expect(first_decision[:source_location][1]).to be_positive
    expect(first_decision[:request_path]).to eq('/restricted/approved/direct')
    expect(first_decision[:endpoint_namespace]).to eq('/approved')
  end

  it 'checks the endpoint-resolved definition through direct and ordinary helper calls' do
    sample = HelperCallPermissionsSample
    restricted_owner = sample::RestrictedSettlement
    public_owner = sample::PublicSettlement
    restricted_policy = Grape::HelperCallPermission::Policy.new.allow(:settle, scope: :restricted, owner: restricted_owner)
    public_policy = Grape::HelperCallPermission::Policy.new.allow(:settle, scope: :public, owner: public_owner)

    restricted_api = sample::Factory.branch(policy: restricted_policy, scope: :restricted, approved: restricted_owner, override: sample::MountAOverride)

    app_store[:root] = Class.new(Grape::API)
    app.mount restricted_api => '/restricted'

    expect_allowed_call(
      '/restricted/approved/direct', order: 'R-1', body: 'restricted:R-1', scope: :restricted,
      definition: 'HelperCallPermissionsSample::RestrictedSettlement#settle', owner: restricted_owner
    )

    public_api = sample::Factory.branch(policy: public_policy, scope: :public, approved: public_owner, override: sample::MountBOverride)
    app.mount public_api => '/public'

    expect_allowed_call(
      '/public/approved/direct', order: 'P-1', body: 'public:P-1', scope: :public,
      definition: 'HelperCallPermissionsSample::PublicSettlement#settle', owner: public_owner
    )

    get '/restricted/approved/via_workflow', order: 'R-2'
    expect(last_response).to be_successful
    expect(last_response.body).to eq('checkout(restricted:R-2)')
    expect(sample.log.last_decision).to include(allowed: true, scope: :restricted)
    expect(sample.business(:restricted).calls).to eq(%w[R-1 R-2])

    expect_denied_call(
      '/restricted/unapproved/direct', order: 'X-A', scope: :restricted, owner: sample::MountAOverride,
      fragments: ['MountAOverride#settle', 'scope `restricted`', 'business call blocked']
    )
    expect(sample.business(:override_a).calls).to be_empty

    expect_denied_call(
      '/public/unapproved/via_workflow', order: 'X-B', scope: :public, owner: sample::MountBOverride,
      fragments: ['MountBOverride#settle', 'scope `public`']
    )
    expect(sample.log.entries.map { |entry| entry[:event] }).to include(:ordinary_helper)
    expect(sample.business(:override_b).calls).to be_empty
    expect(sample.business(:public).calls).to eq(%w[P-1])

    expect(sample.log.decisions.map { |decision| decision[:method_name] }).to all(eq(:settle))
    expect(sample.log.decisions.map { |decision| [decision[:scope], decision[:definition], decision[:allowed]] }).to eq(
      [
        [:restricted, 'HelperCallPermissionsSample::RestrictedSettlement#settle', true],
        [:public, 'HelperCallPermissionsSample::PublicSettlement#settle', true],
        [:restricted, 'HelperCallPermissionsSample::RestrictedSettlement#settle', true],
        [:restricted, 'HelperCallPermissionsSample::MountAOverride#settle', false],
        [:public, 'HelperCallPermissionsSample::MountBOverride#settle', false]
      ]
    )
    expect_resolution_metadata(sample)
  end
end
