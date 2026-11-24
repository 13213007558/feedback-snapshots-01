# frozen_string_literal: true

describe Grape::Validations::WorkBudget do
  # Two declarations of one batch shape. The +given+ one branches per element:
  # every item evaluates both dependency scopes before exactly one of its
  # fields is validated. The flat one declares the same fields as optionals,
  # so the same data volume is validated without branching. A batch that is
  # ordinary for the flat declaration is what the budget is meant to stop on
  # the branching one.
  def branchy_api(rescue_budget: false, &on_handle)
    Class.new(Grape::API) do
      format :json
      if rescue_budget
        rescue_from Grape::Exceptions::ValidationBudgetExceeded do |error|
          error!({ kind: 'validation_budget', limit: error.limit, spent: error.spent }, 422)
        end
      end

      params do
        requires :items, type: Array do
          requires :kind, type: String, values: %w[credit cash]
          given kind: ->(kind) { kind == 'credit' } do
            requires :card_last4, type: String, allow_blank: false
          end
          given kind: ->(kind) { kind == 'cash' } do
            requires :receipt_no, type: String, allow_blank: false
          end
        end
      end
      post('/branchy') do
        on_handle&.call
        { handled: params[:items].size }
      end
    end
  end

  def flat_api(&on_handle)
    Class.new(Grape::API) do
      format :json

      params do
        requires :items, type: Array do
          requires :kind, type: String, values: %w[credit cash]
          optional :card_last4, type: String, allow_blank: false
          optional :receipt_no, type: String, allow_blank: false
        end
      end
      post('/flat') do
        on_handle&.call
        { handled: params[:items].size }
      end
    end
  end

  # Each element passes the branch its kind selects.
  def batch(count, kind = nil)
    Array.new(count) do |index|
      credit = kind ? kind == :credit : index.even?
      credit ? { kind: 'credit', card_last4: format('%04d', index) } : { kind: 'cash', receipt_no: "R#{index}" }
    end
  end

  def post_batch(path, items)
    post path, { items: items }.to_json, 'CONTENT_TYPE' => 'application/json'
  end

  around do |example|
    previous = Grape.config.validation_work_budget
    example.run
  ensure
    Grape.config.validation_work_budget = previous
  end

  describe 'configuration' do
    it 'accepts a non-negative Integer or nil' do
      expect { Grape.config.validation_work_budget = 0 }.not_to raise_error
      expect { Grape.config.validation_work_budget = nil }.not_to raise_error
      expect { Grape.config.validation_work_budget = -1 }.to raise_error(ArgumentError, /non-negative Integer or nil/)
      expect { Grape.config.validation_work_budget = 'many' }.to raise_error(ArgumentError, /non-negative Integer or nil/)
    end

    it 'defaults to an allowance an ordinary batch fits in' do
      expect(Grape.config.validation_work_budget).to be_positive
    end
  end

  describe 'a batch whose branches add up past the allowance' do
    let(:handled) { [] }
    let(:app) { branchy_api { handled << :branchy } }

    before { Grape.config.validation_work_budget = 10_000 }

    # Each branch at the full 400-element volume on its own stays inside the
    # allowance, and every element of every batch here passes the branch its
    # kind selects. The batch that mixes the two branches has the same 400
    # elements and the same validity, but the work of both dependency scopes
    # across it overruns the allowance, so it is stopped.
    it 'passes each branch at full volume and stops the combination' do
      post_batch('/branchy', batch(400, :credit))
      expect(last_response.status).to eq(201)
      expect(JSON.parse(last_response.body)).to eq('handled' => 400)

      post_batch('/branchy', batch(400, :cash))
      expect(last_response.status).to eq(201)
      expect(JSON.parse(last_response.body)).to eq('handled' => 400)
      expect(handled).to eq(%i[branchy branchy])

      post_batch('/branchy', batch(400))
      expect(last_response.status).to eq(400)
      expect(last_response.body).to include('exceeds the validation work budget of 10000')
      expect(handled).to eq(%i[branchy branchy])
    end

    it 'keeps the category stable and carries the allowance on the exception' do
      expect { described_class.track(2) { described_class.charge(3) } }
        .to raise_error(Grape::Exceptions::ValidationBudgetExceeded) do |error|
          expect(error.limit).to eq(2)
          expect(error.spent).to eq(3)
          expect(error.status).to eq(400)
        end
    end

    it 'is not a ValidationErrors, so a field-error rescue does not catch it' do
      error = nil
      begin
        described_class.track(1) { described_class.charge(2) }
      rescue Grape::Exceptions::ValidationErrors
        raise
      rescue Grape::Exceptions::ValidationBudgetExceeded => e
        error = e
      end

      expect(error).to be_a(Grape::Exceptions::ValidationBudgetExceeded)
    end
  end

  describe 'the same data volume without branches' do
    let(:handled) { [] }
    let(:app) { flat_api { handled << :flat } }

    before { Grape.config.validation_work_budget = 10_000 }

    it 'completes and lets the handler start' do
      post_batch('/flat', batch(400))

      expect(last_response.status).to eq(201)
      expect(JSON.parse(last_response.body)).to eq('handled' => 400)
      expect(handled).to eq(%i[flat])
    end

    it 'accepts a large simple batch under the default allowance' do
      Grape.config.validation_work_budget = 1_000_000
      post_batch('/flat', batch(5_000))

      expect(last_response.status).to eq(201)
      expect(JSON.parse(last_response.body)).to eq('handled' => 5_000)
      expect(handled).to eq(%i[flat])
    end

    it 'spends from the default allowance rather than ignoring it' do
      Grape.config.validation_work_budget = 4_000
      post_batch('/flat', batch(5_000))

      expect(last_response.status).to eq(400)
      expect(handled).to be_empty
    end
  end

  describe 'the boundary between spending and overrunning' do
    it 'passes when the work lands exactly on the allowance' do
      expect { described_class.track(2) { described_class.charge(2) } }.not_to raise_error
    end

    it 'fails once one more unit is spent' do
      expect { described_class.track(2) { described_class.charge(3) } }
        .to raise_error(Grape::Exceptions::ValidationBudgetExceeded)
    end
  end

  describe 'a mounted API' do
    let(:handled) { [] }
    let(:inner) do
      Class.new(Grape::API) do
        format :json
        params do
          requires :items, type: Array do
            requires :kind, type: String
          end
        end
        post('/inner') do
          handled << :inner
          { handled: params[:items].size }
        end
      end
    end

    let(:app) do
      nested = inner
      Class.new(Grape::API) do
        format :json
        mount nested
      end
    end

    it 'shares one allowance with the endpoints it reaches' do
      Grape.config.validation_work_budget = 1_000
      post_batch('/inner', Array.new(2_000) { { kind: 'credit' } })

      expect(last_response.status).to eq(400)
      expect(handled).to be_empty
    end
  end

  describe 'a disabled budget' do
    let(:handled) { [] }
    let(:app) { branchy_api { handled << :branchy } }

    it 'lets the branchy batch through' do
      Grape.config.validation_work_budget = nil
      post_batch('/branchy', batch(400))
      expect(last_response.status).to eq(201)
      expect(handled).to eq(%i[branchy])
    end
  end

  describe 'error aggregation' do
    let(:handled) { [] }
    let(:app) do
      Class.new(Grape::API) do
        format :json

        params do
          requires :items, type: Array do
            requires :kind, type: String, values: %w[credit cash]
            given kind: ->(kind) { kind == 'credit' } do
              requires :card_last4, type: String
            end
          end
        end
        post '/' do
          handled << :ran
          'never'
        end
      end
    end

    it 'reports the budget rather than a list of per-element failures' do
      Grape.config.validation_work_budget = 2_000
      post_batch('/', Array.new(400) { { kind: 'credit' } })
      expect(last_response.status).to eq(400)
      expect(last_response.body).to include('exceeds the validation work budget of 2000')
      expect(handled).to be_empty
    end

    it 'charges for building and translating the collected errors' do
      errors = [Grape::Exceptions::Validation.new(params: %w[items 0 kind], message: :presence)]

      expect { described_class.track(0) { Grape::Exceptions::ValidationErrors.new(exceptions: errors) } }
        .to raise_error(Grape::Exceptions::ValidationBudgetExceeded)
    end
  end

  describe 'a custom rescue_from' do
    let(:handled) { [] }
    let(:app) { branchy_api(rescue_budget: true) { handled << :branchy } }

    it 'leaves the category to the handler' do
      Grape.config.validation_work_budget = 10_000
      post_batch('/branchy', batch(400))
      expect(last_response.status).to eq(422)
      payload = JSON.parse(last_response.body)
      expect(payload['kind']).to eq('validation_budget')
      expect(payload['limit']).to eq(10_000)
      expect(payload['spent']).to be > 10_000
      expect(handled).to be_empty
    end
  end
end
