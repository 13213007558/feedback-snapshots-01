# frozen_string_literal: true

RSpec.describe Faraday::Request::Authorization::CredentialProvider do
  # Controllable provider used by the specs. It approves requests while
  # `allow?` returns true, records every lookup and exposes the per-request
  # bookkeeping the base class keeps.
  let(:provider_class) do
    Class.new(described_class) do
      attr_reader :lookups

      def initialize(versions: nil, allow: ->(_env, _state) { true })
        super()
        @versions = versions
        @allow = allow
        @lookups = []
        @counter = 0
      end

      def fetch_credential(env, state)
        @lookups << state.request_id
        version = @versions ? @versions[@counter] : state.version
        @counter += 1
        if @allow.call(env, state)
          Faraday::Request::Authorization::CredentialResult
            .approved("token-#{version || 1}", version: version)
        else
          Faraday::Request::Authorization::CredentialResult
            .denied('rotated away', version: version)
        end
      end
    end
  end

  let(:provider) { provider_class.new }

  def build_env
    Faraday::Env.new(:get, nil, Faraday::Utils::URI('http://example.com/auth-echo'),
                     Faraday::RequestOptions.new, Faraday::Utils::Headers.new, {})
  end

  describe '#credential_for' do
    it 'returns an explicit approved result' do
      result = provider.credential_for(build_env, 'req-1')
      expect(result).to be_approved
      expect(result.value).to eq('token-1')
    end

    it 'records the fetch count for a single request' do
      provider.credential_for(build_env, 'req-1')
      provider.credential_for(build_env, 'req-1')
      expect(provider.fetch_count('req-1')).to eq(2)
    end

    it 'tracks each request independently when many are prepared concurrently' do
      ids = Array.new(5) { |i| "req-#{i}" }
      threads = ids.map do |id|
        Thread.new do
          3.times { provider.credential_for(build_env, id) }
        end
      end
      threads.each(&:join)

      ids.each do |id|
        expect(provider.fetch_count(id)).to eq(3)
      end
      expect(provider.request_ids).to match_array(ids)
    end

    it 'pins the version from the first lookup across a legitimate retry' do
      versioned = provider_class.new(versions: [7, 9])
      first = versioned.credential_for(build_env, 'req-1')
      second = versioned.credential_for(build_env, 'req-1')

      expect(first.version).to eq(7)
      expect(second.version).to eq(7)
      expect(versioned.request_state('req-1').version).to eq(7)
    end

    it 'records a denial without marking an outbound attempt' do
      denying = provider_class.new(allow: ->(_env, _state) { false })
      result = denying.credential_for(build_env, 'req-denied')

      expect(result).to be_denied
      state = denying.request_state('req-denied')
      expect(state).to be_denied
      expect(state).not_to be_outbound_attempted
    end
  end

  describe '#mark_outbound!' do
    it 'records that an outbound attempt happened for the request' do
      provider.credential_for(build_env, 'req-1')
      provider.mark_outbound!('req-1')

      state = provider.request_state('req-1')
      expect(state).to be_outbound_attempted
    end
  end

  describe 'abstract base' do
    it 'raises when fetch_credential is not implemented' do
      expect { described_class.new.credential_for(build_env, 'req-1') }
        .to raise_error(NotImplementedError)
    end
  end
end
