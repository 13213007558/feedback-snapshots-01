# frozen_string_literal: true

RSpec.describe Faraday::Disclosure do
  let(:policy) { Faraday::DisclosureOptions.from(request: %i[method url_path], error: %i[response_body]) }
  let(:url) { Faraday::Utils.URI('https://example.com/secret/path?token=SECRET-QUERY') }
  let(:env) do
    Faraday::Env.from(
      method: :post,
      url: url,
      request: Faraday::RequestOptions.new,
      request_headers: { 'Authorization' => 'Bearer SECRET-HEADER' },
      request_body: 'SECRET-REQUEST',
      status: 500,
      response_headers: { 'X-Secret' => 'SECRET-RESPONSE-HEADER' },
      response_body: 'SECRET-RESPONSE'
    )
  end

  describe '.policy_for' do
    it 'reads the policy from the request options' do
      env.request.disclosure = policy

      expect(described_class.policy_for(env)).to eq(policy)
    end

    it 'returns nil without a configured policy' do
      expect(described_class.policy_for(env)).to be_nil
    end
  end

  describe '.sanitize_response' do
    it 'keeps the selected response and request fields only' do
      response = Faraday::Response.new(env)
      sanitized = described_class.sanitize_response(response, policy)

      expect(sanitized).to be_a(Faraday::Response)
      expect(sanitized.status).to eq(500)
      expect(sanitized.body).to eq('SECRET-RESPONSE')
      expect(sanitized.headers).to eq({})
      expect(sanitized.url.to_s).to eq('/secret/path')
      expect(sanitized.env.method).to eq(:post)
      expect(sanitized.env.request_headers).to be_nil
      expect(sanitized.env.request_body).to be_nil
      expect(sanitized.env[:params]).to be_nil
    end

    it 'does not modify the original env' do
      described_class.sanitize_response(env, policy)

      expect(env.request_headers['Authorization']).to eq('Bearer SECRET-HEADER')
      expect(env.response_headers['X-Secret']).to eq('SECRET-RESPONSE-HEADER')
      expect(env.url.query).to eq('token=SECRET-QUERY')
    end

    it 'returns the source when it has no env' do
      unfinished = Faraday::Response.new

      expect(described_class.sanitize_response(unfinished, policy)).to equal(unfinished)
    end
  end

  describe '.request_url' do
    it 'keeps the full URL when selected' do
      full = Faraday::DisclosureOptions.from(request: %i[url])

      expect(described_class.request_url(env, full).to_s).to eq(url.to_s)
    end

    it 'keeps only the path when url_path is selected' do
      expect(described_class.request_url(env, policy).to_s).to eq('/secret/path')
    end

    it 'returns nil when neither is selected' do
      method_only = Faraday::DisclosureOptions.from(request: %i[method])

      expect(described_class.request_url(env, method_only)).to be_nil
    end
  end

  describe '.request_params' do
    it 'decodes the query with the request params encoder' do
      expect(described_class.request_params(env)).to eq('token' => 'SECRET-QUERY')
    end
  end

  describe '.status_message' do
    it 'includes the selected method and url' do
      expect(described_class.status_message(500, :post, '/path'))
        .to eq('the server responded with status 500 for POST /path')
    end

    it 'omits missing parts' do
      expect(described_class.status_message(500, nil, nil))
        .to eq('the server responded with status 500')
    end
  end
end
