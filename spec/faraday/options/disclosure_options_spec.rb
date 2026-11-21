# frozen_string_literal: true

RSpec.describe Faraday::DisclosureOptions do
  describe '.from' do
    it { expect(described_class.from(nil)).to be_nil }
    it { expect(described_class.from(false)).to be_nil }

    it 'treats true as the strict policy' do
      options = described_class.from(true)

      expect(options.request).to eq([])
      expect(options.error).to eq([])
      expect(options.request_policy?).to be(false)
      expect(options.error_policy?).to be(false)
    end

    it 'builds a policy from a Hash' do
      options = described_class.from(request: %i[method url_path], error: %i[message])

      expect(options.request).to eq(%i[method url_path])
      expect(options.error).to eq(%i[message])
    end

    it 'deep copies an existing policy' do
      original = described_class.from(request: %i[method])
      copy = described_class.from(original)
      copy.request = %i[url]

      expect(original.request).to eq(%i[method])
      expect(copy.request).to eq(%i[url])
    end
  end

  describe 'attribute selection' do
    it 'leaves an omitted dimension unconfigured' do
      options = described_class.from(request: %i[method])

      expect(options.request_configured?).to be(true)
      expect(options.error_configured?).to be(false)
      expect(options.error).to be_nil
      expect(options.error_detail?(:message)).to be(true)
    end

    it 'selects nothing for an explicitly empty dimension' do
      options = described_class.from(request: [], error: [])

      expect(options.request_configured?).to be(true)
      expect(options.request_policy?).to be(false)
      expect(options.request_attribute?(:method)).to be(false)
      expect(options.error_detail?(:response_body)).to be(false)
    end

    it 'accepts aliases' do
      options = described_class.from(request: %i[request_headers request_body],
                                     error: %i[headers body exception])

      expect(options.request).to eq(%i[headers body])
      expect(options.error).to eq(%i[response_headers response_body wrapped_exception])
    end

    it 'rejects unknown attributes' do
      expect { described_class.from(request: %i[password]) }
        .to raise_error(ArgumentError, /unknown request disclosure attribute/)
      expect { described_class.from(error: %i[password]) }
        .to raise_error(ArgumentError, /unknown error disclosure attribute/)
    end
  end

  describe 'options coercion' do
    it 'coerces a Hash assigned to RequestOptions' do
      request = Faraday::RequestOptions.from(disclosure: { request: %i[method] })

      expect(request.disclosure).to be_a(described_class)
      expect(request.disclosure.request).to eq(%i[method])
    end

    it 'coerces a Hash assigned later' do
      request = Faraday::RequestOptions.new
      request.disclosure = { error: %i[message] }

      expect(request.disclosure).to be_a(described_class)
      expect(request.disclosure.error).to eq(%i[message])
    end

    it 'coerces a Hash assigned to ConnectionOptions' do
      connection = Faraday::ConnectionOptions.from(disclosure: { request: %i[url_path] })

      expect(connection.disclosure).to be_a(described_class)
      expect(connection.disclosure.request).to eq(%i[url_path])
    end
  end

  describe 'round trips' do
    it 'survives to_hash and merge' do
      options = described_class.from(request: %i[method], error: %i[message])
      merged = options.merge(request: %i[url_path])

      expect(merged.to_hash).to eq(request: %i[url_path], error: %i[message])
      expect(options.request).to eq(%i[method])
    end
  end
end
