# frozen_string_literal: true

RSpec.describe Faraday::RequestOptions do
  subject(:options) { Faraday::RequestOptions.new }

  it 'allows to set the request proxy' do
    expect(options.proxy).to be_nil

    expect { options[:proxy] = { booya: 1 } }.to raise_error(NoMethodError)

    options[:proxy] = { user: 'user' }
    expect(options.proxy).to be_a_kind_of(Faraday::ProxyOptions)
    expect(options.proxy.user).to eq('user')

    options.proxy = nil
    expect(options.proxy).to be_nil
    expect(options.inspect).to eq('#<Faraday::RequestOptions (empty)>')
  end

  it 'coerces a proxy passed to the constructor' do
    options = Faraday::RequestOptions.new(proxy: 'http://proxy.example.com:8080')

    expect(options.proxy).to be_a_kind_of(Faraday::ProxyOptions)
    expect(options.proxy.host).to eq('proxy.example.com')
  end

  it 'coerces a proxy assigned through the writer' do
    options.proxy = { uri: 'http://proxy.example.com:8080' }

    expect(options.proxy).to be_a_kind_of(Faraday::ProxyOptions)
  end

  describe '#dup' do
    it 'gives the copy its own proxy options' do
      options.proxy = 'http://proxy.example.com:8080'
      copy = options.dup

      expect(copy.proxy).not_to equal(options.proxy)
      expect(copy.proxy.host).to eq(options.proxy.host)

      copy.proxy.host = 'other.example.com'
      expect(options.proxy.host).to eq('proxy.example.com')
      expect(copy.proxy.host).to eq('other.example.com')
    end
  end
end
