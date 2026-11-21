# frozen_string_literal: true

# Demonstrates managed requests that must use an approved proxy.
#
#   ruby -Ilib examples/proxy_required.rb
#
# Two adapters that record the env they receive stand in for a real adapter,
# so every scenario shows the proxy that actually reached the adapter.

require 'faraday'

# Shared log for both recording adapters.
RECORDED = []

# Records every env it receives and answers 200.
class RecordingAdapter < Faraday::Adapter
  def call(env)
    super
    RECORDED << [env.url.path, env.request.proxy&.host]
    save_response(env, 200, 'ok', {})
    @app.call(env)
  end
end

# A recording adapter that refuses to run without a proxy.
class ApprovedProxyAdapter < RecordingAdapter
  def call(env)
    raise 'this request needs an approved proxy' if env.request.proxy.nil?

    super
  end
end

def connection(adapter, options = {})
  Faraday.new('http://example.com', options) { |f| f.adapter adapter }
end

def show(title)
  RECORDED.clear
  yield
  puts "#{title}: #{RECORDED.inspect}"
end

# 1. A managed request that declares its approved proxy.
show('explicit proxy') do
  connection(ApprovedProxyAdapter, proxy: 'http://approved.proxy:8080')
    .get('/internal') { |req| req.options.proxy_required = true }
end

# 2. A managed request with no approved proxy: fails instead of going direct,
#    even though the environment provides a proxy.
ENV['http_proxy'] = 'http://env.proxy:3128'
begin
  connection(ApprovedProxyAdapter).get('/internal') do |req|
    req.options.proxy_required = true
  end
rescue Faraday::ProxyRequiredError => e
  puts "no approved proxy: #{e.class}: #{e.message}"
end

# 3. A normal request keeps using the environment proxy, or goes direct when
#    there is none.
show('environment proxy') { connection(RecordingAdapter).get('/public') }
ENV.delete('http_proxy')
show('direct') { connection(RecordingAdapter).get('/public') }

# 4. A proxy set on one request never carries over to the next.
conn = connection(RecordingAdapter)
RECORDED.clear
conn.get('/first') { |req| req.options.proxy = 'http://first.proxy:8080' }
conn.get('/second')
puts "no leak: #{RECORDED.inspect}"
