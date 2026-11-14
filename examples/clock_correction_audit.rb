#!/usr/bin/env ruby
# frozen_string_literal: true

# Demonstrates the opt-in OAuth clock correction flow with fake HTTP responses.
# It makes no network requests: the transport is a lambda which returns
# Net::HTTPResponse objects (or raises, for the unknown-outcome case).
#
# Run with:
#   bundle exec ruby examples/clock_correction_audit.rb

require "oauth"

SITE = "http://api.example.com"
PATH = "/orders"
BODY = "item=book"
IDEMPOTENCY_KEY = "order-42"

def refused_response(origin: SITE)
  response = Net::HTTPUnauthorized.new("1.1", "401", "Unauthorized")
  response["WWW-Authenticate"] = 'OAuth oauth_problem="timestamp_refused", oauth_problem_advice="clock skew"'
  response.uri = URI.parse(origin)
  response.instance_variable_set(:@body, "")
  response
end

def ok_response
  response = Net::HTTPOK.new("1.1", "200", "OK")
  response.instance_variable_set(:@body, "accepted")
  response
end

def problem_for(response)
  headers = response.to_hash["www-authenticate"]
  return nil unless headers

  header = headers.grep(/^OAuth /).first
  return nil unless header && header.include?("oauth_problem")

  params = OAuth::Helper.parse_header(header)
  OAuth::Problem.new(params.delete("oauth_problem"), response, params)
rescue StandardError
  nil
end

def run_scenario(label, transport:, trusted_time_source:, max_offset_seconds: 300)
  consumer = OAuth::Consumer.new(
    "consumer-key",
    "consumer-secret",
    site: SITE,
    clock_correction: {
      trusted_time_source: trusted_time_source,
      max_offset_seconds: max_offset_seconds
    }
  )
  token = OAuth::ConsumerToken.new(consumer, "access-token", "token-secret")
  sent = 0

  correction = OAuth::Client::ClockCorrection.new(
    consumer.options[:clock_correction],
    offsets: {}
  )

  outcome = correction.execute(
    target_origin: SITE,
    http_method: :post,
    build_request: lambda do |options|
      consumer.create_signed_request(
        :post,
        PATH,
        token,
        options,
        BODY,
        {"Idempotency-Key" => IDEMPOTENCY_KEY}
      )
    end,
    transport: lambda do |request|
      sent += 1
      transport.call(request, sent)
    end,
    problem_for: method(:problem_for)
  )

  puts "== #{label} =="
  puts "result=#{outcome.result} reason=#{outcome.reason.inspect} sent=#{sent} " \
       "manual_retry=#{outcome.manual_retry?} offset=#{outcome.offset_seconds.inspect}"
  outcome.attempts.each do |attempt|
    puts "  attempt #{attempt[:number]}: timestamp=#{attempt[:oauth_timestamp]} " \
         "nonce=#{attempt[:oauth_nonce]} signature=#{attempt[:oauth_signature]} " \
         "idempotency=#{attempt[:idempotency_key].inspect} body_sha256=#{attempt[:body_sha256][0, 12]}..."
  end
  puts
  outcome
end

allowed = run_scenario(
  "allowed correction (same service, caller-approved time)",
  transport: ->(_request, sent) { sent == 1 ? refused_response : ok_response },
  trusted_time_source: ->(_response, _context) { Time.now.to_i + 45 }
)
raise "expected correction" unless allowed.corrected? && allowed.request_count == 2

malicious = run_scenario(
  "malicious large offset (bounded by policy)",
  transport: ->(_request, _sent) { refused_response },
  trusted_time_source: ->(_response, _context) { Time.now.to_i + 999_999 }
)
raise "expected rejection" unless malicious.result == :offset_rejected && malicious.request_count == 1

unknown = run_scenario(
  "timeout (result unknown, no automatic write replay)",
  transport: ->(_request, _sent) { raise Net::ReadTimeout, "read timed out" },
  trusted_time_source: ->(_response, _context) { Time.now.to_i + 45 }
)
raise "expected unknown outcome" unless unknown.result == :unknown_outcome && unknown.manual_retry?

puts "All demonstrations completed. Caller may retry manually where manual_retry=true."
