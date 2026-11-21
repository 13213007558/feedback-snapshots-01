# frozen_string_literal: true

require "spec_helper"

require "rails"
require "action_controller/railtie"
require "active_support/core_ext/object/json"
require "logger"
require "stringio"
require "json"

# A synthetic sensitive domain object. Its custom #inspect raises so that any
# accidental rendering of the record through the public path fails loudly, and
# a counter proves the public representation makes zero calls into it.
class SyntheticSensitiveRecord
  class << self
    attr_accessor :inspect_calls
  end
  self.inspect_calls = 0

  def initialize(id:, secret:)
    @id = id
    @secret = secret
  end

  attr_reader :id, :secret

  def inspect
    self.class.inspect_calls += 1
    raise "SyntheticSensitiveRecord#inspect must never be called by the public representation"
  end

  def to_s
    "synthetic-sensitive-record"
  end
end

class ApplicationPolicy
  attr_reader :user, :record

  def initialize(user, record)
    @user = user
    @record = record
  end
end

# First policy: denies updates for the synthetic sensitive record.
class SyntheticSensitiveRecordPolicy < ApplicationPolicy
  def update?
    false
  end
end

# Second policy: denies destruction for the same record.
class SyntheticSensitiveRecordAuditPolicy < ApplicationPolicy
  def destroy?
    false
  end
end

# A stand-in for the product's public log sink (e.g. a JSON line shipper).
class PublicJsonLogSink
  def initialize
    @io = StringIO.new
    @logger = Logger.new(@io)
    @logger.formatter = proc { |severity, _time, _progname, message|
      JSON.generate(severity: severity, message: message) + "\n"
    }
  end

  attr_reader :logger

  def entries
    @io.rewind
    lines = @io.read.lines
    @io.rewind
    lines.map { |line| JSON.parse(line) }
  end

  def clear
    @io.truncate(0)
    @io.rewind
  end
end

PUBLIC_LOG_SINK = PublicJsonLogSink.new

class ApplicationController < ActionController::Base
  include Pundit::Authorization

  rescue_from Pundit::NotAuthorizedError, with: :user_not_authorized

  private

  def current_user
    :anonymous
  end

  # Local development can still catch the original exception, with the record
  # and policy instance available for debugging.
  def user_not_authorized(exception)
    PUBLIC_LOG_SINK.logger.info(exception.denied_event.to_json)
    response.set_header("X-Pundit-Correlation-Id", exception.correlation_id)
    head :forbidden
  end
end

class SensitiveRecordsController < ApplicationController
  module ErrorCapturing
    class << self
      attr_accessor :last_error
    end

    def user_not_authorized(exception)
      ErrorCapturing.last_error = exception
      super
    end
  end

  def update
    record = SyntheticSensitiveRecord.new(id: 4242, secret: "top-secret-token")
    authorize(record, :update?)
    head :ok
  end

  def destroy
    record = SyntheticSensitiveRecord.new(id: 4242, secret: "top-secret-token")
    authorize(record, :destroy?, policy_class: SyntheticSensitiveRecordAuditPolicy)
    head :ok
  end
end

class PublicLoggingRailsApp < Rails::Application
  config.eager_load = false
  config.secret_key_base = "a" * 64
  config.logger = Logger.new(IO::NULL)
  config.action_dispatch.show_exceptions = :all
  config.consider_all_requests_local = false
  config.hosts.clear
  config.action_dispatch.default_headers = {}
end

PublicLoggingRailsApp.initialize!

PublicLoggingRailsApp.routes.draw do
  patch "/sensitive_records/:id", to: "sensitive_records#update"
  delete "/sensitive_records/:id", to: "sensitive_records#destroy"
end

RSpec.describe "Pundit denial logging in a Rails request", type: :request do
  def call_request(method, path)
    PublicLoggingRailsApp.routes.call(Rack::MockRequest.env_for(path, method: method))
  end

  let(:log_entries) { PUBLIC_LOG_SINK.entries }

  around do |example|
    PUBLIC_LOG_SINK.clear
    example.run
  end

  it "responds 403 and emits a public JSON event for the first policy" do
    status, headers, = call_request("PATCH", "/sensitive_records/4242")

    expect(status).to eq 403
    expect(log_entries.size).to eq 1

    entry = log_entries.last.fetch("message")
    expect(JSON.parse(entry)).to eq(
      "event" => "pundit.authorization_denied",
      "policy_class" => "SyntheticSensitiveRecordPolicy",
      "query" => "update?",
      "correlation_id" => headers["X-Pundit-Correlation-Id"]
    )
  end

  it "emits a distinct event for the second policy and query" do
    status, headers, = call_request("DELETE", "/sensitive_records/4242")

    expect(status).to eq 403
    expect(log_entries.size).to eq 1

    expect(JSON.parse(log_entries.last.fetch("message"))).to eq(
      "event" => "pundit.authorization_denied",
      "policy_class" => "SyntheticSensitiveRecordAuditPolicy",
      "query" => "destroy?",
      "correlation_id" => headers["X-Pundit-Correlation-Id"]
    )
  end

  it "keeps the restricted record and policy instance out of the public log" do
    call_request("PATCH", "/sensitive_records/4242")

    raw_line = log_entries.last.to_json
    expect(raw_line).not_to include "top-secret-token"
    expect(raw_line).not_to include "0x"
    expect(raw_line).not_to include "synthetic-sensitive-record"
    message = JSON.parse(log_entries.last.fetch("message"))
    expect(message).not_to have_key "record"
    expect(message).not_to have_key "policy"
    expect(message.fetch("policy_class")).to eq "SyntheticSensitiveRecordPolicy"
  end

  it "never invokes the model's custom #inspect through the public path" do
    SyntheticSensitiveRecord.inspect_calls = 0

    expect { call_request("PATCH", "/sensitive_records/4242") }.not_to raise_error
    expect { call_request("DELETE", "/sensitive_records/4242") }.not_to raise_error

    expect(SyntheticSensitiveRecord.inspect_calls).to eq 0
  end

  it "preserves locate-ability: the correlation id links response, event and exception" do
    install_tracer

    status, headers, = call_request("PATCH", "/sensitive_records/4242")
    error = SensitiveRecordsController::ErrorCapturing.last_error

    expect(status).to eq 403
    expect(error).to be_a Pundit::NotAuthorizedError
    expect(headers["X-Pundit-Correlation-Id"]).to eq error.correlation_id
    expect(JSON.parse(log_entries.last.fetch("message")).fetch("correlation_id")).to eq(
      error.correlation_id
    )
  end

  it "keeps the full exception available for local development handling" do
    install_tracer
    SyntheticSensitiveRecord.inspect_calls = 0

    call_request("PATCH", "/sensitive_records/4242")
    error = SensitiveRecordsController::ErrorCapturing.last_error

    expect(error.query).to eq :update?
    expect(error.record).to be_a SyntheticSensitiveRecord
    expect(error.record.id).to eq 4242
    expect(error.policy).to be_a SyntheticSensitiveRecordPolicy
    expect(error.message).to eq(
      "not allowed to SyntheticSensitiveRecordPolicy#update? this SyntheticSensitiveRecord"
    )
    expect(SyntheticSensitiveRecord.inspect_calls).to eq 0
  end

  def install_tracer
    tracer = SensitiveRecordsController::ErrorCapturing
    SensitiveRecordsController.prepend(tracer) unless SensitiveRecordsController.include?(tracer)
    tracer.last_error = nil
  end
end
