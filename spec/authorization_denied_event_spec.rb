# frozen_string_literal: true

require "spec_helper"
require "json"

RSpec.describe Pundit::AuthorizationDeniedEvent do
  # A record whose custom #inspect raises: a public representation must never
  # invoke it, otherwise sensitive data could be rendered into a log line.
  let(:sensitive_record_class) do
    Class.new do
      def inspect
        raise "custom #inspect must not be called by the public representation"
      end

      def to_s
        "synthetic-sensitive-record"
      end
    end
  end

  let(:sensitive_record) { sensitive_record_class.new }

  let(:policy_class) do
    Class.new do
      define_singleton_method(:name) { "SyntheticSensitiveRecordPolicy" }

      def initialize(user, record)
        @user = user
        @record = record
      end

      attr_reader :user, :record

      def update?
        false
      end

      def inspect
        raise "policy #inspect must not be called by the public representation"
      end
    end
  end

  let(:policy) { policy_class.new(:user, sensitive_record) }

  let(:error) do
    Pundit::NotAuthorizedError.new(
      query: :update?,
      record: sensitive_record,
      policy: policy
    )
  end

  describe ".from_error" do
    it "copies the policy class name, query and correlation id" do
      event = described_class.from_error(error)

      expect(event).to have_attributes(
        event: "pundit.authorization_denied",
        policy_class: "SyntheticSensitiveRecordPolicy",
        query: "update?",
        correlation_id: error.correlation_id
      )
    end

    it "does not call #inspect on the restricted record" do
      expect { described_class.from_error(error) }.not_to raise_error
    end
  end

  describe "#initialize" do
    it "accepts a policy module and uses its name" do
      event = described_class.new(policy_class: policy_class, query: :show?)

      expect(event.policy_class).to eq "SyntheticSensitiveRecordPolicy"
    end

    it "keeps a string policy class as-is" do
      event = described_class.new(policy_class: "PostPolicy", query: "show?")

      expect(event.policy_class).to eq "PostPolicy"
    end

    it "allows a nil policy class" do
      event = described_class.new(policy_class: nil, query: nil)

      expect(event.policy_class).to be_nil
      expect(event.query).to be_nil
    end

    it "generates a correlation id when none is given" do
      event = described_class.new(policy_class: "PostPolicy", query: :show?)

      expect(event.correlation_id).to match(/\A[0-9a-f-]{36}\z/)
    end

    it "accepts an explicit correlation id" do
      event = described_class.new(
        policy_class: "PostPolicy",
        query: :show?,
        correlation_id: "corr-42"
      )

      expect(event.correlation_id).to eq "corr-42"
    end
  end

  describe "#to_h" do
    it "only contains public-safe keys" do
      hash = described_class.from_error(error).to_h

      expect(hash.keys).to match_array %w[event policy_class query correlation_id]
      expect(hash).to eq(
        "event" => "pundit.authorization_denied",
        "policy_class" => "SyntheticSensitiveRecordPolicy",
        "query" => "update?",
        "correlation_id" => error.correlation_id
      )
    end
  end

  describe "#to_json" do
    it "serializes only public-safe values" do
      parsed = JSON.parse(described_class.from_error(error).to_json)

      expect(parsed).to eq(
        "event" => "pundit.authorization_denied",
        "policy_class" => "SyntheticSensitiveRecordPolicy",
        "query" => "update?",
        "correlation_id" => error.correlation_id
      )
    end

    it "forwards ActiveSupport as_json options when loaded" do
      require "active_support/core_ext/object/json"

      json = described_class.from_error(error).to_json(only: ["query"])

      expect(JSON.parse(json)).to eq("query" => "update?")
    end
  end

  describe "#as_json" do
    it "returns the hash representation" do
      event = described_class.from_error(error)

      expect(event.as_json).to eq event.to_h
    end
  end

  describe "#inspect" do
    it "renders without touching the restricted record" do
      event = described_class.from_error(error)

      expect(event.inspect).to include "SyntheticSensitiveRecordPolicy", "update?"
    end
  end

  describe "#==" do
    it "is equal to an event with the same attributes" do
      event = described_class.new(
        policy_class: "PostPolicy",
        query: :show?,
        correlation_id: "corr-1"
      )
      same = described_class.new(
        policy_class: "PostPolicy",
        query: "show?",
        correlation_id: "corr-1"
      )
      different = described_class.new(
        policy_class: "PostPolicy",
        query: :update?,
        correlation_id: "corr-1"
      )

      expect(event).to eq same
      expect(event).to eql same
      expect(event.hash).to eq same.hash
      expect(event).not_to eq different
    end

    it "is not equal to other objects" do
      event = described_class.new(policy_class: "PostPolicy", query: :show?)

      expect(event).not_to eq event.to_h
    end
  end
end

RSpec.describe Pundit::NotAuthorizedError do
  let(:sensitive_record_class) do
    Class.new do
      def inspect
        raise "custom #inspect must not be called by the public representation"
      end
    end
  end

  let(:sensitive_record) { sensitive_record_class.new }

  let(:policy_class) do
    Class.new do
      define_singleton_method(:name) { "SyntheticSensitiveRecordPolicy" }

      def initialize(user, record)
        @user = user
        @record = record
      end

      attr_reader :user, :record

      def update?
        false
      end

      def inspect
        raise "policy #inspect must not be called by the public representation"
      end
    end
  end

  let(:other_policy_class) do
    Class.new do
      define_singleton_method(:name) { "AuditLogPolicy" }

      def initialize(user, record)
        @user = user
        @record = record
      end

      def destroy?
        false
      end
    end
  end

  let(:policy) { policy_class.new(:user, sensitive_record) }

  let(:error) do
    described_class.new(query: :update?, record: sensitive_record, policy: policy)
  end

  describe "backwards compatibility" do
    it "can still be initialized with a string message and rescued locally" do
      error = described_class.new("must be logged in")

      expect(error.message).to eq "must be logged in"
      expect(error.query).to be_nil
      expect(error.record).to be_nil
      expect(error.policy).to be_nil
      expect(error.correlation_id).to match(/\A[0-9a-f-]{36}\z/)
    end

    it "still exposes the query, record and policy for local handling" do
      expect(error.query).to eq :update?
      expect(error.record).to eq sensitive_record
      expect(error.policy).to eq policy
    end
  end

  describe "#correlation_id" do
    it "is generated per error" do
      another = described_class.new(query: :update?, record: sensitive_record, policy: policy)

      expect(error.correlation_id).to match(/\A[0-9a-f-]{36}\z/)
      expect(error.correlation_id).not_to eq another.correlation_id
    end

    it "can be provided explicitly" do
      error = described_class.new(
        query: :update?,
        record: sensitive_record,
        policy: policy,
        correlation_id: "corr-77"
      )

      expect(error.correlation_id).to eq "corr-77"
    end
  end

  describe "#policy_class_name" do
    it "returns the policy class name without touching the record" do
      expect(error.policy_class_name).to eq "SyntheticSensitiveRecordPolicy"
    end

    it "is nil when no policy was given" do
      expect(described_class.new("boom").policy_class_name).to be_nil
    end
  end

  describe "#denied_event" do
    it "builds a public-safe event with the same correlation id" do
      event = error.denied_event

      expect(event).to be_a Pundit::AuthorizationDeniedEvent
      expect(event.policy_class).to eq "SyntheticSensitiveRecordPolicy"
      expect(event.query).to eq "update?"
      expect(event.correlation_id).to eq error.correlation_id
    end

    it "is memoized" do
      expect(error.denied_event).to equal error.denied_event
    end

    it "never calls #inspect on the restricted record" do
      expect { error.denied_event }.not_to raise_error
    end
  end

  describe "#to_json / #as_json" do
    it "serializes through the public event and never the record or policy" do
      parsed = JSON.parse(error.to_json)

      expect(parsed).to eq(
        "event" => "pundit.authorization_denied",
        "policy_class" => "SyntheticSensitiveRecordPolicy",
        "query" => "update?",
        "correlation_id" => error.correlation_id
      )
      expect(parsed).not_to have_key "record"
      expect(parsed).not_to have_key "policy"
      expect(error.as_json).to eq error.denied_event.as_json
    end

    it "does not call #inspect on the restricted record" do
      expect { error.to_json }.not_to raise_error
    end
  end

  describe "Marshal" do
    it "round trips without the restricted record or policy instance" do
      restored = Marshal.load(Marshal.dump(error)) # rubocop:disable Security/MarshalLoad

      expect(restored).to be_a described_class
      expect(restored.message).to eq error.message
      expect(restored.query).to eq :update?
      expect(restored.correlation_id).to eq error.correlation_id
      expect(restored.policy_class_name).to eq "SyntheticSensitiveRecordPolicy"
      expect(restored.record).to be_nil
      expect(restored.policy).not_to eq policy
      expect(JSON.parse(restored.to_json)).to eq JSON.parse(error.to_json)
    end

    it "supports errors without a policy" do
      headless = described_class.new(query: :create?)

      restored = Marshal.load(Marshal.dump(headless)) # rubocop:disable Security/MarshalLoad

      expect(restored.policy_class_name).to be_nil
      expect(restored.record).to be_nil
      expect(restored.correlation_id).to eq headless.correlation_id
    end

    it "memoizes the placeholder policy class and restores the original name" do
      restored = Marshal.load(Marshal.dump(error)) # rubocop:disable Security/MarshalLoad
      placeholder = restored.policy

      expect(placeholder).to be_a described_class::PolicyClassPlaceholder
      expect(placeholder.klass).to equal placeholder.klass
      expect(placeholder.class).to equal placeholder.klass
      expect(placeholder.class.name).to eq "SyntheticSensitiveRecordPolicy"
    end

    it "returns nil from the placeholder factory for a missing name" do
      expect(described_class.policy_placeholder(nil)).to be_nil
    end
  end

  describe "realistic denials from two policies" do
    it "captures distinct policy and query data for each denial" do
      update_error = error
      destroy_error = described_class.new(
        query: :destroy?,
        record: sensitive_record,
        policy: other_policy_class.new(:user, sensitive_record)
      )

      expect(JSON.parse(update_error.to_json).values_at("policy_class", "query")).to eq(
        ["SyntheticSensitiveRecordPolicy", "update?"]
      )
      expect(JSON.parse(destroy_error.to_json).values_at("policy_class", "query")).to eq(
        ["AuditLogPolicy", "destroy?"]
      )
      expect(update_error.correlation_id).not_to eq destroy_error.correlation_id
    end
  end
end
