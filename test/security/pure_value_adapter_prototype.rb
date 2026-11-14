# frozen_string_literal: true

require 'date'
require 'time'

module LiquidSecurityPrototype
  class RejectedValue < StandardError; end
  class AdapterContractError < StandardError; end

  module PureValue
    module_function

    def call(value, seen = {})
      case value
      when nil, true, false, String, Numeric
        value
      when Symbol
        value.to_s
      when Time, DateTime, Date
        value
      when Array
        raise RejectedValue, 'cyclic array' if seen[value.object_id]

        seen[value.object_id] = true
        value.map { |item| call(item, seen) }
      when Hash
        raise RejectedValue, 'cyclic hash' if seen[value.object_id]

        seen[value.object_id] = true
        value.each_with_object({}) do |(key, item), result|
          unless key.is_a?(String) || key.is_a?(Symbol)
            raise RejectedValue, "non-string hash key: #{key.class}"
          end

          result[key.to_s] = call(item, seen)
        end
      else
        raise RejectedValue, "no pure-value adapter for #{value.class}"
      end
    ensure
      seen.delete(value.object_id) if value.is_a?(Array) || value.is_a?(Hash)
    end
  end

  class BusinessObject
    attr_reader :name, :status, :tags, :updated_at

    def initialize(name:, status:, tags:, updated_at:)
      @name = name
      @status = status
      @tags = tags
      @updated_at = updated_at
    end

    def delete_all
      :deleted
    end

    def secret_token
      's3cr3t'
    end
  end

  class BusinessRefAdapter < Liquid::Drop
    ALLOWED_METHODS = %w(name status tags updated_at to_s to_liquid).freeze

    def initialize(object)
      super()
      verify_contract!(object)
      @object = object
    end

    def name
      PureValue.call(@object.name)
    end

    def status
      PureValue.call(@object.status)
    end

    def tags
      PureValue.call(@object.tags)
    end

    def updated_at
      PureValue.call(@object.updated_at)
    end

    def to_s
      PureValue.call(@object.name)
    end

    private

    def verify_contract!(_object)
      invokable = self.class.invokable_methods
      extra = invokable - ALLOWED_METHODS
      return if extra.empty?

      raise AdapterContractError, "adapter leaked invokable methods: #{extra.to_a.inspect}"
    end
  end

  module Fixture
    module_function

    def object
      BusinessObject.new(
        name: 'acme',
        status: 'active',
        tags: %w[alpha beta],
        updated_at: Time.utc(2026, 11, 14, 12, 0, 0),
      )
    end

    def snapshot
      PureValue.call(
        'name' => 'acme',
        'status' => 'active',
        'tags' => %w[alpha beta],
        'updated_at' => Time.utc(2026, 11, 14, 12, 0, 0),
      )
    end

    def assigns
      object = object()
      { 'settings' => snapshot, 'audit' => BusinessRefAdapter.new(object) }
    end

    def view
      snapshot.merge('audit' => BusinessRefAdapter.new(object()))
    end
  end
end
