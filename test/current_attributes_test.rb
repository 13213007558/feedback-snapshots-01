# frozen_string_literal: true

require_relative "helper"
require "sidekiq/middleware/current_attributes"

module Myapp
  class Current < ActiveSupport::CurrentAttributes
    attribute :user_id, :tenant_id, :org_id, :request_id, :secret
  end

  class OtherCurrent < ActiveSupport::CurrentAttributes
    attribute :other_id
  end
end

class CurrentAttributesJob
  include Sidekiq::Job

  def perform
  end
end

Serializer = ActiveJob::Arguments

class TestCurrentAttributes < Minitest::Test
  def setup
    @config = reset!
  end

  def run
    # Rails reloader auto-clears context
    Rails.application.reloader.wrap { super }
  end

  def test_saves
    cm = Sidekiq::CurrentAttributes::Save.new({
      "cattr" => "Myapp::Current",
      "cattr_1" => "Myapp::OtherCurrent"
    })
    job = {}
    with_context("Myapp::Current", "user_id", 123) do
      with_context("Myapp::OtherCurrent", "other_id", 789) do
        cm.call(nil, job, nil, nil) do
          assert_equal 123, Serializer.deserialize(job["cattr"]).to_h[:user_id]
          assert_equal 789, Serializer.deserialize(job["cattr_1"]).to_h[:other_id]
        end
      end
    end

    with_context("Myapp::Current", :user_id, 456) do
      with_context("Myapp::OtherCurrent", :other_id, 999) do
        cm.call(nil, job, nil, nil) do
          assert_equal 123, Serializer.deserialize(job["cattr"]).to_h[:user_id]
          assert_equal 789, Serializer.deserialize(job["cattr_1"]).to_h[:other_id]
        end
      end
    end
  end

  def test_loads
    cm = Sidekiq::CurrentAttributes::Load.new({
      "cattr" => "Myapp::Current",
      "cattr_1" => "Myapp::OtherCurrent"
    })

    job = {"cattr" => {"user_id" => 123}, "cattr_1" => {"other_id" => 456}}
    assert_nil Myapp::Current.user_id
    assert_nil Myapp::OtherCurrent.other_id
    cm.call(nil, job, nil) do
      assert_equal 123, Myapp::Current.user_id
      assert_equal 456, Myapp::OtherCurrent.other_id
    end
    # the Rails reloader is responsible for resetting Current after every unit of work
  end

  def test_persists_with_class_argument
    Sidekiq::CurrentAttributes.persist("Myapp::Current", @config)
    job_hash = {}
    with_context("Myapp::Current", :user_id, 16) do
      @config.client_middleware.invoke(nil, job_hash, nil, nil) do
        assert_equal 16, Serializer.deserialize(job_hash["cattr"]).to_h[:user_id]
      end
    end

    #   assert_nil Myapp::Current.user_id
    #   Sidekiq.server_middleware.invoke(nil, job_hash, nil) do
    #     assert_equal 16, job_hash["cattr"][:user_id]
    #     assert_equal 16, Myapp::Current.user_id
    #   end
    #   assert_nil Myapp::Current.user_id
    # ensure
    #   Sidekiq.client_middleware.clear
    #   Sidekiq.server_middleware.clear
  end

  def test_persists_with_hash_argument
    cattrs = [Myapp::Current, "Myapp::OtherCurrent"]
    Sidekiq::CurrentAttributes.persist(cattrs, @config)
    job_hash = {}
    with_context("Myapp::Current", :user_id, 16) do
      with_context("Myapp::OtherCurrent", :other_id, 17) do
        @config.client_middleware.invoke(nil, job_hash, nil, nil) do
          assert_equal 16, Serializer.deserialize(job_hash["cattr"]).to_h[:user_id]
          assert_equal 17, Serializer.deserialize(job_hash["cattr_1"]).to_h[:other_id]
        end
      end
    end
  end

  def test_persists_after_perform_inline
    Sidekiq::CurrentAttributes.persist("Myapp::Current", @config)
    with_context("Myapp::Current", :user_id, 16) do
      assert_equal 16, Myapp::Current.user_id
      CurrentAttributesJob.perform_inline
      assert_equal 16, Myapp::Current.user_id
    end
  end

  def test_ignores_nonexistent_attributes
    cm = Sidekiq::CurrentAttributes::Load.new({
      "cattr" => "Myapp::Current"
    })

    job = {"cattr" => {"user_id" => 123, "non_existent" => 456}}
    assert_nil Myapp::Current.user_id
    cm.call(nil, job, nil) do
      assert_equal 123, Myapp::Current.user_id
    end
  end

  def test_doesnt_swallow_errors_raised_in_the_job
    cm = Sidekiq::CurrentAttributes::Load.new({
      "cattr" => "Myapp::Current"
    })

    job = {"cattr" => {"user_id" => 123}}
    assert_raises do
      first_time = true
      cm.call(nil, job, nil) do
        if first_time
          first_time = false
          raise nil.this_method_is_undefined
        end
      end
    end
  end

  def test_save_only_persists_allowlisted_attributes
    cm = Sidekiq::CurrentAttributes::Save.new({
      "cattr" => ["Myapp::Current", [:tenant_id, :request_id]]
    })
    job = {}
    with_context("Myapp::Current", :tenant_id, 42) do
      with_context("Myapp::Current", :request_id, "req-1") do
        with_context("Myapp::Current", :secret, "do-not-persist") do
          cm.call(nil, job, nil, nil) do
            persisted = Serializer.deserialize(job["cattr"]).to_h
            assert_equal 42, persisted[:tenant_id]
            assert_equal "req-1", persisted[:request_id]
            refute persisted.key?(:secret)
            refute job["cattr"].include?("do-not-persist")
          end
        end
      end
    end
  end

  def test_save_with_empty_allowlist_persists_nothing
    cm = Sidekiq::CurrentAttributes::Save.new({
      "cattr" => ["Myapp::Current", []]
    })
    job = {}
    with_context("Myapp::Current", :user_id, 123) do
      cm.call(nil, job, nil, nil) do
        refute job.has_key?("cattr")
      end
    end
  end

  def test_save_accepts_string_attribute_names_in_allowlist
    Sidekiq::CurrentAttributes.persist(
      {"Myapp::Current" => ["tenant_id", "request_id"]},
      @config
    )
    job_hash = {}
    with_context("Myapp::Current", :tenant_id, 3) do
      with_context("Myapp::Current", :request_id, "req-s") do
        with_context("Myapp::Current", :secret, "hidden") do
          @config.client_middleware.invoke(nil, job_hash, nil, nil) {}
        end
      end
    end

    persisted = Serializer.deserialize(job_hash["cattr"]).to_h
    assert_equal 3, persisted[:tenant_id]
    assert_equal "req-s", persisted[:request_id]
    refute persisted.key?(:secret)
  end

  def test_load_with_empty_allowlist_restores_nothing
    cm = Sidekiq::CurrentAttributes::Load.new({
      "cattr" => ["Myapp::Current", []]
    })

    Myapp::Current.reset
    job = {"cattr" => {"user_id" => 123, "tenant_id" => 4}}
    cm.call(nil, job, nil) do
      assert_nil Myapp::Current.user_id
      assert_nil Myapp::Current.tenant_id
    end
  end

  def test_load_only_restores_allowlisted_attributes
    cm = Sidekiq::CurrentAttributes::Load.new({
      "cattr" => ["Myapp::Current", [:tenant_id, :request_id]]
    })

    # payload as produced by an older, broader policy
    job = {"cattr" => {"tenant_id" => 7, "request_id" => "req-2", "secret" => "leak"}}
    cm.call(nil, job, nil) do
      assert_equal 7, Myapp::Current.tenant_id
      assert_equal "req-2", Myapp::Current.request_id
      assert_nil Myapp::Current.secret
      assert_nil Myapp::Current.user_id
    end
  end

  def test_load_filters_when_policy_narrows_between_executions
    broad = Sidekiq::CurrentAttributes::Save.new({
      "cattr" => ["Myapp::Current", [:tenant_id, :org_id, :request_id, :secret]]
    })
    job = {}
    with_context("Myapp::Current", :tenant_id, 9) do
      with_context("Myapp::Current", :org_id, 55) do
        with_context("Myapp::Current", :request_id, "req-3") do
          with_context("Myapp::Current", :secret, "topsecret") do
            broad.call(nil, job, nil, nil) {}
          end
        end
      end
    end

    # the persisted message still carries the old, broader payload
    persisted = Serializer.deserialize(job["cattr"]).to_h
    assert_equal "topsecret", persisted[:secret]

    # a worker thread starts each unit of work with a clean context (the Rails
    # reloader resets CurrentAttributes), then restores only the job payload
    Myapp::Current.reset

    # policy change before the retry: only two attributes remain approved
    narrow = Sidekiq::CurrentAttributes::Load.new({
      "cattr" => ["Myapp::Current", [:tenant_id, :request_id]]
    })
    narrow.call(nil, job, nil) do
      assert_equal 9, Myapp::Current.tenant_id
      assert_equal "req-3", Myapp::Current.request_id
      assert_nil Myapp::Current.org_id
      assert_nil Myapp::Current.secret
    end
  end

  def test_load_accepts_legacy_string_cattrs_value
    cm = Sidekiq::CurrentAttributes::Load.new({
      "cattr" => "Myapp::Current"
    })

    job = {"cattr" => {"user_id" => 123, "tenant_id" => 4}}
    cm.call(nil, job, nil) do
      assert_equal 123, Myapp::Current.user_id
      assert_equal 4, Myapp::Current.tenant_id
    end
  end

  def test_persist_with_hash_argument_builds_allowlisted_cattrs
    Sidekiq::CurrentAttributes.persist(
      {"Myapp::Current" => ["tenant_id", :request_id], "Myapp::OtherCurrent" => nil},
      @config
    )
    assert_equal(
      {"cattr" => ["Myapp::Current", [:tenant_id, :request_id]],
       "cattr_1" => ["Myapp::OtherCurrent", nil]},
      @config.client_middleware.entries.first.instance_variable_get(:@args).first
    )
  end

  def test_persist_with_array_of_pairs_builds_allowlisted_cattrs
    Sidekiq::CurrentAttributes.persist(
      [["Myapp::Current", [:tenant_id]], "Myapp::OtherCurrent"],
      @config
    )
    assert_equal(
      {"cattr" => ["Myapp::Current", [:tenant_id]],
       "cattr_1" => ["Myapp::OtherCurrent", nil]},
      @config.client_middleware.entries.first.instance_variable_get(:@args).first
    )
  end

  def test_persist_round_trip_through_middleware_chain
    Sidekiq::CurrentAttributes.persist(
      {"Myapp::Current" => [:tenant_id, :request_id]},
      @config
    )
    job_hash = {}
    with_context("Myapp::Current", :tenant_id, 88) do
      with_context("Myapp::Current", :request_id, "req-4") do
        with_context("Myapp::Current", :secret, "hidden") do
          @config.client_middleware.invoke(nil, job_hash, nil, nil) {}
        end
      end
    end

    persisted = Serializer.deserialize(job_hash["cattr"]).to_h
    refute persisted.key?(:secret)

    # the worker thread starts from a clean context and restores only the
    # fields allowed by the policy from the persisted job message
    Myapp::Current.reset
    @config.server_middleware.invoke(nil, job_hash, nil) do
      assert_equal 88, Myapp::Current.tenant_id
      assert_equal "req-4", Myapp::Current.request_id
      assert_nil Myapp::Current.secret
    end
  end

  private

  def with_context(strklass, attr, value)
    constklass = strklass.constantize
    constklass.send(:"#{attr}=", value)
    yield
  end
end
