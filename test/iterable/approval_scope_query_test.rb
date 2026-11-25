# frozen_string_literal: true

require_relative "../helper"
require "sidekiq/api"

describe "IterableJobQuery approval diagnostics" do
  it "exposes the redacted diagnostics blob without a cursor" do
    # State is built from a raw Redis hash, so the coercion exercised by the
    # web UI is the same as the one exercised here.
    raw = {
      "ex" => "3",
      "c" => "null",
      "sd" => "0123456789abffff",
      "diag" => Sidekiq.dump_json({
        "v" => "1",
        "scope" => "0123456789ab",
        "processed" => 5,
        "iterations" => 5,
        "committed" => 4,
        "recovered" => 1,
        "revoked" => 2,
        "reason" => "scope_changed"
      })
    }
    state = Sidekiq::IterableJobQuery::State.new("diagnostic-jid", raw)

    assert_equal "0123456789ab", state.scope
    assert_equal "scope_changed", state.reason
    assert_equal 5, state.processed
    assert_equal 1, state.recovered
    assert_equal 5, state.iterations
    assert_equal 4, state.committed
    refute state.diagnostics.key?("cursor")
  end

  it "returns nil diagnostics for legacy state" do
    state = Sidekiq::IterableJobQuery::State.new("legacy", {"c" => "2", "ex" => "1"})
    assert_nil state.diagnostics
    assert_nil state.scope
    assert_nil state.reason
    assert_nil state.iterations
  end

  it "returns nil for unreadable diagnostics" do
    state = Sidekiq::IterableJobQuery::State.new("broken", {"c" => "2", "diag" => "not-json"})
    assert_nil state.diagnostics
  end
end
