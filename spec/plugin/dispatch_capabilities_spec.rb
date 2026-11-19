require_relative "../spec_helper"

describe "dispatch_capabilities plugin" do
  def inner_app(seen=nil, &block)
    Class.new(Roda) do
      plugin :dispatch_capabilities

      route do |r|
        seen << r.capabilities if seen
        instance_exec(r, &block) if block
        "caps:#{r.capabilities.to_a.join(',')}"
      end
    end.app
  end

  it "grants read-only capabilities to the downstream app for the duration of the dispatch" do
    seen = []
    inner = inner_app(seen)

    app(:dispatch_capabilities) do |r|
      r.on "grant" do
        r.run_with_capabilities inner, [:read_reports, "export"]
      end
      "fallback caps:#{r.capabilities.to_a.join(',')}"
    end

    env = {}
    body("/grant", env).must_equal "caps:read_reports,export"
    env.key?("roda.capabilities").must_equal false

    granted = seen.last
    granted.must_be :frozen?
    granted.to_a.must_be :frozen?
    granted.allows?(:read_reports).must_equal true
    granted.allows?(:export).must_equal true
    granted.allows?(:delete_reports).must_equal false
    proc{granted.to_a << :delete_reports}.must_raise FrozenError

    env = {}
    body("/other", env).must_equal "fallback caps:"
    env.key?("roda.capabilities").must_equal false
  end

  it "restores the previous capabilities when the downstream app raises" do
    inner = inner_app do |r|
      raise "downstream failure"
    end

    app(:dispatch_capabilities) do |r|
      begin
        r.run_with_capabilities inner, [:read_reports]
      rescue RuntimeError
        "rescued caps:#{r.capabilities.to_a.join(',')}"
      end
    end

    env = {}
    body("/grant", env).must_equal "rescued caps:"
    env.key?("roda.capabilities").must_equal false
  end

  it "restores capabilities granted by an enclosing scope" do
    seen = []
    inner = inner_app(seen)

    app(:dispatch_capabilities) do |r|
      r.with_capabilities([:outer]) do
        r.with_capabilities([:inner]) do
          inner.call(r.env)
        end
        "after inner:#{r.capabilities.to_a.join(',')}"
      end
    end

    body.must_equal "after inner:outer"
    seen.last.to_a.must_equal [:inner]
  end

  it "defaults to no capabilities when the downstream app is accessed directly" do
    seen = []
    @app = inner_app(seen) do |r|
      r.on "check" do
        "empty:#{r.capabilities.empty?} allows:#{r.capabilities.allows?(:read_reports)}"
      end
    end

    body.must_equal "caps:"
    body("/check").must_equal "empty:true allows:false"
    seen.each{|capabilities| capabilities.must_be :empty?}
  end
end
