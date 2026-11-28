# frozen_string_literal: true

require_relative "helper"
require "sidekiq/web"
require "rack/test"
require "rack/session"

# Help-only install of an extension: the mounter grants :menu and :assets
# but withholds :routes, so its operational endpoints (which need separate
# approval) are never mounted. registered() is not even called.
class HelpExt
  ROOT = File.expand_path("fixtures/helpext", __dir__)

  def self.registered(app)
    app.get "/helpext/status" do
      [200, {"content-type" => "text/plain"}, ["help status"]]
    end
    app.post "/helpext/purge" do
      [200, {"content-type" => "text/plain"}, ["purged"]]
    end
  end
end

# The full internal install of the same idea: menu, routes and assets,
# registered under the existing rules (default capabilities).
class OpsExt
  ROOT = File.expand_path("fixtures/opext", __dir__)

  def self.registered(app)
    app.get "/opext" do
      [200, {"content-type" => "text/plain"}, ["ops console"]]
    end
  end
end

# An extension whose registration fails halfway: it picks up a tab, locales
# and asset middleware from the config phase and mounts one route before
# blowing up. None of that may survive the failed registration.
class BrokenExt
  ROOT = File.expand_path("fixtures/brokenext", __dir__)

  def self.registered(app)
    app.get "/brokenext" do
      [200, {"content-type" => "text/plain"}, ["broken console"]]
    end
    raise "brokenext blew up during registration"
  end
end

describe Sidekiq::Web::Config do
  include Rack::Test::Methods

  def app
    @app ||= Rack::Lint.new(Sidekiq::Web.new)
  end

  before do
    @config = reset!
    env "HTTP_SEC_FETCH_SITE", "same-origin"

    Sidekiq::Web.configure do |c|
      c.middlewares.clear
      c.use Rack::Session::Cookie, secrets: "35c5108120cb479eecb4e947e423cad6da6f38327cf0ebb323e30816d74fa01f"
    end
  end

  # Probe every resource and the visible menu, returning a snapshot of
  # what the app actually exposes right now.
  def survey(resources)
    statuses = resources.to_h do |label, (verb, path)|
      public_send(verb, path)
      [label, last_response.status]
    end
    {statuses: statuses, menus: Sidekiq::Web.tabs.keys}
  end

  def print_survey(before, after)
    puts
    puts format("%-40s %6s %6s", "resource", "before", "after")
    before[:statuses].each_key do |label|
      puts format("%-40s %6s %6s", label, before[:statuses][label], after[:statuses][label])
    end
    puts "visible menus before: #{before[:menus].join(", ")}"
    puts "visible menus after:  #{after[:menus].join(", ")}"
  end

  it "lets the mounter scope each install and rolls back incomplete registrations" do
    Sidekiq::Web.configure do |cfg|
      # public install: help resources only, operational endpoints stay unmounted
      cfg.register_extension(HelpExt,
        name: "helpext",
        tab: "Help",
        index: "helpext/pages/guide.html",
        root_dir: HelpExt::ROOT,
        asset_paths: ["pages"],
        capabilities: %i[menu assets])

      # internal install: the full version, registered under the existing rules
      cfg.register_extension(OpsExt,
        name: "opext",
        tab: "Ops",
        index: "opext",
        root_dir: OpsExt::ROOT,
        asset_paths: ["css"])
    end

    resources = {
      "help guide (static asset)" => [:get, "/helpext/pages/guide.html"],
      "help status op (unapproved)" => [:get, "/helpext/status"],
      "help purge op (unapproved)" => [:post, "/helpext/purge"],
      "ops console (full install)" => [:get, "/opext"],
      "ops asset (full install)" => [:get, "/opext/css/ops.css"],
      "broken console (failed reg)" => [:get, "/brokenext"],
      "broken asset (failed reg)" => [:get, "/brokenext/css/broken.css"]
    }

    before_failure = survey(resources)

    ex = assert_raises(RuntimeError) do
      Sidekiq::Web.configure do |cfg|
        cfg.register_extension(BrokenExt,
          name: "brokenext",
          tab: "Broken",
          index: "brokenext",
          root_dir: BrokenExt::ROOT,
          asset_paths: ["css"])
      end
    end
    assert_equal "brokenext blew up during registration", ex.message

    # rebuild the Rack stack from the post-rollback configuration
    @app = nil
    after_failure = survey(resources)

    print_survey(before_failure, after_failure)

    # the failed registration was rolled back completely
    refute_includes Sidekiq::Web.tabs.keys, "Broken"
    refute Sidekiq::Web.locales.any? { |dir| dir.include?("brokenext") },
      "brokenext locales should be rolled back"
    refute Sidekiq::Web.middlewares.any? { |(args, _)| args.last[:urls] == ["/brokenext/css"] },
      "brokenext asset middleware should be rolled back"

    # and only that: both earlier installs are untouched by the failure
    assert_equal before_failure, after_failure
    assert_equal 200, after_failure[:statuses]["help guide (static asset)"]
    assert_equal 404, after_failure[:statuses]["help status op (unapproved)"]
    assert_equal 404, after_failure[:statuses]["help purge op (unapproved)"]
    assert_equal 200, after_failure[:statuses]["ops console (full install)"]
    assert_equal 200, after_failure[:statuses]["ops asset (full install)"]
    assert_equal 404, after_failure[:statuses]["broken console (failed reg)"]
    assert_equal 404, after_failure[:statuses]["broken asset (failed reg)"]
    assert_includes after_failure[:menus], "Help"
    assert_includes after_failure[:menus], "Ops"
    assert Sidekiq::Web.locales.any? { |dir| dir.include?("opext") },
      "full install locales should be loaded"
  end

  it "rejects unknown capabilities before changing anything" do
    err = assert_raises(ArgumentError) do
      Sidekiq::Web.configure do |cfg|
        cfg.register_extension(OpsExt,
          name: "nope",
          tab: "Nope",
          index: "nope",
          capabilities: %i[menu bogus])
      end
    end
    assert_match(/unknown extension capabilities/, err.message)
    refute_includes Sidekiq::Web.tabs.keys, "Nope"
  end
end
