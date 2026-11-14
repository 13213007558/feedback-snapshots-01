# frozen_string_literal: true

# Current (old) production rules, replayed offline.
Rack::Attack::Replay.ruleset do |config|
  config.throttle("search/ip", limit: 3, period: 60) do |req|
    req.ip if req.path == "/search"
  end

  config.blocklist("admin/external") do |req|
    req.path.start_with?("/admin") && !req.ip.to_s.start_with?("10.")
  end

  config.blocklist("allow2ban/logins") do |req|
    Rack::Attack::Allow2Ban.filter("logins:#{req.ip}", maxretry: 3, findtime: 60, bantime: 300) do
      req.path == "/login" && req.params["result"] == "fail"
    end
  end
end
