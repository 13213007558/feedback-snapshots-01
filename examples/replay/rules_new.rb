# frozen_string_literal: true

# Candidate (new) rules: tightened search throttle, dropped the admin
# blocklist, added a user-agent based throttle for the API feed.
Rack::Attack::Replay.ruleset do |config|
  config.throttle("search/ip", limit: 2, period: 60) do |req|
    req.ip if req.path == "/search"
  end

  config.throttle("api/agent", limit: 5, period: 60) do |req|
    req.user_agent if req.path == "/api/feed"
  end

  config.blocklist("allow2ban/logins") do |req|
    Rack::Attack::Allow2Ban.filter("logins:#{req.ip}", maxretry: 3, findtime: 60, bantime: 300) do
      req.path == "/login" && req.params["result"] == "fail"
    end
  end
end
