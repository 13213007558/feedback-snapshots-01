# frozen_string_literal: true

# NB: `req` is a Rack::Request object (basically an env hash with friendly accessor methods)

# Throttle 10 requests/ip/second
# NB: return value of block is key name for counter
#     falsy values bypass throttling
Rack::Attack.throttle("req/ip", limit: 10, period: 1) { |req| req.ip }

# Throttle attempts to a particular path. 2 POSTs to /login per second per IP
Rack::Attack.throttle "logins/ip", limit: 2, period: 1 do |req|
  req.post? && req.path == "/login" && req.ip
end

# Throttle login attempts per email, 10/minute/email
# Normalize the email, using the same logic as your authentication process, to
# protect against rate limit bypasses.
Rack::Attack.throttle "logins/email", limit: 2, period: 60 do |req|
  req.post? && req.path == "/login" && req.params['email'].to_s.downcase.gsub(/\s+/, "")
end

# Response-based credential-stuffing protection. Unlike the entry-time throttle
# above, this only records an attempt once the login endpoint has responded:
# 401s accumulate per account, a 200 clears the failures that predated it, and
# 5 failures inside 15 minutes bans the account for an hour. The classifier
# sees only method/path/ip/agent + status/headers (never the password or body).
Rack::Attack.account_guard "logins/account", maxretry: 5, findtime: 15 * 60, bantime: 60 * 60,
                           classifier: ->(result) { result.status == 401 ? :failure : :success } do |req|
  req.post? && req.path == "/login" && req.params['email'].to_s.downcase.gsub(/\s+/, "")
end

# blocklist bad IPs from accessing admin pages
Rack::Attack.blocklist "bad_ips from logging in" do |req|
  req.path =~ /^\/admin/ && bad_ips.include?(req.ip)
end

# safelist a User-Agent
Rack::Attack.safelist 'internal user agent' do |req|
  req.user_agent == 'InternalUserAgent'
end
