# Rack::Protection

This gem protects against typical web attacks.
Should work for all Rack apps, including Rails.

# Usage

Use all protections you probably want to use:

``` ruby
# config.ru
require 'rack/protection'
use Rack::Protection
run MyApp
```

Skip a single protection middleware:

``` ruby
# config.ru
require 'rack/protection'
use Rack::Protection, :except => :path_traversal
run MyApp
```

Use a single protection middleware:

``` ruby
# config.ru
require 'rack/protection'
use Rack::Protection::AuthenticityToken
run MyApp
```


## More examples

Enable host authorization with an explicit allowlist:

``` ruby
# config.ru
require 'rack/protection'

use Rack::Protection::HostAuthorization,
  permitted_hosts: ['example.com', '.example.org']

run MyApp
```

Enable HTTPS-related headers in production only:

``` ruby
# config.ru
require 'rack/protection'

if ENV['RACK_ENV'] == 'production'
  use Rack::Protection::StrictTransport,
    max_age: 31_536_000, # 1 year
    include_subdomains: true
end

run MyApp
```

Customize CSP directives:

``` ruby
# config.ru
require 'rack/protection'

use Rack::Protection::ContentSecurityPolicy,
  default_src: "'self'",
  script_src: ["'self'", 'https://cdn.example.com']

run MyApp
```

Disable more than one protection middleware:

``` ruby
# config.ru
require 'rack/protection'

use Rack::Protection,
  except: [:path_traversal, :json_csrf]

run MyApp
```


# Prevented Attacks

## DNS rebinding and other Host header attacks

* [`Rack::Protection::HostAuthorization`][host-authorization] (not included by `use Rack::Protection`)

## Cross Site Request Forgery

Prevented by:

* [`Rack::Protection::AuthenticityToken`][authenticity-token] (not included by `use Rack::Protection`)
* [`Rack::Protection::FormToken`][form-token] (not included by `use Rack::Protection`)
* [`Rack::Protection::JsonCsrf`][json-csrf]
* [`Rack::Protection::RemoteReferrer`][remote-referrer] (not included by `use Rack::Protection`)
* [`Rack::Protection::RemoteToken`][remote-token]
* [`Rack::Protection::HttpOrigin`][http-origin]

## Cross Site Scripting

Prevented by:

* [`Rack::Protection::EscapedParams`][escaped-params] (not included by `use Rack::Protection`)
* [`Rack::Protection::XSSHeader`][xss-header] (Internet Explorer and Chrome only)
* [`Rack::Protection::ContentSecurityPolicy`][content-security-policy]

## Clickjacking

Prevented by:

* [`Rack::Protection::FrameOptions`][frame-options]

## Directory Traversal

Prevented by:

* [`Rack::Protection::PathTraversal`][path-traversal]

## Session Hijacking

Prevented by:

* [`Rack::Protection::SessionHijacking`][session-hijacking] (not included by `use Rack::Protection`)

By default the middleware tracks the user agent and empties the session when
it changes. For mobile clients, whose network traits legitimately change, a
graded mode is available that splits signals into two tiers:

```ruby
use Rack::Protection::SessionHijacking,
    identity_signals: [
      # Callables built from server-trusted data, e.g. a device token the
      # app issued at login. A mismatch drops the session. Plain header
      # names are refused here: client-forgeable headers must never be
      # used as identity credentials.
      ->(env) { Rack::Request.new(env).cookies['device_token'] }
    ],
    # Weak signals (headers or callables): a mismatch only moves the
    # session into the restricted state, the session is kept. The legacy
    # :track entries (default: the user agent) count as weak signals.
    weak_signals: %w[HTTP_X_NETWORK_HINT]
```

While restricted, the application must require re-authentication for
sensitive operations and then explicitly lift the restriction:

```ruby
def strongly_authenticated?(env)
  # restricted? == true  -> definitely require fresh credentials.
  # restricted? == false -> merely "no anomaly detected", never proof of
  # authentication on its own.
  env['rack.session'][:user_id] && !Rack::Protection::SessionHijacking.restricted?(env)
end

post '/reauthenticate' do
  halt 403 unless credentials_valid?(params) # verify fresh credentials FIRST
  Rack::Protection::SessionHijacking.confirm_reauthentication(env)
end
```

`confirm_reauthentication` is the only way the weak-signal baseline is
updated after the session was established, so attack requests cannot teach
the middleware new traits. On logout, account switch or session restore,
rebuild the baseline with `Rack::Protection::SessionHijacking.reset_tracking(env)`
or `Rack::Protection::SessionHijacking.rebaseline(env)`. Set
`weak_reaction: :drop_session` (or omit the graded options) to keep the old
"clear the whole session" behaviour. See
`examples/session_hijacking.ru` for a runnable demo of a normal mobile
scenario versus a copied-session scenario.

## Cookie Tossing

Prevented by:

* [`Rack::Protection::CookieTossing`][cookie-tossing] (not included by `use Rack::Protection`)

## IP Spoofing

Prevented by:

* [`Rack::Protection::IPSpoofing`][ip-spoofing]

## Helps to protect against protocol downgrade attacks and cookie hijacking

Prevented by:

* [`Rack::Protection::StrictTransport`][strict-transport] (not included by `use Rack::Protection`)

# Installation

    gem install rack-protection

# Instrumentation

Instrumentation is enabled by passing in an instrumenter as an option.

```
use Rack::Protection, instrumenter: ActiveSupport::Notifications
```

The instrumenter is passed a namespace (String) and environment (Hash). The namespace is 'rack.protection' and the attack type can be obtained from the environment key 'rack.protection.attack'.

[authenticity-token]: http://www.sinatrarb.com/protection/authenticity_token
[content-security-policy]: http://www.sinatrarb.com/protection/content_security_policy
[cookie-tossing]: http://www.sinatrarb.com/protection/cookie_tossing
[escaped-params]: http://www.sinatrarb.com/protection/escaped_params
[form-token]: http://www.sinatrarb.com/protection/form_token
[frame-options]: http://www.sinatrarb.com/protection/frame_options
[host-authorization]: https://github.com/sinatra/sinatra/blob/main/rack-protection/lib/rack/protection/host_authorization.rb
[http-origin]: http://www.sinatrarb.com/protection/http_origin
[ip-spoofing]: http://www.sinatrarb.com/protection/ip_spoofing
[json-csrf]: http://www.sinatrarb.com/protection/json_csrf
[path-traversal]: http://www.sinatrarb.com/protection/path_traversal
[remote-referrer]: http://www.sinatrarb.com/protection/remote_referrer
[remote-token]: http://www.sinatrarb.com/protection/remote_token
[session-hijacking]: http://www.sinatrarb.com/protection/session_hijacking
[strict-transport]: http://www.sinatrarb.com/protection/strict_transport
[xss-header]: http://www.sinatrarb.com/protection/xss_header
