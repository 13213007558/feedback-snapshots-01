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

# Rejections decided from the response

Most protections decide before calling the application. `Rack::Protection::JsonCsrf`,
however, can only decide after it has seen the application's `content-type` header.
Such protections use `Rack::Protection::Base#check_response` (or
`#reject_response`) so that every response-dependent rejection follows the same
lifecycle:

* The rejection decision and the configured reaction each run once.
* `reaction: :report` keeps the original response, sets `protection.failed` in
  `env`, and leaves the body for the server to consume and close.
* Any other reaction must return a Rack response triple. The original body is
  then closed exactly once and is never iterated.
* A reaction returning `nil` (including side-effect reactions such as
  `:drop_session`) falls back to the standard denial response, preserving the
  fail-closed behavior of `JsonCsrf`.
* A reaction returning a non-`nil`, non-Rack value raises
  `Rack::Protection::Base::ResponseReactionError`.
* Exceptions while deciding, reacting, instrumenting, or closing are contained:
  an existing rejection never becomes a pass-through. A close failure is logged
  and the replacement response is still returned.

This works for both enumerable bodies (`#each`) and streaming/callable bodies
(`#call`), and for bodies that raise from `#close`.

## Responsibility split

The protection layer owns the decision and the ownership transfer: it invokes
the reaction once, records a report finding, closes a body it replaces exactly
once, and never iterates it. It must return a valid Rack triple (or preserve the
original under `:report`).

The Rack server owns the response it receives: it iterates an enumerable body or
invokes a callable body, closes that body after sending, and suppresses or
propagates exceptions from the network and from body iteration. A body kept by
`:report` therefore remains the server's responsibility to consume and close.

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
