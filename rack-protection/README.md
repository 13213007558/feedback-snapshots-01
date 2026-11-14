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

### Per-form authenticity tokens

`AuthenticityToken.token(session, path:, method:)` issues a token bound to a
single action identifier of the form `"<path>#<method>"`. A per-form token is
only accepted when the request is verified against the same identifier; it can
never be replayed against a different path or method. A token issued without a
path/method remains the legacy *global* token, which is intentionally
path- and method-agnostic, and the two are never interchangeable.

The path and method are canonicalized identically at issue and verify time
(`canonical_form_identifier`): the HTTP method is compared case-insensitively
and a single trailing slash is ignored, so `"/foo"` and `"/foo/"` describe the
same action. Everything else is significant. To keep issue and verify in sync:

* **Mount prefix:** sign with the mount-aware path the app actually sees.
  `Rack::Request#path` is `SCRIPT_NAME + PATH_INFO`, so an app mounted under
  `/app` must sign `"/app/foo"`, not just `"/foo"`.
* **Percent-encoding:** sign the raw, encoded spelling. `Request#path` keeps
  percent-encoding (e.g. `"/foo%20bar"`, `"/foo%2Fbar"`); a decoded path at
  issue time is a different identifier and is rejected. An encoded slash
  (`%2F`) never acts as a path separator.
* **Method override:** place `Rack::MethodOverride` *before*
  `AuthenticityToken` in the stack. Then protection sees the overridden method
  (e.g. a browser `POST` carrying `_method=put` is evaluated as `PUT`), and the
  form should be signed with `method: :put`. If the override middleware runs
  after protection, protection sees the original `POST` instead.

Mismatches in any of these dimensions fail closed with a `403` rather than
collapsing two distinct actions into one.

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
