# JsonCsrf threat-model lab

Offline Rack experiments for `Rack::Protection::JsonCsrf` (rack-protection 4.2.1) in the
`sinatra/sinatra` checkout. No network access is required.

Run:

```sh
./security/json-csrf-lab/run.sh
```

The harness builds its own Rack apps, session cookie, token, and instrumentation. It writes
`results/latest.json` and `results/latest.md`, then exits non-zero if any expectation in the matrix
does not match. Run from the repository root so the pinned `.feedback` bundle is used.

## What is modeled

Three separate risks, deliberately not merged:

1. **Cross-site read.** The attacker wants the JSON body of a victim-authenticated response,
   either by embedding it as a script (classic array/JSON hijacking) or by reading it with CORS
   or another browser primitive. JsonCsrf's `has_vector?` is a response-side, content-type-gated
   heuristic aimed at this class.
2. **Cross-site write.** The attacker causes a state change with victim credentials. The status
   code the victim sees is irrelevant here; the server-side effect is what matters.
3. **Navigation.** A top-level cross-site load of a URL is not the same primitive as a cross-site
   `fetch()`/`XHR`, and it is not a write merely because it is cross-site. A navigation can still
   leak data through a misconfigured CORS policy or through a side-effecting GET.

The experiment records, for each request: response status, response body actually delivered,
whether the application was called, whether the application committed a side effect, whether the
body was enumerated (`body_each`) or closed (`body_close`), whether the request was authenticated,
the `protection.failed` flag, and instrumentation events.

That separation matters because `JsonCsrf` calls the application first and evaluates the response
afterwards. A `403` in the log is therefore not evidence that the business write never happened.

## Source-chain summary

`JsonCsrf#call` (`rack-protection/lib/rack/protection/json_csrf.rb:26`) is:

```ruby
status, headers, body = app.call(env)
if has_vector?(request, headers)
  react_and_close(env, body) or [status, headers, body]
else
  [status, headers, body]
end
```

`has_vector?` (`:39`) returns false, in order, when:

- `request.xhr?` is true, which in Rack 3.2.8 is only an exact
  `HTTP_X_REQUESTED_WITH == "XMLHttpRequest"` check (`rack/request.rb:318`);
- `options[:allow_if]` returns true (evaluated *after* the app already ran);
- the response `content-type` is not exactly `application/json` after stripping parameters;
- an Origin or `X-Origin` header is present (`origin(env)` in `base.rb:152`); or
- the Referer host equals the request host.

If those all fail, `react_and_close` (`:47`) calls `react`, closes the response body, and returns
the denial. `JsonCsrf` aliases `react` to `deny` at class-definition time (`:24`), so
`reaction: :report` and `reaction: :drop_session` do not affect it. The alias also bypasses
`Base#instrument`, so `rack.protection.attack` is not set for a JsonCsrf denial.

`Base#referrer` (`base.rb:144`) falls back to the request host when `HTTP_REFERER` is missing or
unparsable, unless `allow_empty_referrer: false`. That is why a missing Referer looks same-origin
to `JsonCsrf`. A present Origin header short-circuits `JsonCsrf` entirely, regardless of its value;
`JsonCsrf` does not itself compare Origins, despite its comment claiming it "defers to HttpOrigin".

`HttpOrigin` (`http_origin.rb:52`) is the opposite shape: it is a pre-application check, skips safe
methods, accepts when no Origin is present, and byte-compares `base_url(env)` or
`permitted_origins`. Its `default_reaction :deny` is a normal `Base` reaction, so `:report`,
`:drop_session`, and instrumentation do work there.

## Baseline results (all offline, 73 scenarios)

Reads, `JsonCsrf` alone:

- Cross-host Referer: `403`, app called, body closed without enumeration (`R02`).
- No Referer or empty Referer: `200` with the JSON body (`R03`, `R04`); `referrer` substitutes
  `HTTP_HOST`. Strict `allow_empty_referrer: false` turns this into a `403` after the app ran (`R16`).
- `X-Requested-With: XMLHttpRequest`: `200` (`R05`). Lowercase `xmlhttprequest` is not `xhr?` and stays
  `403` (`R20`).
- Any Origin, including `https://evil.example`, `X-Origin`, `null`, or empty string: `200` (`R06`,
  `R07`, `R15`, `R19`, `R21`, `R22`).
- `application/vnd.api+json`, `text/html`, missing Content-Type, or a capitalized `Content-Type`
  response header: not matched, `200` (`R10`–`R13`).
- A CORS endpoint that reflects the evil Origin with credentials: `200` and the reflected
  `access-control-allow-origin`/`access-control-allow-credentials` headers survive (`R14`, also
  through the umbrella stack in `R18`).

Writes, `JsonCsrf` alone (the application runs first):

- Eager commit with cross-host Referer: `403` but `writes=1` (`W01`); with a valid session and
  auth cookie: `403` but authenticated `writes=1` (`W04`). A valid CSRF token does not stop the
  downstream `JsonCsrf` response check from replacing the response after the write (`W32`).
- Eager commit with no Referer: `200` and `writes=1` (`W02`); authenticated equivalent `W05`.
- Eager commit with evil Origin, `null` Origin, empty Origin, or `X-Origin`: `200` and `writes=1`
  (`W03`, `W27`, `W28`, `W41`, `W42`).
- Streaming body whose write happens inside `each`: `403`, `writes=0`, body never enumerated (`W06`).
- Body whose cleanup performs the write: `403`, `writes=1`, body closed (`W07`). This is the
  "close is not free" case.
- HTML/204 responses: no content-type match, so `200`/`204` and `writes=1` (`W08`, `W09`).
- `reaction: :report`: still `403`, and `protection.failed` stays unset because the alias ignores
  the option (`W10`).
- `reaction: :drop_session`: still `403`, session not cleared, `writes=1` (`W11`).
- `allow_if: ->(_env) { true }`: `200`, `writes=1`; it is evaluated after the app (`W34`).
- A state-changing GET is also checked only after the app: cross-host Referer `403` with
  `writes=1` (`W38`); same-host or missing Referer `200` with `writes=1` (`W43`, `W44`). Evil
  Origin on a GET is accepted (`W45`).

Umbrella stack (`Rack::Protection.new`, default middleware order `http_origin` then `json_csrf`
then `remote_token`):

- Evil Origin unsafe request: `403` before the app, `app_calls=0`, no write (`W12`).
- Evil Referer with no Origin: `HttpOrigin` passes (no Origin). `JsonCsrf` is outside
  `RemoteToken`, so `RemoteToken` runs first inside the downstream chain; it denies the bad
  Referer before the business app (`app_calls=0`, `W13`). In report mode `RemoteToken` passes, the
  app writes, and `JsonCsrf` denies the JSON response (`403`, `writes=1`, `W16`).
- No Origin and no Referer: `HttpOrigin` passes, `RemoteToken` falls back to the host, `JsonCsrf`
  passes; `200` with `writes=1` (`W14`).
- Report mode with evil Origin: `HttpOrigin` records the attack and passes; `JsonCsrf` sees the
  Origin header, so it runs the app and returns the JSON `200` with `writes=1` and the flag set
  (`W15`). There is no denial, only a report.
- Report mode with evil Referer and no Origin: `JsonCsrf` wraps `RemoteToken`; `RemoteToken`
  records and lets the app run, then the JSON response comes back and `JsonCsrf` replaces it, so
  the result is `403` with `writes=1` and the flag set (`W16`).
- `drop_session` with a session: `HttpOrigin` clears the session and returns `nil` (so no denial
  tuple), `JsonCsrf`/the app continue; an authenticated endpoint that re-checks the session then
  sees `401` after already entering the app (`W40`), while a non-session-gated write succeeds
  (`W33`).
- Sinatra's `setup_protection` defaults to `reaction: :drop_session` and `without_session: true`
  when sessions are off (`lib/sinatra/base.rb:1868-1873`). With no session, `drop_session` is a
  no-op and returns `nil`; `HttpOrigin` therefore does not block, and a silent evil-Origin write
  succeeds (`W35`).
- `X-Origin: https://evil.example` with no Referer: `HttpOrigin` only reads `HTTP_ORIGIN`, so it
  passes; `JsonCsrf` treats any Origin as authoritative and passes; `200` with `writes=1`
  (`W27`, `W28`).

Token and origin alternatives, for comparison:

- `AuthenticityToken` denies before the app (`app_calls=0`) when the token is absent (`W20`) and
  allows a valid token (`W21`).
- `FormToken` skips the token for `X-Requested-With: XMLHttpRequest` (`W22`): a header-only bypass,
  exactly the reason not to treat a custom header as proof of a trusted browser.
- `RemoteToken` allows a missing Referer by host fallback (`W23`) and an evil Origin with a missing
  Referer (`W25`), but denies an evil Referer before the app (`W24`).
- A strict pre-app Origin allowlist denies evil Origin and missing Origin without calling the
  application (`W17`, `W18`) and allows same Origin (`W19`).
- `HttpOrigin` alone allows a missing Origin and a bad Referer (`W36`, `W39`), and allows an evil
  Referer when the Origin is same-host (`W31`). The umbrella stack's `RemoteToken` is what denies
  that last combination before the app (`W30`).

Navigation:

- A top-level cross-site GET with a cross-host Referer is denied after the app ran (`N01`).
- A top-level navigation without Referer passes (`N02`).
- A top-level cross-site form POST is denied after the write (`N03`), and without Referer it passes
  and writes (`N04`). These are navigation cases; they are not the same as an attacker reading a
  response cross-origin, and the write outcome is independent of the navigation label.

Diagnostics:

- `JsonCsrf` denial produces no instrumentation event because the alias bypasses `Base#instrument`
  (`D01`).
- `HttpOrigin` denial produces `rack.protection` = `httporigin` (`D02`).

## What each layer can and cannot do

**Must happen before the application call** if it is to prevent side effects:

- Origin/Referer allowlisting for unsafe methods, including rejecting a missing Origin where the
  policy requires one (e.g. the `StrictOrigin` probe).
- A CSRF token or double-submit check tied to the session.
- Any authorization check that must be true before the business logic runs.
- Rejecting cross-site navigations that are meant to be blocked, if the requirement is to prevent
  the navigation itself.

`HttpOrigin` and `AuthenticityToken`/`RemoteToken` are structurally able to do this. `JsonCsrf` is
not: its `has_vector?` needs the response headers, which only exist after `app.call`.

**Can only happen in the response phase:**

- Deciding whether a response body is JSON and should be withheld from a cross-origin reader.
- Adding `Vary: Origin`, `Access-Control-Allow-Origin`, `X-Content-Type-Options: nosniff`, or
  similar headers.
- Clamping or rewriting a response that has already been produced.

`JsonCsrf` is therefore a response-filter for the cross-site-read class, not a write guard. Closing
the body is a best-effort cleanup: it stops enumeration (`W06`) but does not undo an eager commit
(`W01`, `W04`), and it can itself run code that writes (`W07`).

## Header and policy caveats

- `X-Requested-With` is client-controlled. It is not evidence of a trusted browser, a same-origin
  request, or a preflight. Both `JsonCsrf` and `FormToken` treat it as a bypass (`R05`, `W22`).
- The presence of an Origin header is not a same-origin assertion. `JsonCsrf` accepts *any* Origin
  (`R06`, `W03`), and `X-Origin` is accepted the same way (`R07`, `W28`). "Defers to HttpOrigin" is
  only true if `HttpOrigin` is actually earlier in the stack; standalone `JsonCsrf` does not check
  Origin values.
- Missing or empty Referer is treated as same-host by `Base#referrer` unless
  `allow_empty_referrer: false`. That option moves the check earlier only in the sense that it
  denies more, not that it runs before the app.
- A `403` is not proof of no write. The matrix shows `403` with `writes=1` in `W01`, `W04`, `W07`,
  `W11`, `W16`, `W32`, `W38`. The write happened before the response was replaced.
- `report` mode is a real bypass for middleware that uses the normal `Base` reaction (`W15`,
  `W16`); for `JsonCsrf` the alias makes `report` a no-op and it still denies its own vector
  (`W10`). Even where `report` does pass the request, it does not prevent side effects (`W15`,
  `W16`).
- `drop_session` is not a universal reaction: it returns `nil` when there is no session, and a
  middleware that treats `nil` as no denial continues to the app. Sinatra's default uses
  `drop_session` with `without_session: true` when sessions are disabled (`W35`).
- CORS is a separate policy. A reflected evil Origin with credentials (`R14`, `R18`) is a read
  exposure even when the JSON content type is correct; `JsonCsrf` does not remove the CORS headers
  and does not evaluate the CORS policy.
- `application/*+json` is not matched (`R10`); a capitalized header key or `text/html` is not
  matched (`R11`, `R13`). These are limitations of the exact-match check, not claims about every
  browser.

## Retention / replacement / combination guidance

Use the matrix as evidence, not as a universal browser claim:

- **Keep `JsonCsrf` only as a defense-in-depth response filter** for the JSON-read class, and only
  where the application's JSON responses are actually served with `application/json` and no CORS
  read exposure. It does not prevent writes: the app has already run when it decides (`W01`–`W05`),
  and `reaction:`/`report` cannot change that (`W10`, `W11`). If the application relies on it as
  the primary CSRF defense, that reliance is misplaced.
- **Replace it with a pre-application origin/token check** when writes matter: `HttpOrigin`
  (with an explicit `permitted_origins` allowlist and a policy for missing Origin), or a CSRF
  token (`AuthenticityToken`/`RemoteToken`) for unsafe methods. Those deny before the application
  call in the matrix (`W17`, `W18`, `W20`, `W24`). If sessions are disabled, choose a pre-app
  origin check rather than `drop_session` (`W35`).
- **Combine pre-app and response-phase checks** when both read and write risks are in scope:
  pre-app Origin/token enforcement for unsafe methods, plus `JsonCsrf` (or an explicit
  `Content-Type`/`nosniff`/CORS policy) for JSON responses. Keep `HttpOrigin` before `JsonCsrf`
  in the stack; `JsonCsrf` alone does not compare Origin values.
- **Do not treat `X-Requested-With` as a trust signal** (`R05`, `W22`). If a JSON API needs to
  serve browser XHR clients, origin/token checks are still required; a custom header can be set
  by any client that can make the request.

## Validation

- `./security/json-csrf-lab/run.sh` -> `73 scenarios, 0 expectation mismatches, 0 runtime errors`.
- Upstream `rack-protection` suite: `294 examples, 0 failures` (unchanged; the lab does not modify
  the gem or its specs).

## Limits of this evidence

This is a Rack-level simulation, not a browser test. It says nothing about whether a particular
browser sends `Origin` on a particular navigation, whether `Referer` survives a given referrer
policy, or which CORS preflight/credential combination a browser permits. Those questions need
browser-specific testing outside this sandbox. The claims above are limited to what the pinned
rack-protection 4.2.1 and Rack 3.2.8 code and the offline requests in `results/latest.json` show.
