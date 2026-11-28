
# Sidekiq 8.0 Web Configuration

## Quick Jump
<!--toc:start-->
- [Sidekiq 8.0 Web](#sidekiq-80-web)
- [The Problem](#the-problem)
- [The Solution](#the-solution)
<!--toc:end-->

Sidekiq 8.0 revises how Sidekiq::Web is configured.

# The Problem

Before 8.0, Sidekiq used global class-methods on the Sidekiq::Web class to access and configure various options.
The lack of idiomatic API made me hesitant to add more configuration knobs to Sidekiq::Web.

```ruby
Sidekiq::Web.app_link "https://acmecorp.com"
Sidekiq::Web.register MyExtension
Sidekiq::Web.use Some::Rack::Middleware
```

# The Solution

## Sidekiq::Web::Config

The above API is essentially wrapped in a `configure` block. You can:

1. Register 3rd party Web UI extensions
2. Allow you to add Rack middleware for authentication or authorization
3. Configure minor UI tweaks

```ruby
require "sidekiq/web"
Sidekiq::Web.configure do |config|
  config.register(MyExtension, name: "myext", tab: "TabName", index: "tabpage/")
  config.use Some::Rack::Middleware
  config.app_url "https://acmecorp.com" # Adds "Back to App" button in the UI
end
```

See `lib/sidekiq/web/config.rb` for options.

## Web UI Extensions

There is a sample Web UI extension in `examples/webui-ext` which shows you how to build your own UI extension.
Sidekiq 8.0 took a number of steps to improve security.

### Scoping an install

By default `register` mounts everything an extension offers: its tabs, its HTTP
endpoints and its static assets. The mounter can explicitly narrow those surfaces
with `capabilities:` when an install should only publish a subset, e.g. a public
install which serves help resources while the extension's operational endpoints
await separate approval:

```ruby
Sidekiq::Web.configure do |config|
  # help-only install: navbar tab and static files, no HTTP endpoints
  config.register(HelpExt, name: "help", tab: "Help", index: "help/pages/guide.html",
    root_dir: HelpExt::ROOT, asset_paths: ["pages"],
    capabilities: %i[menu assets])

  # internal install: the full extension, same as always
  config.register(HelpExt, name: "help", tab: "Help", index: "help",
    root_dir: HelpExt::ROOT, asset_paths: ["pages"])
end
```

The available capabilities are `:menu` (navbar tabs), `:routes` (HTTP endpoints)
and `:assets` (static files and locales). Without `:routes`, the extension's
`registered` hook is never called. Registration is transactional: if an
extension fails partway through `register`, everything it added is rolled back
and the error is re-raised, so a half-registered extension never leaks tabs,
routes or assets into the Web UI.

### Parameters

Starting in 8.0 we distinguish between URL parameters (query parameters) and route parameters (variables in the URL).
Assume your extension has an endpoint like so:

```ruby
# https://acmecorp.com/sidekiq/batches/b-123abc?size=10
get "/batches/:bid" do
  route_params(:bid) # => "b-123abc"
  url_params("size") # => "10"
end
```

Note that each param type uses Strings or Symbols so you can't mistake one for the other.
This ensures an attacker can't override the `bid` by adding a query parameter.

https://acmecorp.com/sidekiq/batches/b-123abc?size=10&bid=b-456def

### Assets

Sidekiq::Web 8.0 further locks down its Content-Security-Policy by requiring all assets to tag themselves with a per-request nonce, which makes it impossible to inject a malicious asset via XSS.

This can be done automatically for you by using the new `stylesheet_tag` or `script_tag` helpers in `lib/sidekiq/web/helpers.rb`.
