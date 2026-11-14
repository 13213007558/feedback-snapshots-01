## Per-action configuration

You can override the settings for a given action by producing a temporary override. Be aware that because of the dynamic nature of the value, the header values will be computed per request.

```ruby
# Given a config of:
::SecureHeaders::Configuration.default do |config|
   config.csp = {
     default_src: %w('self'),
     script_src: %w('self')
   }
 end

class MyController < ApplicationController
  def index
    # Append value to the source list, override 'none' values
    # Produces: default-src 'self'; script-src 'self' s3.amazonaws.com; object-src 'self' www.youtube.com
    append_content_security_policy_directives(script_src: %w(s3.amazonaws.com), object_src: %w('self' www.youtube.com))

    # Overrides the previously set source list, override 'none' values
    # Produces: default-src 'self'; script-src s3.amazonaws.com; object-src 'self'
    override_content_security_policy_directives(script_src: %w(s3.amazonaws.com), object_src: %w('self'))

    # Global settings default to "sameorigin"
    override_x_frame_options("DENY")
  end
```

The following methods are available as controller instance methods. They are also available as class methods, but require you to pass in the `request` object.
* `append_content_security_policy_directives(hash)`: appends each value to the corresponding CSP app-wide configuration.
* `override_content_security_policy_directives(hash)`: merges the hash into the app-wide configuration, overwriting any previous config
* `override_x_frame_options(value)`: sets the `X-Frame-Options header` to `value`

## Appending / overriding Content Security Policy

When manipulating content security policy, there are a few things to consider. The default header value is `default-src https:` which corresponds to a default configuration of `{ default_src: %w(https:)}`.

#### Append to the policy with a directive other than `default_src`

The value of `default_src` is joined with the addition if the it is a [fetch directive](https://w3c.github.io/webappsec-csp/#directives-fetch). Note the `https:` is carried over from the `default-src` config. If you do not want this, use `override_content_security_policy_directives` instead. To illustrate:

```ruby
::SecureHeaders::Configuration.default do |config|
   config.csp = {
     default_src: %w('self')
   }
 end
 ```

Code  | Result
------------- | -------------
`append_content_security_policy_directives(script_src: %w(mycdn.com))` | `default-src 'self'; script-src 'self' mycdn.com`
`override_content_security_policy_directives(script_src: %w(mycdn.com))`  | `default-src 'self'; script-src mycdn.com`

#### Nonce

You can use a view helper to automatically add nonces to script tags. Currently, using a nonce helper or calling `content_security_policy_nonce` will populate all configured CSP headers, including report-only and enforced policies. 

```erb
<%= nonced_javascript_tag do %>
console.log("nonced!");
<% end %>

<%= nonced_style_tag do %>
body {
  background-color: black;
}
<% end %>

<%= nonced_javascript_include_tag "include.js" %>

<%= nonced_javascript_pack_tag "pack.js" %>

<%= nonced_stylesheet_link_tag "link.css" %>

<%= nonced_stylesheet_pack_tag "pack.css" %>
```

becomes:

```html
<script nonce="/jRAxuLJsDXAxqhNBB7gg7h55KETtDQBXe4ZL+xIXwI=">
console.log("nonced!")
</script>
<style nonce="/jRAxuLJsDXAxqhNBB7gg7h55KETtDQBXe4ZL+xIXwI=">
body {
  background-color: black;
}
</style>
```

```

content-security-policy: ...
  script-src 'nonce-/jRAxuLJsDXAxqhNBB7gg7h55KETtDQBXe4ZL+xIXwI=' ...;
  style-src 'nonce-/jRAxuLJsDXAxqhNBB7gg7h55KETtDQBXe4ZL+xIXwI=' ...;
```

`script`/`style-nonce` can be used to whitelist inline content. To do this, call the `content_security_policy_script_nonce` or `content_security_policy_style_nonce` then set the nonce attributes on the various tags.

```erb
<script nonce="<%= content_security_policy_script_nonce %>">
  console.log("whitelisted, will execute")
</script>

<script nonce="lol">
  console.log("won't execute, not whitelisted")
</script>

<script>
  console.log("won't execute, not whitelisted")
</script>
```

#### Element-level vs. attribute-level script directives

CSP3 splits `script-src` into `script-src-elem` (controls `<script>` elements)
and `script-src-attr` (controls inline event-handler attributes such as
`onclick`). The browser checks the most specific directive that is present and
falls back in this order:

```
script-src-elem / script-src-attr  ->  script-src  ->  default-src
```

A nonce only ever authorizes an element, so `content_security_policy_script_nonce`
populates the configured element-level directives (`script-src-elem` when
present, and `script-src` so older browsers that ignore `*-src-elem` still
match). It is never added to `script-src-attr`, which lets you keep inline event
handlers disabled without the auto-generated nonce reopening them:

```ruby
config.csp = {
  default_src: %w('self'),
  script_src: %w('self'),
  script_src_elem: %w('self'),
  script_src_attr: %w('none') # inline event handlers stay blocked
}
```

produces (after a nonce is requested):

```
content-security-policy: default-src 'self';
  script-src 'self' 'nonce-...' 'unsafe-inline';
  script-src-attr 'none';
  script-src-elem 'self' 'nonce-...' 'unsafe-inline'
```

An explicit deny — a directive whose only value is `'none'` — always wins. The
nonce is not appended to such a directive and `'none'` is not dropped. The same
rules apply to `style-src-elem` / `style-src-attr` and the style nonce.

`disable_nonce_backwards_compatibility` only suppresses the companion
`'unsafe-inline'` token on the element-level directives; it never changes the
attribute-level directive.

## Clearing browser cache

You can clear the browser cache after the logout request by using the following.

``` ruby
class ApplicationController < ActionController::Base
  # Configuration override to send the clear-site-data header.
  SecureHeaders::Configuration.override(:clear_browser_cache) do |config|
    config.clear_site_data = SecureHeaders::ClearSiteData::ALL_TYPES
  end


  # Clears the browser's cache for browsers supporting the clear-site-data
  # header.
  #
  # Returns nothing.
  def clear_browser_cache
    SecureHeaders.use_secure_headers_override(request, :clear_browser_cache)
  end
end

class SessionsController < ApplicationController
  after_action  :clear_browser_cache, only: :destroy
end
```
