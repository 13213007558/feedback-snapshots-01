Cross-site scripting (or XSS) is #3 on the 2013 [OWASP Top Ten](https://www.owasp.org/index.php/Top_10_2013-A3-Cross-Site_Scripting_(XSS\)) web security risks and it pops up nearly everywhere.

XSS occurs when a user-controlled value is displayed on a web page without properly escaping it, allowing someone to inject Javascript or HTML into the page which will be interpreted and executed by the browser..

In Rails 2.x, values need to be explicitly escaped (e.g., by using the `h` method). Since Rails 3.x, auto-escaping in views is enabled by default. However, one can still use the `raw` or `html_safe` methods to output a value directly.

See [the Ruby Security Guide](http://guides.rubyonrails.org/security.html#cross-site-scripting-xss) for more details.

### Query Parameters and Cookies

ERB example:

    <%= params[:query].html_safe %>

Brakeman looks for several situations that can allow XSS. The simplest is like the example above: a value from the `params` or `cookies` is being directly output to a view. In such cases, it will issue a warning like:

    Unescaped parameter value near line 3: params[:query]

By default, Brakeman will also warn when a parameter or cookie value is used as an argument to a method, the result of which is output unescaped to a view.

For example:

    <%= raw some_method(cookie[:name]) %>

This raises a warning like:

    Unescaped cookie value near line 5: some_method(cookies[:oreo])

However, the confidence level for this warning will be weak, because it is not directly outputting the cookie value.

### Mutable SafeBuffers

`html_safe` returns a `SafeBuffer`, which bypasses ERB auto-escaping even when output with `<%= %>`. Buffers are mutable and may be built up in a helper then returned to a view:

    def status_badge
      buffer = "".html_safe
      buffer.safe_concat(params[:status])
      buffer
    end

The methods used to add content have different security meanings:

* `buffer << value` and `buffer.concat(value)` escape `value` unless it is already marked HTML safe, so ordinary string appends are not reported.
* `buffer.safe_concat(value)` inserts `value` without escaping. SafeBuffer#replace and append-style methods only remain safe when the argument is not user-controlled.
* Assigning a new value to the variable (`buffer = params[:x]`) drops the buffer; normal auto-escaping applies again unless the value is output with `<%==` or `raw`.
* Multiple variables may refer to the same buffer. An unsafe append through any alias affects every reference, including a helper's return value.

Brakeman reports the expression that introduced the unsafe content together with the view line where the buffer is output. Fixed markup such as `buffer.safe_concat("<b>warning</b>")` is not reported, because the angle brackets are static and not user-controlled.

Some methods are known to Brakeman to either be dangerous (`link_to` is one) or safe (`escape_once`). Users can specify safe methods using the `--safe-methods` option. Alternatively, Brakeman can be set to _only_ warn when values are used directly with the `--report-direct` option.

### Model Attributes

Because (many) models come from database values, Brakeman mistrusts them by default.

For example, if `@user` is an instance of a model set in an action like

    def set_user
      @user = User.first
    end

and there is a view with

    <%= @user.name.html_safe %>

Brakeman will raise a warning like

    Unescaped model attribute near line 3: User.first.name

If you trust all your data (although you probably shouldn't), this can be disabled with `--ignore-model-output`.
