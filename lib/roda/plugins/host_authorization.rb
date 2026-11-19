# frozen-string-literal: true

#
class Roda
  module RodaPlugins
    # The host_authorization plugin allows configuring an authorized host or
    # an array of authorized hosts.  Then in the routing tree, you can check
    # whether the request uses an authorized host via the +check_host_authorization!+
    # method.
    # 
    # If the request doesn't match one of the authorized hosts, the
    # request processing stops at that point. Using this plugin can prevent
    # DNS rebinding attacks if the application can receive requests for
    # arbitrary hosts.
    #
    # By default, an empty response using status 403 will be returned for requests
    # with unauthorized hosts.
    #
    # Because +check_host_authorization!+ is an instance method, you can easily choose
    # to only check for authorization in certain routes, or to check it after
    # other processing.  For example, you could check for authorized hosts after
    # serving static files, since the serving of static files should not be
    # vulnerable to DNS rebinding attacks.
    #
    # = Usage
    #
    # In your routing tree, call the +check_host_authorization!+ method at the point you
    # want to check for authorized hosts:
    #
    #   plugin :host_authorization, 'www.example.com'
    #   plugin :public
    #
    #   route do |r|
    #    r.public
    #    check_host_authorization!
    #
    #    # ...
    #   end
    #
    # = Specifying authorized hosts
    #
    # For applications hosted on a single domain name, you can use a single string:
    #
    #   plugin :host_authorization, 'www.example.com'
    #
    # For applications hosted on multiple domain names, you can use an array of strings:
    #
    #   plugin :host_authorization, %w'www.example.com www.example2.com'
    #
    # For applications supporting arbitrary subdomains, you can use a wildcard string
    # containing <tt>*</tt> (matching any number of characters) or <tt>?</tt>
    # (matching a single character), or a regexp.  Wildcard strings must match the
    # entire host.  If using a regexp, make sure you use <tt>\A<tt> and <tt>\z</tt> in
    # your regexp, and restrict the allowed characters to the minimum required,
    # otherwise you can potentionally introduce a security issue:
    #
    #   plugin :host_authorization, '*.example.com'
    #   plugin :host_authorization, /\A[-0-9a-f]+\.example\.com\z/
    #
    # For applications with more complex requirements, you can use a proc.  Similarly
    # to the regexp case, the proc should be aware the host contains user-submitted
    # values, and not assume it is in any particular format:
    #
    #   plugin :host_authorization, proc{|host| ExternalService.allowed_host?(host)}
    #
    # If an array of values is passed as the host argument, the host is authorized if
    # it matches any value in the array.  All host rules (including the allowed host
    # patterns, and the +defer_hosts+ and +reject_hosts+ options described below) use
    # the same matching logic: strings are compared exactly unless they contain
    # wildcard characters, and other objects are matched using <tt>===</tt>, which is
    # why regexps, procs, and arbitrary objects that support <tt>===</tt> work.
    #
    # For security reasons, only the +Host+ header is checked by default.  If you are
    # sure that your application is being run behind a forwarding proxy that sets the
    # <tt>X-Forwarded-Host</tt> header, you should enable support for checking that
    # header using the +check_forwarded+ keyword argument:
    # 
    #   plugin :host_authorization, 'www.example.com', check_forwarded: true
    #
    # In this case, the trailing host in the <tt>X-Forwarded-Host</tt> header is checked,
    # which should be the host set by the forwarding proxy closest to the application.
    # In cases where multiple forwarding proxies are used that append to the
    # <tt>X-Forwarded-Host</tt> header, you should not use this plugin.
    #
    # = Assigning policy ownership
    #
    # When the application is used as middleware in front of another application, it
    # may only be responsible for enforcing the host policy for part of the host space.
    # You can explicitly configure which hosts this layer is responsible for, and which
    # hosts should be left to the next application's own host policy:
    #
    #   plugin :host_authorization, 'www.example.com',
    #     defer_hosts: '*.internal.example.com'
    #
    # With this configuration, requests for <tt>www.example.com</tt> are handled by
    # this layer, requests for hosts matching <tt>*.internal.example.com</tt> are
    # forwarded to the next application without this layer making a host decision,
    # and requests for any other host are rejected by this layer.
    #
    # +defer_hosts+ can be a single value or an array of values.  The same matching
    # logic used for authorized hosts is used for deferred hosts.  When the application
    # is not used as middleware, there is no next application to defer to, so deferred
    # hosts are treated as authorized and this check is a no-op for them.
    #
    # You can also explicitly list hosts that this layer must reject, even if they would
    # otherwise match an authorized host (or the default authorized host) or a deferred
    # host.  This is useful when the next application's host policy is less strict than
    # this layer's:
    #
    #   plugin :host_authorization, '*.example.com', reject_hosts: 'admin.example.com'
    #
    # Rejection takes precedence over both authorization and deferral.
    #
    # = Recording rejections
    #
    # You can provide a callable using the +on_reject+ keyword argument that is called
    # whenever this layer rejects a host.  This is useful for audit logging:
    #
    #   plugin :host_authorization, 'www.example.com',
    #     on_reject: proc{|host, env| AuditLog.host_rejected(host, env['PATH_INFO'])}
    #
    # The callable is called with the host that was rejected and the rack environment for
    # the request.  It is called before the response for the request is generated, and
    # its return value is ignored.  The plugin does not modify the request environment,
    # and the callable should not modify it either.
    #
    # = Customizing behavior
    #
    # By default, an unauthorized host will receive an empty 403 response.  You can
    # customize this by passing a block when loading the plugin. For example, for
    # sites using the render plugin, you could return a page that uses your default
    # layout:
    #
    #   plugin :render
    #   plugin :host_authorization, 'www.example.com' do |r|
    #     response.status = 403
    #     view(content: "<h1>Forbidden</h1>")
    #   end
    #
    # The block passed to this plugin is treated as a match block.
    module HostAuthorization
      # Cache of compiled wildcard host patterns.
      @pattern_cache = RodaCache.new
      class << self
        attr_reader :pattern_cache
      end

      def self.configure(app, host=nil, opts=(no_positional_opts = true; OPTS),
          check_forwarded: opts[:check_forwarded],
          defer_hosts: opts[:defer_hosts],
          reject_hosts: opts[:reject_hosts],
          on_reject: opts[:on_reject],
          **kw, &block)
        RodaPlugins.check_keywords("the host_authorization plugin", no_positional_opts, opts, kw)

        if on_reject && !on_reject.respond_to?(:call)
          raise RodaError, "the :on_reject option to the host_authorization plugin must be callable"
        end

        app.opts[:host_authorization_host] = host unless host.nil?
        app.opts[:host_authorization_check_forwarded] = check_forwarded unless check_forwarded.nil?
        app.opts[:host_authorization_defer_hosts] = defer_hosts unless defer_hosts.nil?
        app.opts[:host_authorization_reject_hosts] = reject_hosts unless reject_hosts.nil?
        app.opts[:host_authorization_on_reject] = on_reject unless on_reject.nil?

        if block
          app.define_roda_method(:host_authorization_unauthorized, 1, &block)
        end
      end

      module ClassMethods
        RodaPlugins.opt_attr_reader(self, :host_authorization_host)
        RodaPlugins.opt_attr_reader(self, :host_authorization_check_forwarded, name: :host_authorization_check_forwarded?)
        RodaPlugins.opt_attr_reader(self, :host_authorization_defer_hosts)
        RodaPlugins.opt_attr_reader(self, :host_authorization_reject_hosts)
        RodaPlugins.opt_attr_reader(self, :host_authorization_on_reject)
      end

      module InstanceMethods
        # Check whether the host is authorized.  If the host is a configured deferred
        # host, this layer makes no host decision, leaving the host policy to the next
        # application.  If the host is not authorized, call the +on_reject+ handler if
        # configured, and return a response immediately based on the plugin block.
        # This does not modify the request environment.
        def check_host_authorization!
          r = @_request
          host = _convert_host_for_authorization(r.env["HTTP_HOST"].to_s.dup)

          return _host_authorization_reject_request(r, host) if host_authorization_rejected?(host)
          return _host_authorization_defer_request(r) if host_authorization_deferred?(host)
          return if host_authorized?(host)

          if forwarded_host = _host_authorization_forwarded_host(r)
            return _host_authorization_reject_request(r, host) if host_authorization_rejected?(forwarded_host)
            return if host_authorized?(forwarded_host)
          end

          _host_authorization_reject_request(r, host)
        end

        private

        # The host from the X-Forwarded-Host header that should be checked, or
        # nil if the header is not being checked or does not contain a host.
        def _host_authorization_forwarded_host(r)
          return unless self.class.host_authorization_check_forwarded?
          return unless forwarded_host = r.env["HTTP_X_FORWARDED_HOST"]

          if i = forwarded_host.rindex(',')
            forwarded_host = forwarded_host[i+1, 10000000].to_s
          end
          forwarded_host = _convert_host_for_authorization(forwarded_host.strip)

          forwarded_host unless forwarded_host.empty?
        end

        # Handle a request for a deferred host.  When the application is used as
        # middleware, forward the request to the next application without this
        # application handling it.  Otherwise, this check is a no-op.
        def _host_authorization_defer_request(r)
          if r.respond_to?(:forward_next!)
            r.forward_next!
          else
            nil
          end
        end

        # Record the rejection decision (without modifying the request environment),
        # and return the unauthorized response.
        def _host_authorization_reject_request(r, host)
          _host_authorization_record_rejection(host, r.env)

          r.on do
            host_authorization_unauthorized(r)
          end
        end

        # Whether the host given is a host whose policy is owned by the next
        # application, and so should not be checked by this layer.
        def host_authorization_deferred?(host, defer_hosts = self.class.host_authorization_defer_hosts)
          host_authorization_match?(host, defer_hosts)
        end

        # Whether the host given was explicitly configured as a host this layer
        # must reject, even if it would otherwise be authorized.
        def host_authorization_rejected?(host, reject_hosts = self.class.host_authorization_reject_hosts)
          host_authorization_match?(host, reject_hosts)
        end

        # Record the rejection using the +on_reject+ handler if one was configured.
        def _host_authorization_record_rejection(host, env)
          if on_reject = self.class.host_authorization_on_reject
            on_reject.call(host, env)
          end
        end

        # Whether the host given matches any entry in the given host patterns.
        def host_authorization_match?(host, patterns)
          case patterns
          when nil
            false
          when Array
            patterns.any?{|pattern| host_authorization_match?(host, pattern)}
          when String
            if patterns.include?('*') || patterns.include?('?')
              host_authorization_pattern(patterns).match?(host)
            else
              patterns == host
            end
          else
            patterns === host
          end
        end

        # A regexp for the given wildcard host pattern.  Only <tt>*</tt> (match
        # any number of characters) and <tt>?</tt> (match a single character) are
        # treated as wildcards, all other characters are matched literally.
        def host_authorization_pattern(pattern)
          HostAuthorization.pattern_cache[pattern] ||= begin
            regexp = Regexp.escape(pattern).gsub('\\*', '.*').gsub('\\?', '.')
            /\A#{regexp}\z/
          end
        end

        # Remove the port information from the passed string (mutates the passed argument).
        def _convert_host_for_authorization(host)
          host.sub!(/:\d+\z/, "")
          host
        end

        # Whether the host given is one of the authorized hosts for this application.
        def host_authorized?(host, authorized_host = self.class.host_authorization_host)
          case authorized_host
          when nil
            false
          when Array
            authorized_host.any?{|auth_host| host_authorized?(host, auth_host)}
          else
            host_authorization_match?(host, authorized_host)
          end
        end

        # Action to take for unauthorized hosts. Sets a 403 status by default.
        def host_authorization_unauthorized(_)
          @_response.status = 403
          nil
        end
      end
    end

    register_plugin(:host_authorization, HostAuthorization)
  end
end
