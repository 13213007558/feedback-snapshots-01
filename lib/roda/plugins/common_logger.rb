# frozen-string-literal: true

#
class Roda
  module RodaPlugins
    # The common_logger plugin adds common logger support to Roda
    # applications, similar to Rack::CommonLogger, with the following
    # differences:
    #
    # * Better performance
    # * Doesn't include middleware timing
    # * Doesn't proxy the body
    # * Doesn't support different capitalization of the Content-Length response header
    # * Logs to +$stderr+ instead of <tt>env['rack.errors']</tt> if explicit logger not passed
    #
    # Example:
    #
    #   plugin :common_logger
    #   plugin :common_logger, $stdout
    #   plugin :common_logger, Logger.new('filename')
    #   plugin :common_logger, Logger.new('filename'), method: :debug
    #   plugin :common_logger, use_request_ip: true
    #
    #   # Log a safe representation of the path instead of the actual path
    #   plugin :common_logger, Logger.new('filename'), log_path: proc{|request| ...}
    #
    #   # Use a hash to map paths to safe representations
    #   plugin :common_logger, Logger.new('filename'),
    #     log_path: {/\A\/downloads\/[0-9a-f]+\z/ => '/downloads/:id'},
    #     log_path_fallback: '-'
    #
    # Keyword Arguments:
    # +method+ :: Specifies the method to call on the logger object when logging.
    # +use_request_ip+ :: Use +request.ip+ to get the IP address, instead of the default
    #                     of checking +HTTP_X_FORWARDED_FOR+ and then +REMOTE_ADDR+. This
    #                     will become the default behavior starting in Roda 4.
    # +log_path+ :: A callable, hash, or block used to produce the path
    #               representation included in the log.  When a callable is
    #               used, it is called with the request.  If the callable is a
    #               Proc that accepts no arguments, it is called in the request
    #               context instead.  When a hash is used, the keys are
    #               matched against the request's +path+.  Regular expression
    #               keys are matched
    #               using <tt>key === path</tt>, string keys are matched
    #               exactly, and string keys ending in <tt>/</tt> are also
    #               matched as prefixes.  The value for the first matching
    #               key is used.  If the callable returns +nil+, +false+, or an
    #               empty string, if it raises an error, or if no hash entry
    #               matches, +log_path_fallback+ is used.  The query string is
    #               not included in the log when this option is used, and the
    #               request environment is not modified.
    # +log_path_fallback+ :: The path representation to use if +log_path+ does
    #                        not produce a usable value, such as for a request
    #                        that did not match any route.  Defaults to
    #                        <tt>'-'</tt>, the common log format placeholder for
    #                        an unavailable request target.  Specifying this
    #                        option also enables safe path logging when only
    #                        the route-level +log_path+ method is used.
    #
    # In addition to the plugin-level +log_path+ option, a route can set the
    # path representation for the current request by calling +log_path+ (or
    # <tt>r.log_path</tt>) in the route block.  This is useful when the safe
    # representation depends on the matched route:
    #
    #   plugin :common_logger, $stdout, log_path_fallback: '-'
    #
    #   route do |r|
    #     r.on 'downloads', String do |id|
    #       r.log_path '/downloads/:id' # or just log_path '/downloads/:id'
    #       # ...
    #     end
    #   end
    #
    # The value set by +log_path+ takes precedence over the plugin-level
    # +log_path+ option.  If +log_path+ is called with +nil+, or is not called
    # for a request, the plugin-level option (or the fallback) is used.
    # +log_path+ only affects logging.  It does not modify the request path,
    # query string, or any Rack environment value, so routing and the
    # application continue to see the original path.
    module CommonLogger
      SCOPE_INSTANCE_VARIABLES = [:@_request_timer].freeze

      UNSET = Object.new
      private_constant :UNSET

      MUTATE_LINE = RUBY_VERSION < '2.3' || RUBY_VERSION >= '3'
      private_constant :MUTATE_LINE

      def self.configure(app, logger=nil, opts=(no_positional_opts = true; OPTS), method: opts[:method], use_request_ip: false, log_path: opts[:log_path], log_path_fallback: opts.fetch(:log_path_fallback, UNSET), **kw, &block)
        RodaPlugins.check_keywords("the common_logger plugin", no_positional_opts, opts, kw)

        log_path ||= block

        unless log_path.nil? || log_path.respond_to?(:call) || log_path.is_a?(Hash)
          raise RodaError, "common_logger plugin :log_path option must be a callable or a hash"
        end

        if !log_path_fallback.equal?(UNSET)
          unless log_path_fallback.is_a?(String)
            raise RodaError, "common_logger plugin :log_path_fallback option must be a String"
          end
          app.opts[:common_logger_log_path_fallback] = log_path_fallback.dup.freeze
        end

        common_logger = app.opts[:common_logger] = logger || app.opts[:common_logger] || $stderr # RODA4: drop setting of option, no longer used
        app.opts[:common_logger_meth] = common_logger.method(method || (common_logger.respond_to?(:write) ? :write : :<<))
        app.opts[:common_logger_use_request_ip] = use_request_ip # RODA4: Deefault to true
        app.opts[:common_logger_log_path] = log_path || app.opts[:common_logger_log_path]
      end

      if RUBY_VERSION >= '2.1'
        # A timer object for calculating elapsed time.
        def self.start_timer
          # RODA4.1: Remove
          Process.clock_gettime(Process::CLOCK_MONOTONIC)
        end
      else
        # simplecov:disable
        def self.start_timer # :nodoc:
          Time.now
        end
        # simplecov:enable
      end

      module ClassMethods
        RodaPlugins.opt_attr_reader(self, :common_logger_meth)
        RodaPlugins.opt_attr_reader(self, :common_logger_use_request_ip, name: :common_logger_use_request_ip?)
        RodaPlugins.opt_attr_reader(self, :common_logger_log_path)
        RodaPlugins.opt_attr_reader(self, :common_logger_log_path_fallback)
      end

      module RequestMethods
        # Set the path representation used for logging the current request.
        # This is an alias for the scope method of the same name, allowing
        # <tt>r.log_path</tt> to be used in the route block.
        def log_path(path)
          scope.log_path(path)
        end
      end

      module InstanceMethods
        # Set the path representation used for logging the current request.
        # This can be called from the route block when the representation
        # depends on the matched route.  It only affects logging, not the
        # request path or Rack environment.  Passing +nil+ clears any
        # representation set previously for this request.
        #
        # This requires the plugin to be configured with the +log_path+ or
        # +log_path_fallback+ option, so that requests not setting a
        # representation (such as unmatched requests) have an explicit
        # conservative representation to log.
        def log_path(path)
          unless self.class.common_logger_log_path || self.class.common_logger_log_path_fallback
            raise RodaError, "log_path can only be used when the common_logger plugin is configured with the :log_path or :log_path_fallback option"
          end

          @_common_log_path = path
          nil
        end

        private

        # Return a safe representation of the request path for logging.  If a
        # log_path callable or hash is configured, use it.  If it does not
        # produce a usable value, use the configured fallback.  The request
        # environment is never modified, and the actual path remains available
        # to the routing code.
        def _common_log_path_value
          fallback = self.class.common_logger_log_path_fallback || '-'

          if defined?(@_common_log_path) && (path = @_common_log_path).is_a?(String) && !path.empty?
            return path
          end

          if (matcher = self.class.common_logger_log_path).is_a?(Hash)
            path = @_request.path
            matcher.each do |k, v|
              matched = case k
                when Regexp
                  k === path
                when String
                  path == k || (k.end_with?('/') && path.start_with?(k))
                else
                  false
              end
              next unless matched
              return v.is_a?(String) && !v.empty? ? v : fallback
            end
            return fallback
          end

          callable = self.class.common_logger_log_path
          return fallback unless callable

          if callable.is_a?(Proc) && callable.arity == 0
            path = instance_exec(&callable)
          else
            path = callable.call(@_request)
          end

          if path.is_a?(String) && !path.empty?
            path
          else
            fallback
          end
        rescue StandardError
          fallback
        end

        # Log request/response information in common log format to logger.
        def _roda_after_90__common_logger(result)
          return unless result && (status = result[0]) && (headers = result[1])

          elapsed_time = if timer = @_request_timer
            '%0.4f' % (CommonLogger.start_timer - timer)
          else 
            '-'
          end

          env = @_request.env

          ip = if self.class.common_logger_use_request_ip?
            @_request.ip
          else
            env['HTTP_X_FORWARDED_FOR'] || env["REMOTE_ADDR"]
          end

          request_target = if self.class.common_logger_log_path || (defined?(@_common_log_path) && @_common_log_path) || self.class.common_logger_log_path_fallback
            _common_log_path_value
          else
            "#{env["SCRIPT_NAME"]}#{env["PATH_INFO"]}#{"?#{env["QUERY_STRING"]}" if ((qs = env["QUERY_STRING"]) && !qs.empty?)}"
          end

          line = "#{ip || "-"} - #{env["REMOTE_USER"] || "-"} [#{Time.now.strftime("%d/%b/%Y:%H:%M:%S %z")}] \"#{env["REQUEST_METHOD"]} #{request_target} #{@_request.http_version}\" #{status} #{((length = headers[RodaResponseHeaders::CONTENT_LENGTH]) && (length unless length == '0')) || '-'} #{elapsed_time} "
          if MUTATE_LINE
            line.gsub!(/[^[:print:]]/){|c| sprintf("\\x%x", c.ord)}
          # simplecov:disable
          else
            line = line.gsub(/[^[:print:]]/){|c| sprintf("\\x%x", c.ord)}
          # simplecov:enable
          end
          line[-1] = "\n"
          self.class.common_logger_meth.call(line)
        end

        # Create timer instance used for timing
        def _roda_before_05__common_logger
          @_request_timer = CommonLogger.start_timer
        end
      end
    end

    register_plugin(:common_logger, CommonLogger)
  end
end
