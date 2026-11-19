# frozen-string-literal: true

require 'rack/utils'

class Roda
  module RodaPlugins
    # The conditional_sessions plugin loads the sessions plugin.  However,
    # it only allows sessions for requests where the block passed to the
    # plugin returns a truthy value.  The block is evaluated in request
    # context. This is designed for use in applications that want to use
    # sessions for some requests, and want to be sure that sessions are not
    # used for other requests.  For example, if you want to make sure that
    # sessions are not used for requests with paths starting with +/static+,
    # you could do:
    #
    #   plugin :conditional_sessions, secret: ENV["SECRET"] do
    #     !path_info.start_with?('/static')
    #   end
    #
    # Then the request +session+, +session_created_at+, and +session_updated_at+ methods
    # raise a RodaError exception when sessions are not allowed.  The request
    # +persist_session+ and route scope +clear_session+ methods do nothing when
    # sessions are not allowed.
    #
    # == Three Request Modes
    #
    # The block can return +true+/+false+ as above, but it can also return
    # one of the following symbols to select a specific request mode:
    #
    # :sessions :: Allow normal session loading and storage.  This is the
    #              mode used for requests where the visitor has consented to
    #              session storage.
    # :csrf :: Do not load or persist the normal session, but allow CSRF
    #          protection using a dedicated CSRF cookie (requires the
    #          route_csrf plugin's :secret_cookie option).  This is useful
    #          for login forms that must be protected before consent.
    # :none :: Do not load or persist the normal session and do not use a
    #          CSRF cookie.  This is the mode for pages that have neither
    #          session state nor forms, such as public or static pages.
    #
    # A truthy return value other than one of these symbols is treated as
    # :sessions, and a falsey return value is treated as :none, for
    # backwards compatibility.
    #
    # For example, for a site that does not store sessions until the visitor
    # has consented, while still protecting a login form:
    #
    #   plugin :route_csrf,
    #     secret: ENV['CSRF_SECRET'],
    #     secret_cookie: true
    #
    #   plugin :conditional_sessions, secret: ENV['SESSION_SECRET'] do
    #     case path_info
    #     when '/static', '/health'
    #       :none
    #     when '/login', '/consent', '/withdraw'
    #       cookies['visitor_consent'] ? :sessions : :csrf
    #     else
    #       cookies['visitor_consent'] ? :sessions : :none
    #     end
    #   end
    #
    # Use +path_info+ instead of +path+ in the block, since +path+ can change
    # as routing progresses.
    #
    # The request method +session_mode+ returns the selected mode, and
    # +use_sessions?+ returns whether the mode is :sessions.  The request
    # method +use_csrf?+ returns whether CSRF protection is available for
    # the request (mode :sessions or :csrf).  The same methods are available
    # in the route block scope.
    #
    # == Withdrawing Consent
    #
    # When a visitor withdraws consent, the normal session cookie created
    # earlier must still be removed even though the request selecting the
    # withdrawal action may already be treated as :none or :csrf (and
    # therefore cannot use +session+ or +clear_session+).  The
    # +expire_session+ method (available in both request and route block
    # scope) unconditionally adds headers that delete the session cookie,
    # without loading or creating a session.  For example:
    #
    #   plugin :cookies
    #
    #   route do |r|
    #     r.post 'withdraw-consent' do
    #       expire_session
    #       delete_csrf_secret_cookie
    #       # Delete the application's own consent cookie.
    #       response.delete_cookie('visitor_consent')
    #       r.redirect '/'
    #     end
    #   end
    #
    # The conditional_sessions plugin loads the sessions plugin itself, so an
    # explicit +plugin :sessions+ call is not needed.  The +response.delete_cookie+
    # call above requires the cookies plugin, but +expire_session+ and
    # +delete_csrf_secret_cookie+ do not.
    #
    # +expire_session+ does not require the sessions plugin's cookie to have
    # been submitted, so it is safe to call on every withdrawal, including
    # for visitors that never consented.
    module ConditionalSessions
      # Pass all options to the sessions block, and use the block to select
      # the session mode for the request.
      def self.load_dependencies(app, opts=OPTS, &block)
        app.plugin :sessions, opts
        if block
          app::RodaRequest.class_exec do
            define_method(:_conditional_sessions_mode_result, &block)
            private :_conditional_sessions_mode_result
          end
        end
      end

      module InstanceMethods
        # The session mode for the current request, one of :sessions, :csrf,
        # or :none.  See the plugin documentation for details.
        def session_mode
          @_request.session_mode
        end

        # Whether the current request uses normal sessions.
        def use_sessions?
          @_request.use_sessions?
        end

        # Whether the current request supports CSRF protection.
        def use_csrf?
          @_request.use_csrf?
        end

        # Do nothing if not using sessions.
        def clear_session
          super if use_sessions?
        end

        # Delete the normal session cookie in the response without loading or
        # creating a session.  This is intended for withdrawing consent when
        # the current request may not be allowed to use sessions.
        def expire_session
          @_request.expire_session
        end
      end

      module RequestMethods
        # The session mode for the current request.  If the plugin was loaded
        # without a block, sessions are always allowed.
        def session_mode
          defined?(@_conditional_sessions_mode) ? @_conditional_sessions_mode : (@_conditional_sessions_mode = _normalize_conditional_sessions_mode(_conditional_sessions_mode_result))
        end

        # Whether the current request uses normal sessions.
        def use_sessions?
          session_mode == :sessions
        end

        # Whether the current request supports CSRF protection.  True for
        # requests using sessions or the CSRF-only mode.
        def use_csrf?
          session_mode != :none
        end

        # Delete the normal session cookie in the response without loading
        # or creating a session.  This works even if sessions are not allowed
        # for the current request, which makes it usable when withdrawing
        # consent.
        def expire_session
          config = roda_class.sessions_config
          Rack::Utils.delete_cookie_header!(response.headers, config.key, config.remove_cookie_options)
          # Replace any loaded session with an empty hash, so later session
          # access does not reload the submitted cookie, and the sessions after
          # hook does not write the old data back after the deletion header.
          env[config.env_key] = {}
          env.delete('roda.session.created_at')
          env.delete('roda.session.updated_at')
          env.delete('roda.session.serialized')
          env.delete('roda.session.version')
          nil
        end

        # Raise RodaError if not using sessions.
        def session
          raise RodaError, "session called on request not using sessions" unless use_sessions?
          super
        end

        # Raise RodaError if not using sessions.
        def session_created_at
          raise RodaError, "session_created_at called on request not using sessions" unless use_sessions?
          super
        end

        # Raise RodaError if not using sessions.
        def session_updated_at
          raise RodaError, "session_updated_at called on request not using sessions" unless use_sessions?
          super
        end

        # Do nothing if not using sessions.
        def persist_session(headers, session)
          super if use_sessions?
        end

        private

        # The raw result of the plugin block.  Sessions are allowed if the
        # plugin was loaded without a block.
        def _conditional_sessions_mode_result
          :sessions
        end

        # Normalize the plugin block result to a supported session mode.
        # Truthy values other than :csrf are treated as :sessions, and falsey
        # values are treated as :none, for backwards compatibility.
        def _normalize_conditional_sessions_mode(mode)
          case mode
          when :sessions, :csrf, :none
            mode
          when nil, false
            :none
          else
            :sessions
          end
        end
      end
    end

    register_plugin(:conditional_sessions, ConditionalSessions)
  end
end
