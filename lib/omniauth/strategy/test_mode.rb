module OmniAuth
  module Strategy
    # Runs the request and callback phases against OmniAuth.config.mock_auth
    # instead of the provider when OmniAuth.config.test_mode is enabled.
    module TestMode
      # This is called in lieu of the normal request process
      # in the event that OmniAuth has been configured to be
      # in test mode.
      def mock_call!(*)
        if request_call?
          mock_request_call
        elsif on_callback_path?
          mock_callback_call
        else
          call_app!
        end
      rescue StandardError => e
        handle_phase_error(e)
      end

      def mock_request_call
        setup_phase
        return failure_response if failure_dispatched?

        rejection = validation_rejection
        return rejection if rejection

        session['omniauth.params'] = omniauth_params

        run_hook(:before_request_phase)
        return failure_response if failure_dispatched?

        store_origin if options.origin_param

        result = redirect(callback_url)

        run_hook(:after_request_phase)
        failure_dispatched? ? failure_response : result
      end

      def mock_callback_call
        setup_phase
        return failure_response if failure_dispatched?

        origin = session.delete('omniauth.origin')
        env['omniauth.origin'] ||= origin
        env['omniauth.origin'] = nil if env.fetch('omniauth.origin').eql?('')
        env['omniauth.params'] = session.delete('omniauth.params') || {}

        mocked_auth = OmniAuth.mock_auth_for(name)
        failed = mocked_auth.instance_of?(Symbol)

        # As in a real callback, the hook runs before the auth result is
        # written, so a hook that fails (or writes then fails) cannot leave
        # a successful auth hash for the app or the failure handler.
        run_hook(:before_callback_phase)
        return failure_response if failure_dispatched?
        return fail!(mocked_auth) if failed

        env['omniauth.auth'] = mocked_auth
        call_app!
      end
    end
  end
end
