# Generated phase trace

| Scenario | Events |
| --- | --- |
| request | request_validation_phase -> before_request_phase -> request_phase -> after_request_phase |
| request, setup | setup_phase -> request_validation_phase -> before_request_phase -> request_phase -> after_request_phase |
| request, validation returns a denial | request_validation_phase |
| request, validation raises | request_validation_phase -> on_failure(authenticity_error) |
| request, before hook calls fail! | request_validation_phase -> before_request_phase -> on_failure(blocked_by_hook) |
| request, setup calls fail! | setup_phase -> on_failure(unknown_tenant) |
| callback | before_callback_phase -> callback_phase -> auth_hash_written -> downstream_app(auth) |
| callback, hook raises | before_callback_phase -> on_failure(hook rejected callback) |
| callback, hook calls fail! | before_callback_phase -> on_failure(tenant_mismatch) |
| OPTIONS | before_options_phase |
| OPTIONS, hook calls fail! | before_options_phase -> on_failure(options_denied) |
| non-auth path | downstream_app(no_auth) |
| other_phase path | other_phase |
| test-mode request | request_validation_phase -> before_request_phase -> after_request_phase |
| test-mode callback | before_callback_phase -> downstream_app(auth) |
| test-mode callback, mocked failure | before_callback_phase -> on_failure(invalid_credentials) |
