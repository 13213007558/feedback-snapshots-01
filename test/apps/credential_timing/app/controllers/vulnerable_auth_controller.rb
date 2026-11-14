class VulnerableAuthController < ApplicationController
  # Plain == joined by short-circuit &&: the password comparison is skipped
  # whenever the username mismatches.
  def plain_equals_and_and
    authenticate_or_request_with_http_basic do |username, password|
      username == FixtureSecrets.admin_user && password == FixtureSecrets.admin_password
    end
  end

  # secure_compare on both sides, but still combined with &&. Constant-time
  # primitives do not remove the short-circuit between the two checks.
  def secure_compare_and_and
    authenticate_or_request_with_http_basic do |username, password|
      ActiveSupport::SecurityUtils.secure_compare(username, FixtureSecrets.admin_user) &&
        Rack::Utils.secure_compare(password, FixtureSecrets.admin_password)
    end
  end

  # Digest-then-== is fixed length, but the && still short-circuits between
  # the username and password checks.
  def digest_and_and
    authenticate_or_request_with_http_basic do |username, password|
      Digest::SHA256.hexdigest(username) == FixtureSecrets.expected_user_digest &&
        Digest::SHA256.hexdigest(password) == FixtureSecrets.expected_pass_digest
    end
  end

  # Local variables wrapping the credential input, then an unsafe == pair.
  def local_wrapping_equals
    authenticate_or_request_with_http_basic do |username, password|
      candidate_user = username
      candidate_pass = password
      candidate_user == FixtureSecrets.admin_user && candidate_pass == FixtureSecrets.admin_password
    end
  end

  # An unknown helper whose name merely contains "secure". It cannot be
  # explained from a known calling convention, so it must be flagged.
  def unknown_named_secure_helper
    authenticate_or_request_with_http_basic do |username, password|
      FixtureSecrets.super_secure_compare(username, FixtureSecrets.admin_user) &&
        FixtureSecrets.super_secure_compare(password, FixtureSecrets.admin_password)
    end
  end

  # A single plain == (only one credential checked here). It cannot leak the
  # *combination* order, but == itself is not fixed length.
  def single_equals
    authenticate_or_request_with_http_basic do |username, _password|
      username == FixtureSecrets.admin_user
    end
  end
end
