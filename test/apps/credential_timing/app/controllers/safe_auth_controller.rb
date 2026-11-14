class SafeAuthController < ApplicationController
  # Both secure_compare calls are evaluated unconditionally and their boolean
  # results are combined with the non-short-circuit & operator.
  def secure_compare_with_bitwise_and
    authenticate_or_request_with_http_basic do |username, password|
      user_ok = ActiveSupport::SecurityUtils.secure_compare(username, FixtureSecrets.admin_user)
      pass_ok = Rack::Utils.secure_compare(password, FixtureSecrets.admin_password)
      user_ok & pass_ok
    end
  end

  # Fixed-length digest comparisons, combined with non-short-circuit &. Both
  # digests are always computed and both == comparisons always run.
  def digest_with_bitwise_and
    authenticate_or_request_with_http_basic do |username, password|
      user_ok = Digest::SHA256.hexdigest(username) == FixtureSecrets.expected_user_digest
      pass_ok = Digest::SHA256.hexdigest(password) == FixtureSecrets.expected_pass_digest
      user_ok & pass_ok
    end
  end

  # Local-variable booleans joined by &: the two secure_compare calls happen
  # before any boolean combination, so neither can be skipped.
  def local_booleans_bitwise_and
    authenticate_or_request_with_http_basic do |username, password|
      user_ok = secure_compare(username, FixtureSecrets.admin_user)
      pass_ok = secure_compare(password, FixtureSecrets.admin_password)
      user_ok & pass_ok
    end
  end

  # Enumerable all? forces every comparison; there is no && short-circuit.
  def all_comparisons
    authenticate_or_request_with_http_basic do |username, password|
      [
        ActiveSupport::SecurityUtils.secure_compare(username, FixtureSecrets.admin_user),
        Rack::Utils.secure_compare(password, FixtureSecrets.admin_password)
      ].all?
    end
  end

  # OpenSSL's documented fixed-length constant-time primitive, combined with
  # a non-short-circuit operator.
  def openssl_fixed_length
    authenticate_or_request_with_http_basic do |username, password|
      user_ok = OpenSSL.fixed_length_secure_compare(username, FixtureSecrets.admin_user)
      pass_ok = OpenSSL.fixed_length_secure_compare(password, FixtureSecrets.admin_password)
      user_ok & pass_ok
    end
  end
end
