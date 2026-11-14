# frozen_string_literal: true

require_relative "../test_helper"

class SignaturePolicyTest < Minitest::Test
  def test_policy_normalizes_and_exact_matches_method_names
    policy = OAuth::Signature::Policy.new("HMAC-SHA1", "RSA-SHA1")

    assert_equal %w[hmac-sha1 rsa-sha1], policy.allowed_methods
    assert policy.allows?("HMAC-SHA1")
    assert policy.allows?("rsa-sha1")
    refute policy.allows?("hmac-sha256")
    refute policy.allows?("plaintext")
  end

  def test_policy_is_independent_of_the_global_registry
    # A method installed as a plugin is still rejected unless explicitly allowed.
    assert_includes OAuth::Signature.available_methods, "plaintext"

    policy = OAuth::Signature::Policy.new("hmac-sha1")

    refute policy.allows?("plaintext")
    refute policy.allows?("rsa-sha1")
  end

  def test_policy_rejects_empty_and_duplicate_allow_lists
    assert_raises(ArgumentError) { OAuth::Signature::Policy.new }
    error = assert_raises(ArgumentError) do
      OAuth::Signature::Policy.new("hmac-sha1", "HMAC-SHA1")
    end
    assert_match(/duplicate/i, error.message)
  end

  def test_plugin_for_rejects_duplicate_protocol_parameters_without_resolver
    request = mock_request({
      "oauth_signature_method" => %w[HMAC-SHA1 RSA-SHA1]
    })
    policy = OAuth::Signature::Policy.new("hmac-sha1", "rsa-sha1")

    assert_raises(OAuth::AmbiguousSignatureMethod) do
      policy.plugin_for!(request)
    end
  end

  def test_plugin_for_rejects_missing_method
    request = mock_request({})
    policy = OAuth::Signature::Policy.new("hmac-sha1")

    assert_raises(OAuth::AmbiguousSignatureMethod) do
      policy.plugin_for!(request)
    end
  end

  def test_plugin_for_rejects_forbidden_method_even_when_registered
    request = mock_request({ "oauth_signature_method" => "PLAINTEXT" })
    policy = OAuth::Signature::Policy.new("hmac-sha1")

    error = assert_raises(OAuth::UnauthorizedSignatureMethod) do
      policy.plugin_for!(request)
    end
    assert_equal "plaintext", error.method
    assert_equal %w[hmac-sha1], error.allowed_methods
  end

  def test_plugin_for_rejects_allowed_method_without_registered_plugin
    registry = { "hmac-sha1" => OAuth::Signature::HMAC::SHA1 }
    policy = OAuth::Signature::Policy.new("hmac-sha1", "rsa-sha1", registry: registry)
    request = mock_request({ "oauth_signature_method" => "RSA-SHA1" })

    assert_raises(OAuth::UnauthorizedSignatureMethod) do
      policy.plugin_for!(request)
    end
  end

  def test_plaintext_is_opt_in_only
    refute OAuth::Signature::Policy.new("hmac-sha1").allows?("plaintext")
    assert OAuth::Signature::Policy.new("plaintext").allows?("plaintext")
  end

  def test_undecorated_third_party_method_defaults_to_shared_secret
    custom = Class.new(OAuth::Signature::Base) do
      implements "custom-secret-method"
    end

    assert_equal :shared_secret, custom.key_type
    assert custom.compatible_credential?("a-secret")
    refute custom.compatible_credential?(OpenSSL::PKey::RSA.new(2048))
  ensure
    OAuth::Signature.available_methods.delete("custom-secret-method")
  end

  def test_credential_compatibility_hmac_accepts_string_only
    assert OAuth::Signature::HMAC::SHA1.compatible_credential?("a-shared-secret")
    assert OAuth::Signature::HMAC::SHA256.compatible_credential?("a-shared-secret")
    rsa_key = OpenSSL::PKey::RSA.new(2048)
    refute OAuth::Signature::HMAC::SHA1.compatible_credential?(rsa_key)
  end

  def test_credential_compatibility_rsa_rejects_bare_hmac_secret
    rsa_key = OpenSSL::PKey::RSA.new(2048)
    cert = OpenSSL::X509::Certificate.new(File.read(cert_path))
    assert OAuth::Signature::RSA::SHA1.compatible_credential?(rsa_key)
    assert OAuth::Signature::RSA::SHA1.compatible_credential?(rsa_key.to_pem)
    assert OAuth::Signature::RSA::SHA1.compatible_credential?(cert)
    refute OAuth::Signature::RSA::SHA1.compatible_credential?("kd94hf93k423kf44")
  end

  private

  def mock_request(parameters)
    OAuth::RequestProxy::MockRequest.new(
      "method" => "POST",
      "uri" => "http://photos.example.net/photos",
      "parameters" => parameters
    )
  end

  def cert_path
    "#{File.dirname(__FILE__)}/../keys/rsa.cert"
  end
end
