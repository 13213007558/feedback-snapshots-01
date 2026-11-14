# frozen_string_literal: true

require_relative "../test_helper"

# Two interfaces loading the exact same global plugin set but enforcing
# different signature method policies.
class SignatureVerifierTest < Minitest::Test
  def setup
    # Both endpoints see every installed plugin; their policies differ.
    @shared_registry = OAuth::Signature.available_methods.dup
    assert_includes @shared_registry, "hmac-sha1"
    assert_includes @shared_registry, "rsa-sha1"
    assert_includes @shared_registry, "plaintext"

    @hmac_endpoint = OAuth::Signature::Verifier.new(
      OAuth::Signature::Policy.new("hmac-sha1", registry: @shared_registry)
    )
    @rsa_endpoint = OAuth::Signature::Verifier.new(
      OAuth::Signature::Policy.new("rsa-sha1", registry: @shared_registry)
    )

    @rsa_private_key = OpenSSL::PKey::RSA.new(File.read(pem_path))
    @hmac_secret = "kd94hf93k423kf44"
  end

  # --- forbidden method never reaches the credential resolver -------------

  def test_hmac_endpoint_rejects_rsa_request_without_calling_resolver
    request = signed_rsa_request
    resolver_calls = 0

    error = assert_raises(OAuth::UnauthorizedSignatureMethod) do
      @hmac_endpoint.verify(request) do |*_args|
        resolver_calls += 1
        [nil, @rsa_private_key]
      end
    end

    assert_equal "rsa-sha1", error.method
    assert_equal 0, resolver_calls, "credential resolver must not run for a forbidden method"
  end

  def test_rsa_endpoint_rejects_hmac_request_without_calling_resolver
    request = signed_hmac_request
    resolver_calls = 0

    assert_raises(OAuth::UnauthorizedSignatureMethod) do
      @rsa_endpoint.verify(request) do |*_args|
        resolver_calls += 1
        [nil, @hmac_secret]
      end
    end

    assert_equal 0, resolver_calls, "credential resolver must not run for a forbidden method"
  end

  def test_either_endpoint_rejects_plaintext_without_calling_resolver
    request = signed_plaintext_request
    resolver_calls = 0
    resolver = proc do |*_args|
      resolver_calls += 1
      [nil, @hmac_secret]
    end

    assert_raises(OAuth::UnauthorizedSignatureMethod) { @hmac_endpoint.verify(request, &resolver) }
    assert_raises(OAuth::UnauthorizedSignatureMethod) { @rsa_endpoint.verify(request, &resolver) }
    assert_equal 0, resolver_calls
  end

  # --- legitimate requests succeed on their matching endpoint --------------

  def test_hmac_endpoint_accepts_valid_hmac_request
    request = signed_hmac_request
    calls = 0

    result = @hmac_endpoint.verify(request) do |*_args|
      calls += 1
      [nil, @hmac_secret]
    end

    assert result
    assert_equal 1, calls
  end

  def test_rsa_endpoint_accepts_valid_rsa_request
    request = signed_rsa_request
    calls = 0

    result = @rsa_endpoint.verify(request) do |*_args|
      calls += 1
      [nil, @rsa_private_key]
    end

    assert result
    assert_equal 1, calls
  end

  def test_rsa_endpoint_accepts_public_certificate_credential
    request = signed_rsa_request
    certificate = OpenSSL::X509::Certificate.new(File.read(cert_path))

    result = @rsa_endpoint.verify(request, consumer_secret: certificate)

    assert result
  end

  # --- credential type must match the method -------------------------------

  def test_rsa_endpoint_rejects_hmac_secret_used_as_rsa_key
    request = signed_rsa_request

    assert_raises(OAuth::IncompatibleCredential) do
      @rsa_endpoint.verify(request) { [nil, @hmac_secret] }
    end
  end

  def test_hmac_endpoint_rejects_rsa_key_used_as_shared_secret
    request = signed_hmac_request

    assert_raises(OAuth::IncompatibleCredential) do
      @hmac_endpoint.verify(request) { [nil, @rsa_private_key] }
    end
  end

  # --- duplicates, tampering, and no fallback ------------------------------

  def test_duplicate_signature_method_parameter_is_rejected
    request = signed_hmac_request
    request.parameters["oauth_signature_method"] = %w[HMAC-SHA1 RSA-SHA1]
    calls = 0

    assert_raises(OAuth::AmbiguousSignatureMethod) do
      @hmac_endpoint.verify(request) { calls += 1; [nil, @hmac_secret] }
    end
    assert_equal 0, calls
  end

  def test_tampered_signature_fails_verification
    request = signed_hmac_request
    request.parameters["oauth_signature"] = "tampered"

    refute @hmac_endpoint.verify(request) { [nil, @hmac_secret] }
  end

  def test_plugin_error_propagates_without_falling_back_to_another_method
    exploding = Class.new(OAuth::Signature::Base) do
      implements "exploding-method"
      key_type :shared_secret

      def verify
        raise "plugin failure"
      end
    end

    registry = @shared_registry.merge("exploding-method" => exploding)
    verifier = OAuth::Signature::Verifier.new(
      OAuth::Signature::Policy.new("exploding-method", "hmac-sha1", registry: registry)
    )
    request = mock_request("oauth_signature_method" => "exploding-method")

    error = assert_raises(RuntimeError) do
      verifier.verify(request, consumer_secret: @hmac_secret)
    end
    assert_equal "plugin failure", error.message
  end

  def test_factory_helper_builds_a_policy_bound_verifier
    verifier = OAuth::Signature.verifier("hmac-sha1")

    assert_kind_of OAuth::Signature::Verifier, verifier
    assert verifier.verify(signed_hmac_request) { [nil, @hmac_secret] }
  end

  private

  def base_parameters(method_name)
    {
      "oauth_consumer_key" => "dpf43f3p2l4k3l03",
      "oauth_signature_method" => method_name,
      "oauth_timestamp" => "137131200",
      "oauth_nonce" => "wIjqoS",
      "oauth_version" => "1.0"
    }
  end

  def signed_hmac_request
    parameters = base_parameters("HMAC-SHA1")
    request = mock_request(parameters)
    parameters["oauth_signature"] = OAuth::Signature.sign(request, consumer_secret: @hmac_secret)
    request
  end

  def signed_rsa_request
    parameters = base_parameters("RSA-SHA1")
    request = mock_request(parameters)
    parameters["oauth_signature"] = OAuth::Signature.sign(
      request, consumer: OAuth::Consumer.new("dpf43f3p2l4k3l03", @rsa_private_key)
    )
    request
  end

  def signed_plaintext_request
    parameters = base_parameters("PLAINTEXT")
    request = mock_request(parameters)
    parameters["oauth_signature"] = OAuth::Signature.sign(request, consumer_secret: @hmac_secret)
    request
  end

  def mock_request(parameters)
    OAuth::RequestProxy::MockRequest.new(
      "method" => "POST",
      "uri" => "http://photos.example.net/photos",
      "parameters" => parameters
    )
  end

  def pem_path
    "#{File.dirname(__FILE__)}/../keys/rsa.pem"
  end

  def cert_path
    "#{File.dirname(__FILE__)}/../keys/rsa.cert"
  end
end
