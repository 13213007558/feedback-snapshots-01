# frozen_string_literal: true

require 'openssl'
require_relative 'error'
require_relative 'base64'
require_relative 'x5c_key_finder/policy'
require_relative 'x5c_key_finder/error_builder'

module JWT
  # Selects a JWT verification key from an x5c header certificate chain.
  #
  # Certificates in the x5c header are treated as *chain material only*. Trust
  # anchors are always supplied by the server through +root_certificates+; a
  # certificate included in the header can never promote itself to a trust
  # anchor. A chain that validates does not by itself authorize the leaf
  # certificate to sign a particular kind of credential, so callers state the
  # certificate purpose, the verification time and the revocation evidence
  # policy they require.
  #
  # Policy is applied to a per-call OpenSSL::X509::StoreContext. The
  # OpenSSL::X509::Store built by this class is not mutated after
  # initialization, so calls running concurrently with different times or
  # policies cannot affect each other.
  #
  # See https://tools.ietf.org/html/rfc7515#section-4.1.6
  class X5cKeyFinder
    # Creates a key finder.
    #
    # @param root_certificates [Array<OpenSSL::X509::Certificate>] server-provided trust anchors.
    # @param crls [Array<OpenSSL::X509::CRL>, nil] CRLs available to the default policy.
    # @param options [Hash] default policy; may be given as the second argument as well.
    # @option options [Symbol, Integer] :purpose certificate purpose (defaults to :any).
    # @option options [Time, DateTime, Integer, nil] :at_time verification time (defaults to the
    #   current time). A DateTime or numeric epoch is accepted.
    # @option options [Symbol] :revocation :require (default) or :none.
    # @option options [Array<OpenSSL::X509::CRL>] :crls CRLs used by this finder.
    def initialize(root_certificates = nil, crls = nil, options = {}, **keyword_options)
      if crls.is_a?(Hash)
        options = symbolize_hash(crls).merge(symbolize_hash(options)).merge(symbolize_hash(keyword_options))
      else
        options = symbolize_hash(options).merge(symbolize_hash(keyword_options))
        options[:crls] = crls if crls && !options.key?(:crls)
      end

      root_certificates = options.delete(:root_certificates) if root_certificates.nil? && options.key?(:root_certificates)
      crls = options.delete(:crls)
      raise ArgumentError, 'Root certificates must be specified' unless root_certificates

      @root_certificates = Array(root_certificates)
      @default_policy = Policy.build(options)
      @store = build_store(@root_certificates, crls)
    end

    # Validates the x5c header certificate chain under the requested policy and
    # returns the public key of the first certificate (the signing certificate).
    #
    # The returned key is the one the caller must use for JWT signature
    # verification; validating the chain alone does not prove possession of the
    # corresponding private key.
    #
    # @param x5c_header_or_certificates [Array<String>, Array<OpenSSL::X509::Certificate>]
    # @param options [Hash] per-call policy overrides.
    # @option options [Symbol, Integer] :purpose certificate purpose.
    # @option options [Time, DateTime, Integer, nil] :at_time verification time.
    # @option options [Symbol] :revocation :require or :none.
    # @option options [Array<OpenSSL::X509::CRL>] :crls CRLs for this call only.
    # @return [OpenSSL::PKey::PKey] the signing certificate's public key.
    # @raise [JWT::CertificateVerificationError] when the chain cannot be accepted.
    def from(x5c_header_or_certificates, options = {}, **keyword_options)
      signed_certificates = parse_certificates(Array(x5c_header_or_certificates))
      signing_certificate, *certificate_chain = signed_certificates

      raise_missing_certificate_error!(certificate_chain) if signing_certificate.nil?

      options = normalize_options_hash(options, keyword_options)
      policy = Policy.build(options, base: @default_policy)
      store = options.key?(:crls) ? build_store(@root_certificates, options[:crls]) : @store
      store_context = OpenSSL::X509::StoreContext.new(store, signing_certificate, certificate_chain)
      apply_policy(store_context, policy)

      return signing_certificate.public_key if store_context.verify

      raise ErrorBuilder.build(store_context, certificate_chain)
    end

    private

    def normalize_options_hash(options, keyword_options)
      symbolize_hash(options).merge(symbolize_hash(keyword_options))
    end

    def symbolize_hash(hash)
      Policy.resolve_keys(hash || {})
    end

    def build_store(root_certificates, crls)
      store = OpenSSL::X509::Store.new
      root_certificates.each { |certificate| store.add_cert(certificate) }
      Array(crls).each { |crl| store.add_crl(crl) }
      store
    end

    def apply_policy(store_context, policy)
      store_context.purpose = policy.purpose

      flags = 0
      if policy.revocation_required?
        flags |= OpenSSL::X509::V_FLAG_CRL_CHECK
        flags |= OpenSSL::X509::V_FLAG_CRL_CHECK_ALL
      end

      if policy.at_time
        flags |= OpenSSL::X509::V_FLAG_USE_CHECK_TIME
        store_context.time = policy.at_time
      end

      store_context.flags = flags
    end

    def parse_certificates(x5c_header_or_certificates)
      if x5c_header_or_certificates.all?(OpenSSL::X509::Certificate)
        x5c_header_or_certificates
      else
        x5c_header_or_certificates.map do |encoded|
          OpenSSL::X509::Certificate.new(::JWT::Base64.url_decode(encoded))
        end
      end
    end

    def raise_missing_certificate_error!(certificate_chain)
      raise JWT::CertificateChainError.new(
        'Certificate verification failed: no certificates in x5c header.',
        reason: :missing_certificate,
        certificate_chain: certificate_chain
      )
    end
  end
end
