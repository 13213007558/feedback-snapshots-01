# frozen_string_literal: true

require "openssl"
require "webauthn/authenticator_response"

module WebAuthn
  # Protocol for resolving attestation root certificates from an ordered list
  # of trusted finder sources (for example an internal allowlist followed by a
  # public root source).
  #
  # A finder keeps implementing +find(attestation_format:, aaguid:,
  # attestation_certificate_key_id:)+. For compatibility it may return an
  # Array of OpenSSL::X509::Certificate objects or nil. New finders can return
  # a Result to explicitly deny a credential or report that the source is
  # temporarily unavailable; those states cannot be expressed with an array.
  module AttestationRootCertificatesFinder
    class InvalidResultError < Error; end
    class InvalidUnavailablePolicyError < Error; end

    # The source made an explicit negative policy decision. Verification must
    # stop and must not fall back to a later finder or to default roots.
    class DeniedError < VerificationError; end

    # The source could not answer. The relying party's trusted configuration
    # decides whether resolution may continue or verification must fail.
    class UnavailableError < VerificationError; end

    class Result
      STATUSES = [:found, :not_found, :denied, :unavailable].freeze

      attr_reader :status, :certificates, :source, :reason

      def initialize(status:, certificates: [], source: nil, reason: nil)
        @status = self.class.normalize_status(status)
        @certificates = normalize_certificates(certificates).freeze
        @source = source
        @reason = reason

        if @status == :found && @certificates.empty?
          raise InvalidResultError, "A found result must include at least one certificate"
        end
      end

      class << self
        def found(certificates, source: nil, reason: nil)
          Found.new(certificates: certificates, source: source, reason: reason)
        end
        alias hit found

        def not_found(source: nil, reason: nil)
          NotFound.new(source: source, reason: reason)
        end
        alias no_match not_found

        def denied(source: nil, reason: nil)
          Denied.new(source: source, reason: reason)
        end
        alias deny denied

        def unavailable(source: nil, reason: nil)
          Unavailable.new(source: source, reason: reason)
        end
        alias temporarily_unavailable unavailable

        def normalize_status(status)
          normalized = status.to_s.strip.downcase.gsub(/[\s-]+/, "_").to_sym

          unless STATUSES.include?(normalized)
            raise InvalidResultError,
                  "Unknown attestation root certificate finder result status: #{status.inspect}"
          end

          normalized
        end

        # Converts a finder return value into a Result while retaining the
        # source that produced it. Arrays and nil are the legacy protocol.
        def normalize(value, source: nil)
          case value
          when Result
            value.with_source(value.source || source)
          when nil, false
            NotFound.new(source: source)
          else
            normalize_array(value, source: source)
          end
        end

        def build(status, certificates: [], source: nil, reason: nil)
          case normalize_status(status)
          when :found
            Found.new(certificates: certificates, source: source, reason: reason)
          when :not_found
            NotFound.new(source: source, reason: reason)
          when :denied
            Denied.new(source: source, reason: reason)
          when :unavailable
            Unavailable.new(source: source, reason: reason)
          end
        end

        private

        def normalize_array(value, source:)
          unless value.respond_to?(:to_ary)
            raise InvalidResultError, "Unsupported finder return value: #{value.inspect}"
          end

          certificates = value.to_ary.compact

          if certificates.empty?
            NotFound.new(source: source)
          elsif certificates.all? { |certificate| certificate.is_a?(OpenSSL::X509::Certificate) }
            Found.new(certificates: certificates, source: source)
          else
            raise InvalidResultError, "Finder returned non-certificate values: #{value.inspect}"
          end
        end
      end

      def found?
        status == :found
      end
      alias hit? found?

      def not_found?
        status == :not_found
      end
      alias no_match? not_found?
      alias miss? not_found?

      def denied?
        status == :denied
      end
      alias rejected? denied?

      def unavailable?
        status == :unavailable
      end
      alias temporarily_unavailable? unavailable?

      def certs
        certificates
      end

      def root_certificates
        certificates
      end

      def to_a
        certificates
      end

      def with_source(new_source)
        self.class.build(status, certificates: certificates, source: new_source, reason: reason)
      end

      private

      def normalize_certificates(certificates)
        Array(certificates).compact.each_with_object([]) do |certificate, normalized|
          unless certificate.is_a?(OpenSSL::X509::Certificate)
            raise InvalidResultError, "Expected an OpenSSL::X509::Certificate, got #{certificate.inspect}"
          end

          normalized << certificate
        end
      end
    end

    class Found < Result
      def initialize(certificates: [], source: nil, reason: nil)
        super(status: :found, certificates: certificates, source: source, reason: reason)
      end
    end

    class NotFound < Result
      def initialize(source: nil, reason: nil)
        super(status: :not_found, source: source, reason: reason)
      end
    end
    NoMatch = NotFound

    class Denied < Result
      def initialize(source: nil, reason: nil)
        super(status: :denied, source: source, reason: reason)
      end
    end
    Deny = Denied

    class Unavailable < Result
      def initialize(source: nil, reason: nil)
        super(status: :unavailable, source: source, reason: reason)
      end
    end
    TemporarilyUnavailable = Unavailable

    Result::Hit = Found
    Result::NoMatch = NotFound
    Result::Denied = Denied
    Result::Unavailable = Unavailable

    # Resolves roots from finders in order.
    #
    # - found:       stop and return the certificates and their source
    # - not_found:   continue with the next source
    # - denied:      stop immediately; never fall back
    # - unavailable: stop unless the relying party's trusted policy permits
    #                continuing with the next source
    class Resolver
      DEFAULT_UNAVAILABLE_POLICY = :fail

      CONTINUE_POLICIES = [:continue, :skip, :fallback, :allow_fallback, true].freeze
      FAIL_POLICIES = [:fail, :fail_closed, :closed, :deny, :raise, false].freeze

      attr_reader :finders, :relying_party, :unavailable_policy

      def initialize(finders = [], relying_party: nil, unavailable_policy: nil)
        @finders = Array(finders)
        @relying_party = relying_party
        @unavailable_policy = unavailable_policy
      end

      def resolve(attestation_format: nil, aaguid: nil, attestation_certificate_key_id: nil)
        last_unavailable = nil

        finders.each do |finder|
          result = finder_result(
            finder,
            attestation_format: attestation_format,
            aaguid: aaguid,
            attestation_certificate_key_id: attestation_certificate_key_id
          )

          case result.status
          when :found, :denied
            return result
          when :unavailable
            last_unavailable = result
            return result unless continue_on_unavailable?(result)
          end
        end

        # A source that could not answer is not the same as a definitive
        # no-match. Even when policy permits trying later sources, none of them
        # finding a root must not silently become a no-match that would then
        # fall back to default roots.
        last_unavailable || NotFound.new
      end

      private

      def finder_result(finder, **arguments)
        source = source_for(finder)

        Result.normalize(finder.find(**arguments), source: source)
      rescue DeniedError => error
        Denied.new(source: source, reason: error.message)
      rescue UnavailableError => error
        Unavailable.new(source: source, reason: error.message)
      rescue StandardError => error
        Unavailable.new(source: source, reason: error)
      end

      def source_for(finder)
        finder.respond_to?(:source) ? finder.source : finder
      end

      def continue_on_unavailable?(result)
        policy = effective_unavailable_policy

        if policy.respond_to?(:call)
          !!policy.call(result)
        elsif CONTINUE_POLICIES.include?(policy)
          true
        elsif FAIL_POLICIES.include?(policy) || policy.nil?
          false
        else
          raise InvalidUnavailablePolicyError,
                "Unknown attestation root certificates finder unavailable policy: #{policy.inspect}"
        end
      end

      def effective_unavailable_policy
        return unavailable_policy unless unavailable_policy.nil?

        if relying_party.respond_to?(:attestation_root_certificates_finder_unavailable_policy)
          relying_party.attestation_root_certificates_finder_unavailable_policy
        else
          DEFAULT_UNAVAILABLE_POLICY
        end
      end
    end

    module_function

    def resolve(finders, **options)
      resolve_options = options.slice(:relying_party, :unavailable_policy)
      lookup_options = options.reject { |key, _| resolve_options.key?(key) }

      Resolver.new(finders, **resolve_options).resolve(**lookup_options)
    end
  end

  # Alternative spellings kept as convenience aliases.
  AttestationRootCertificateFinder = AttestationRootCertificatesFinder
  AttestationRootFinder = AttestationRootCertificatesFinder

  AttestationRootCertificateResult = AttestationRootCertificatesFinder::Result
  AttestationRootCertificateHit = AttestationRootCertificatesFinder::Found
  AttestationRootCertificateNoMatch = AttestationRootCertificatesFinder::NotFound
  AttestationRootCertificateDenied = AttestationRootCertificatesFinder::Denied
  AttestationRootCertificateUnavailable = AttestationRootCertificatesFinder::Unavailable

  AttestationRootCertificateDeniedError = AttestationRootCertificatesFinder::DeniedError
  AttestationRootCertificateUnavailableError = AttestationRootCertificatesFinder::UnavailableError
  AttestationRootFinderDeniedError = AttestationRootCertificatesFinder::DeniedError
  AttestationRootFinderUnavailableError = AttestationRootCertificatesFinder::UnavailableError
  AttestationRootFinderTemporarilyUnavailableError = AttestationRootCertificatesFinder::UnavailableError
end
