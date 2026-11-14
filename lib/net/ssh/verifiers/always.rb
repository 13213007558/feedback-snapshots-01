require 'net/ssh/errors'
require 'net/ssh/known_hosts'
require 'net/ssh/verifiers/trust_evidence'

module Net
  module SSH
    module Verifiers
      # Does a strict host verification, looking the server up in the known
      # host files to see if a key has already been seen for this server. If this
      # server does not appear in any host file, an exception will be raised
      # (HostKeyUnknown). This is in contrast to the "Strict" class, which will
      # silently add the key to your known_hosts file. If the server does appear at
      # least once, but the key given does not match any known for the server, an
      # exception will be raised (HostKeyMismatch). A key marked @revoked in a
      # host file is always refused (HostKeyRevoked).
      # Otherwise, this returns true.
      #
      # When the :verify_host_key_evidence option is true, every raised
      # HostKeyError carries a Net::SSH::Verifiers::TrustEvidence object in
      # #trust_evidence describing the entries and checks behind the decision.
      # The collection is read-only over the existing search and never changes
      # which key is selected.
      class Always
        def verify(arguments)
          evidence = build_evidence(arguments)
          refuse_revoked!(arguments, evidence)

          host_keys = arguments[:session].host_keys

          # We've never seen this host before, so raise an exception.
          if host_keys.empty?
            record_cache_miss(evidence, host_keys, arguments)
            process_cache_miss(host_keys, arguments, HostKeyUnknown, "is unknown", :unknown, evidence)
          end

          # Find the known-hosts entry whose key matches the presented certificate.
          found_key = host_keys.find do |key|
            if key.respond_to?(:matches_key?)
              key.matches_key?(arguments[:key])
            else
              key.ssh_type == arguments[:key].ssh_type && key.to_blob == arguments[:key].to_blob
            end
          end

          # No matching entry found — key is not recognized. Observe every entry
          # in search order for the evidence, without altering the selection above.
          if evidence
            host_keys.each do |entry|
              evidence.record_entry(entry, key_match: entry.equal?(found_key))
            end
          end

          unless found_key
            process_cache_miss(host_keys, arguments, HostKeyMismatch, "does not match", :mismatch, evidence)
          end

          # For @cert-authority entries, enforce the certificate constraints
          # OpenSSH checks in sshkey_cert_check_authority. A certificate signed by
          # the trusted CA but failing any of these is rejected with
          # HostKeyMismatch (not HostKeyUnknown) so AcceptNew does not swallow the
          # failure and remember the rejected certificate.
          verify_certificate!(found_key, host_keys, arguments, evidence)

          evidence&.accept
          true
        end

        def verify_signature(&block)
          yield
        end

        private

        # Builds the trust evidence only when the session opted in. Custom
        # verifier sessions without #options (e.g. hand-built test doubles) are
        # treated as opted out.
        def build_evidence(arguments)
          session = arguments[:session]
          options = session.options if session.respond_to?(:options)
          return nil unless options && options[:verify_host_key_evidence]

          TrustEvidence.new(host: session.host_keys.host,
                            key: arguments[:key],
                            fingerprint: arguments[:fingerprint])
        end

        # Custom :known_hosts objects may return a host_keys collection with no
        # revocation support. Evidence is built lazily here because the local
        # tunnel verifier consults revocation before running the full verify.
        def refuse_revoked!(arguments, evidence = nil)
          host_keys = arguments[:session].host_keys
          return unless host_keys.respond_to?(:revoked?) && host_keys.revoked?(arguments[:key])

          evidence ||= build_evidence(arguments)
          if evidence
            if host_keys.respond_to?(:each)
              host_keys.each { |entry| evidence.record_entry(entry, key_match: entry.matches_key?(arguments[:key])) }
            end
            if host_keys.respond_to?(:revoked_matches)
              host_keys.revoked_matches(arguments[:key]).each do |entry|
                evidence.record_entry(entry, key_match: true)
              end
            end
            evidence.reject(:revoked, "is revoked")
          end

          exception = HostKeyRevoked.new("fingerprint #{arguments[:fingerprint]} " +
                                         "is revoked for #{host_keys.host.inspect}")
          exception.data = arguments
          exception.trust_evidence = evidence
          raise exception
        end

        # Records the entries seen during a cache miss so an unknown host still
        # carries its (empty) evidence and a mismatch keeps every pinned entry.
        def record_cache_miss(evidence, host_keys, arguments)
          return unless evidence

          host_keys.each do |entry|
            key_match = entry.respond_to?(:matches_key?) ?
                          entry.matches_key?(arguments[:key]) :
                          entry.ssh_type == arguments[:key].ssh_type && entry.to_blob == arguments[:key].to_blob
            evidence.record_entry(entry, key_match: key_match)
          end
        end

        # Enforces the @cert-authority certificate constraints for entries that
        # implement them (Net::SSH::HostKeyEntries::CertAuthority). Non-certificate
        # entries do not respond to these predicates and are left untouched. Each
        # check is recorded in the evidence as :pass or :fail; a check that does
        # not apply to the entry stays :not_run.
        def verify_certificate!(entry, host_keys, arguments, evidence)
          cert = arguments[:key]

          if entry.respond_to?(:matches_validity?)
            passed = entry.matches_validity?(cert)
            evidence&.record_check(:certificate_validity, passed ? :pass : :fail)
            unless passed
              reason = if cert.valid_before && cert.valid_before < Time.now
                         "Certificate has expired"
                       else
                         "Certificate is not yet valid"
                       end
              process_cache_miss(host_keys, arguments, HostKeyMismatch, reason, :certificate_validity, evidence)
            end
          end

          if entry.respond_to?(:matches_principal?)
            passed = entry.matches_principal?(cert, host_keys.hostname)
            evidence&.record_check(:certificate_hostname, passed ? :pass : :fail)
            unless passed
              process_cache_miss(host_keys, arguments, HostKeyMismatch,
                                 "Certificate invalid: name is not a listed principal",
                                 :certificate_hostname, evidence)
            end
          end

          if entry.respond_to?(:matches_type?)
            passed = entry.matches_type?(cert)
            evidence&.record_check(:certificate_type, passed ? :pass : :fail)
            unless passed
              process_cache_miss(host_keys, arguments, HostKeyMismatch,
                                 "Certificate invalid: not a host certificate",
                                 :certificate_type, evidence)
            end
          end

          return unless entry.respond_to?(:critical_options_supported?)

          passed = entry.critical_options_supported?(cert)
          evidence&.record_check(:critical_options, passed ? :pass : :fail)
          return if passed

          process_cache_miss(host_keys, arguments, HostKeyMismatch,
                             "Certificate invalid: unsupported critical option",
                             :critical_options, evidence)
        end

        def process_cache_miss(host_keys, args, exc_class, message, reason, evidence = nil)
          exception = exc_class.new("fingerprint #{args[:fingerprint]} " +
                                    "#{message} for #{host_keys.host.inspect}")
          exception.data = args
          exception.callback = Proc.new do
            host_keys.add_host_key(args[:key])
          end
          if evidence
            evidence.reject(reason, message)
            exception.trust_evidence = evidence
          end
          raise exception
        end
      end
    end
  end
end
