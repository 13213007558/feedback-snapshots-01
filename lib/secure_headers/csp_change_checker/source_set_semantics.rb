# frozen_string_literal: true

module SecureHeaders
  module CspChangeChecker
    # Sound subset reasoning over the token grammar produced by
    # EffectivePolicyParser. The model is intentionally one-directional: when it
    # cannot prove that an old source covers a new one, it treats the new source
    # as additional capability (potential loosening) rather than guessing. This
    # makes false "provably tightened" results impossible at the cost of more
    # "cannot determine" verdicts.
    module SourceSetSemantics
      module_function

      # True when every URL matched by +new_token+ is also matched by
      # +old_token+ (i.e. old_token is at least as permissive).
      def covers?(old_token, new_token)
        return false if old_token[:kind] == :none || new_token[:kind] == :none

        case old_token[:kind]
        when :star
          star_covers?(new_token)
        when :keyword
          new_token[:kind] == :keyword && old_token[:keyword] == new_token[:keyword]
        when :scheme
          scheme_covers?(old_token, new_token)
        when :host
          host_covers?(old_token, new_token)
        else
          false
        end
      end

      def star_covers?(new_token)
        # "*" only expresses host-source wildcards. It never stands in for
        # keywords or scheme sources such as data:/blob:, so those are treated
        # as not covered (conservative direction).
        new_token[:kind] == :host || new_token[:kind] == :star
      end

      def scheme_covers?(old_token, new_token)
        case new_token[:kind]
        when :scheme
          old_token[:scheme] == new_token[:scheme]
        when :host
          # A bare host source matches every scheme; pinning the old grant to a
          # single scheme cannot cover a scheme-less new grant.
          !new_token[:scheme].nil? && old_token[:scheme] == new_token[:scheme]
        else
          false
        end
      end

      def host_covers?(old_token, new_token)
        return false unless new_token[:kind] == :host
        # A concrete host grant can never cover the bare "*" wildcard.

        host_covers_host?(old_token, new_token) &&
          scheme_covers_host?(old_token, new_token) &&
          port_covers?(old_token, new_token)
      end

      def host_covers_host?(old_token, new_token)
        if old_token[:wildcard]
          base = old_token[:host]
          if new_token[:wildcard]
            new_token[:host] != base && new_token[:host].end_with?(".#{base}")
          else
            new_token[:host] != base && new_token[:host].end_with?(".#{base}")
          end
        else
          !new_token[:wildcard] && old_token[:host] == new_token[:host]
        end
      end

      def scheme_covers_host?(old_token, new_token)
        return true if old_token[:scheme].nil? && new_token[:scheme].nil?
        return false if old_token[:scheme].nil? || new_token[:scheme].nil?
        old_token[:scheme] == new_token[:scheme]
      end

      def port_covers?(old_token, new_token)
        old_port = old_token[:port]
        new_port = new_token[:port]
        return true if old_port.nil? && new_port.nil?
        return false if old_port.nil? # bare old host implies default-port matching only in
        # practice; a port-pinned new grant is narrower, so old cannot cover it.
        return true if old_port == "**"
        return false if new_port.nil? || new_port == "**"
        old_port == new_port
      end

      # A concrete resource that is allowed by +token+ (used as evidence when a
      # newly added source is not covered by the old policy).
      def witness_for(directive, token)
        case token[:kind]
        when :star
          "https://arbitrary-host.example/resource (matched by * in #{directive})"
        when :keyword
          "capability #{token[:keyword]} granted in #{directive}"
        when :scheme
          scheme_witness(directive, token[:scheme])
        when :host
          host_witness(directive, token)
        else
          "unmodelled source #{token[:raw]} in #{directive}"
        end
      end

      def scheme_witness(directive, scheme)
        case scheme
        when "data"
          "data:text/html,<script>alert(1)</script> (data: in #{directive})"
        when "blob"
          "blob:https://app.example/00000000-0000 (blob: in #{directive})"
        when "http"
          "http://insecure.example/resource (http: in #{directive})"
        else
          "#{scheme}://any-host.example/resource (#{scheme}: in #{directive})"
        end
      end

      def host_witness(directive, token)
        scheme = token[:scheme] || "https"
        host = token[:wildcard] ? "sub.#{token[:host]}" : token[:host]
        port = token[:port].nil? ? "" : ":#{token[:port]}"
        "#{scheme}://#{host}#{port}/resource (newly allowed host in #{directive})"
      end

      # Drops an effective 'none' whenever other sources exist, mirroring the
      # generator's reject_all_values_if_none behaviour. A lone 'none' maps to
      # an empty allow-set (deny all).
      def normalize_none(tokens)
        non_none = tokens.reject { |t| t[:kind] == :none }
        has_none = tokens.any? { |t| t[:kind] == :none }
        return [] if has_none && non_none.empty?
        non_none
      end
    end
  end
end
