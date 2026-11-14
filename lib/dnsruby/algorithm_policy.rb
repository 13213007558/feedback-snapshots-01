# --
# Copyright 2024 Nominet UK
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ++

module Dnsruby
  class Dnssec
    # A verification failure caused by the DNSSEC algorithm policy rather than
    # by a bad signature. Kept separate from other VerifyErrors so callers can
    # tell "Dnsruby cannot do this algorithm" from "this deployment forbids it"
    # and from "the signature did not verify".
    class AlgorithmError < VerifyError
      attr_reader :algorithm, :digest_type, :policy

      def initialize(message, algorithm: nil, digest_type: nil, policy: nil)
        @algorithm = algorithm
        @digest_type = digest_type
        @policy = policy
        super(message)
      end
    end

    # The algorithm has no implementation in this version of Dnsruby.
    class AlgorithmUnsupportedError < AlgorithmError; end

    # The algorithm is implemented, but the validation call's policy excludes
    # it.
    class AlgorithmDisabledError < AlgorithmError; end

    # DS digest algorithms use the same distinction as signing algorithms.
    class DsDigestUnsupportedError < AlgorithmUnsupportedError; end
    class DsDigestDisabledError < AlgorithmDisabledError; end

    # Selects which DNSSEC algorithms a single validation call may use.
    #
    # A constraint applies to every DS, DNSKEY and RRSIG on a trust path. A
    # validation succeeds only if at least one complete path uses permitted
    # algorithms and verifies cryptographically. Cached keys are filtered when
    # they are used, so a key learned before the policy was supplied cannot
    # grant new trust under it.
    #
    # There is deliberately no process-wide default: a call that does not pass
    # a policy keeps the library's historical behaviour.
    class AlgorithmPolicy
      # Algorithms implemented by SingleVerifier#verify_rrset_with_key:
      # DSA, DSA-NSEC3-SHA1, RSASHA1, RSASHA1-NSEC3-SHA1, RSASHA256,
      # RSASHA512, ECDSAP256SHA256 and ECDSAP384SHA384.
      SUPPORTED_ALGORITHMS = [3, 5, 6, 7, 8, 10, 13, 14].freeze

      # Digest algorithms implemented by RR::DS#digest_key: SHA-1, SHA-256
      # and SHA-384.
      SUPPORTED_DIGESTS = [1, 2, 4].freeze

      SCOPE_KEY = :dnsruby_dnssec_algorithm_policy_scope

      # Rejections are collected for the whole validation call. If every path
      # is exhausted, the most informative failure is reported to the caller.
      class Scope # :nodoc: all
        attr_reader :policy, :rejections

        def initialize(policy)
          @policy = policy
          @rejections = []
        end

        def reject(error)
          @rejections << error unless @rejections.any? { |e| e.class == error.class && e.message == error.message }
          error
        end
      end
      private_constant :Scope

      attr_reader :algorithms, :disabled_algorithms, :ds_digest_types

      # Build an allow-list, a deny-list, or both. Values may be algorithm
      # numbers, names (for example "RSASHA256") or Symbols. Passing :all for
      # the allow-list permits every implemented algorithm. An empty
      # allow-list permits none. +ds_digest_types+ accepts DS digest type
      # numbers or names.
      def initialize(algorithms: nil, allowed_algorithms: nil, allow: nil,
                     disabled_algorithms: nil, denied_algorithms: nil, deny: nil,
                     ds_digest_types: nil, ds_digests: nil, digest_types: nil)
        allowed = pick(algorithms, allowed_algorithms, allow)
        disabled = pick(disabled_algorithms, denied_algorithms, deny)
        digests = pick(ds_digest_types, ds_digests, digest_types)
        @algorithms = normalize_list(allowed, allow_all: true)
        @disabled_algorithms = normalize_list(disabled, allow_all: false) || []
        @ds_digest_types = normalize_digest_list(digests)
        freeze
      end

      def self.allow(*algorithms)
        new(algorithms: algorithms)
      end

      def self.deny(*algorithms)
        new(disabled_algorithms: algorithms)
      end

      # Every implemented algorithm; useful as a baseline before adding a
      # deny-list.
      def self.permissive
        new
      end

      def allows_algorithm?(algorithm)
        rejection_for_algorithm(algorithm).nil?
      end

      def allows_ds_digest?(digest_type)
        rejection_for_digest(digest_type).nil?
      end

      def rejection_for_algorithm(algorithm, context: 'DNSKEY')
        code = self.class.code_for(algorithm)
        return AlgorithmUnsupportedError.new(
          "#{context} algorithm #{describe_algorithm(code)} is not supported by Dnsruby",
          algorithm: code, policy: self
        ) unless SUPPORTED_ALGORITHMS.include?(code)
        unless algorithm_allowed?(code)
          return AlgorithmDisabledError.new(
            "#{context} algorithm #{describe_algorithm(code)} is disabled by the validation algorithm policy",
            algorithm: code, policy: self
          )
        end
        nil
      end

      def rejection_for_digest(digest_type, context: 'DS')
        code = self.class.code_for_digest(digest_type)
        return DsDigestUnsupportedError.new(
          "#{context} digest type #{describe_digest(code)} is not supported by Dnsruby",
          digest_type: code, policy: self
        ) unless SUPPORTED_DIGESTS.include?(code)
        unless digest_allowed?(code)
          return DsDigestDisabledError.new(
            "#{context} digest type #{describe_digest(code)} is disabled by the validation algorithm policy",
            digest_type: code, policy: self
          )
        end
        nil
      end

      def to_h
        {
          algorithms: @algorithms,
          disabled_algorithms: @disabled_algorithms,
          ds_digest_types: @ds_digest_types
        }
      end

      def ==(other)
        other.is_a?(self.class) && to_h == other.to_h
      end
      alias eql? ==

      def hash
        to_h.hash
      end

      def inspect
        "#<#{self.class} algorithms=#{@algorithms.inspect} disabled=#{@disabled_algorithms.inspect} ds_digest_types=#{@ds_digest_types.inspect}>"
      end

      class << self
        # Resolve the optional second positional argument and keyword options
        # of a verification method into [policy, keys]. A KeyCache, RRSet, RR
        # or array of RRs in the second position is the legacy +keys+ argument;
        # any other value is an algorithm policy. Keywords may name the lists
        # directly (algorithms:, disabled_algorithms:, ds_digest_types:).
        def resolve(keys, options, positional = nil)
          if keys && !keys_argument?(keys)
            reject_duplicate_policy!(options)
            options = options.merge(policy: keys)
            keys = nil
          end
          unless positional.nil?
            raise ArgumentError, "Unexpected DNSSEC algorithm policy argument: #{positional.class}" unless policy_argument?(positional)
            reject_duplicate_policy!(options)
            options = options.merge(policy: positional)
          end
          [extract(options), keys]
        end

        def reject_duplicate_policy!(options)
          return unless options.key?(:policy) || options.key?(:algorithm_policy) ||
            policy_option_keys.any? { |key| options.key?(key) }
          raise ArgumentError, 'DNSSEC algorithm policy specified more than once'
        end

        # Accept the attached Message#algorithm_policy form as well.
        def for_message(msg)
          return nil unless msg && msg.respond_to?(:algorithm_policy)
          coerce(msg.algorithm_policy)
        end

        def coerce(value)
          case value
          when nil
            nil
          when self
            value
          when Array
            new(algorithms: value)
          when Hash
            new(**value)
          else
            raise ArgumentError, "Expected a DNSSEC AlgorithmPolicy, Array or Hash; got #{value.class}"
          end
        end

        # Resolve keyword policy options. Only one of :policy,
        # :algorithm_policy or a set of list keywords may be supplied.
        # Unknown keywords are rejected so typos cannot disable enforcement.
        def extract(options)
          opts = options.dup
          explicit = nil
          if opts.key?(:policy)
            explicit = opts.delete(:policy)
          end
          if opts.key?(:algorithm_policy)
            raise ArgumentError, 'DNSSEC algorithm policy specified more than once' if explicit
            explicit = opts.delete(:algorithm_policy)
          end
          option_keys = opts.keys & policy_option_keys
          unless option_keys.empty?
            raise ArgumentError, 'DNSSEC algorithm policy specified more than once' if explicit
            explicit = opts.select { |key, _| policy_option_keys.include?(key) }
            option_keys.each { |key| opts.delete(key) }
          end
          raise ArgumentError, "Unknown DNSSEC algorithm policy option(s): #{opts.keys.join(', ')}" unless opts.empty?
          coerce(explicit)
        end

        def policy_argument?(value)
          value.is_a?(self) || value.is_a?(Hash) || value.is_a?(Array)
        end

        # Keys accepted by #verify(..., keys) rather than by a policy keyword.
        def keys_argument?(value)
          return true if value.nil?
          return true if value.is_a?(KeyCache) || value.is_a?(RRSet) || value.is_a?(RR)
          value.is_a?(Array) && value.all? { |item| item.is_a?(RR) }
        end

        def code_for(algorithm)
          return algorithm.code if algorithm.respond_to?(:code)
          return algorithm if algorithm.is_a?(Integer)
          return Integer(algorithm, 10) if algorithm.is_a?(String) && algorithm =~ /\A\d+\z/
          Algorithms.new(normalize_name(algorithm)).code
        end

        def code_for_digest(digest_type)
          return digest_type.code if digest_type.respond_to?(:code)
          return digest_type if digest_type.is_a?(Integer)
          return Integer(digest_type, 10) if digest_type.is_a?(String) && digest_type =~ /\A\d+\z/
          RR::DS::DigestTypes.new(normalize_name(digest_type)).code
        end

        def error_message(error)
          error.respond_to?(:message) ? error.message.to_s : error.to_s
        end

        def error_rank(error)
          return 9 unless error
          case error
          when ValidationLimitError then -1
          when AlgorithmUnsupportedError then 2
          when AlgorithmDisabledError then 3
          when VerifyError
            # A cryptographic failure is stronger evidence than a path that was
            # merely filtered out by policy: never hide it behind a weak,
            # policy-disabled signature.
            error_message(error) =~ /cryptograph|signature failed/i ? 1 : 4
          else 5
          end
        end

        # Choose deterministically: rank first, then message. This keeps
        # results independent of DS, DNSKEY and RRSIG ordering.
        def preferred_error(current, candidate)
          return current unless candidate
          return candidate unless current
          current_rank = error_rank(current)
          candidate_rank = error_rank(candidate)
          return candidate if candidate_rank < current_rank
          return current if current_rank < candidate_rank
          error_message(candidate) < error_message(current) ? candidate : current
        end

        def current
          Thread.current[SCOPE_KEY]&.policy
        end

        def current_scope
          Thread.current[SCOPE_KEY]
        end

        def with(policy)
          return yield if policy.nil?
          policy = coerce(policy)
          parent = Thread.current[SCOPE_KEY]
          scope = Scope.new(policy)
          Thread.current[SCOPE_KEY] = scope
          begin
            yield policy
          ensure
            parent.rejections.concat(scope.rejections) if parent
            Thread.current[SCOPE_KEY] = parent
          end
        end

        def reject(error)
          current_scope&.reject(error)
          error
        end

        # Best policy failure seen during this call, if any.
        def best_error
          scope = current_scope
          return nil unless scope && !scope.rejections.empty?
          scope.rejections.min_by { |error| [error_rank(error), error_message(error)] }
        end

        private

        def policy_option_keys
          [:algorithms, :allowed_algorithms, :allow,
           :disabled_algorithms, :denied_algorithms, :deny,
           :ds_digest_types, :ds_digests, :digest_types]
        end

        def normalize_name(value)
          value.is_a?(Symbol) ? value.to_s : value
        end
      end

      private

      def pick(*values)
        values.each { |value| return value unless value.nil? }
        nil
      end

      def normalize_list(value, allow_all:)
        return nil if value.nil?
        values = value.is_a?(Array) ? value : [value]
        if allow_all && !values.empty? && values.all? { |entry| entry == :all || entry.to_s.casecmp('all').zero? }
          return nil
        end
        normalized = values.map do |entry|
          raise ArgumentError, 'Use :all, not a mix of :all and algorithm numbers' if
            entry == :all || (entry.respond_to?(:to_s) && entry.to_s.casecmp('all').zero?)
          self.class.code_for(entry)
        end
        normalized.uniq.sort.freeze
      end

      def normalize_digest_list(value)
        return nil if value.nil?
        values = value.is_a?(Array) ? value : [value]
        if !values.empty? && values.all? { |entry| entry == :all || entry.to_s.casecmp('all').zero? }
          return nil
        end
        values.map do |entry|
          raise ArgumentError, 'Use :all, not a mix of :all and digest types' if
            entry == :all || (entry.respond_to?(:to_s) && entry.to_s.casecmp('all').zero?)
          self.class.code_for_digest(entry)
        end.uniq.sort.freeze
      end

      def algorithm_allowed?(code)
        return false if @disabled_algorithms.include?(code)
        @algorithms.nil? || @algorithms.include?(code)
      end

      def digest_allowed?(code)
        @ds_digest_types.nil? || @ds_digest_types.include?(code)
      end

      def describe_algorithm(code)
        name = Algorithms.new(code).string
        name ? "#{code} (#{name})" : code.to_s
      end

      def describe_digest(code)
        name = RR::DS::DigestTypes.new(code).string
        name ? "#{code} (#{name})" : code.to_s
      end
    end
  end
end

module Dnsruby
  # Convenience alias outside Dnssec.
  AlgorithmPolicy = Dnssec::AlgorithmPolicy unless const_defined?(:AlgorithmPolicy, false)
end
