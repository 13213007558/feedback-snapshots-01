# frozen_string_literal: true

require "digest"

module Sidekiq
  module Job
    module Iterable
      # Binds persisted iteration progress to the approval scope which
      # authorized that progress.
      #
      # A cursor is only a position, never a permission. The digest below is
      # stored alongside the cursor so a later run can prove that the cursor
      # belongs to the same approval scope. A changed or revoked scope makes
      # the old cursor unusable.
      #
      # The scope descriptor must be JSON-serializable. Do not put secrets or
      # per-record payloads in it: the digest is derived from the descriptor
      # and may be shown to operators.
      module ScopeBinding
        module_function

        # Stable SHA-256 digest of a scope descriptor.
        #
        # Hash key order and symbol/string keys do not affect the digest.
        def digest(scope)
          Digest::SHA256.hexdigest(Sidekiq.dump_json(canonicalize(scope)))
        end

        # Recursively normalizes a JSON-like value so equivalent descriptors
        # produce identical bytes.
        def canonicalize(value)
          case value
          when Hash
            value.each_with_object({}) do |(key, val), result|
              result[key.to_s] = canonicalize(val)
            end.sort.to_h
          when Array
            value.map { |element| canonicalize(element) }
          else
            value
          end
        end
      end
    end
  end
end
