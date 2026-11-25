# frozen_string_literal: true

require "active_job/arguments"
require "active_support/current_attributes"

module Sidekiq
  ##
  # Automatically save and load any current attributes in the execution context
  # so context attributes "flow" from Rails actions into any associated jobs.
  # This can be useful for multi-tenancy, i18n locale, timezone, any implicit
  # per-request attribute. See +ActiveSupport::CurrentAttributes+.
  #
  # For multiple current attributes, pass an array of current attributes.
  #
  # Pass a Hash to declare which attributes are allowed to leave the current
  # process and be used by a job. Only the allowlisted attributes are saved
  # into the job payload and loaded back into the context, on every execution
  # of the job, including retries after the policy has changed. Any attribute
  # missing from the allowlist stays local to the process and is never visible
  # in the queue, retry/dead sets, logs or a later worker run.
  #
  # @example
  #
  #   # in your initializer
  #   require "sidekiq/middleware/current_attributes"
  #   Sidekiq::CurrentAttributes.persist("Myapp::Current")
  #   # or multiple current attributes
  #   Sidekiq::CurrentAttributes.persist(["Myapp::Current", "Myapp::OtherCurrent"])
  #   # or restrict which attributes may be persisted and reused
  #   Sidekiq::CurrentAttributes.persist("Myapp::Current" => [:tenant_id, :request_id])
  #
  module CurrentAttributes
    Serializer = ::ActiveJob::Arguments

    # Normalizes the internal cattrs mapping so each value has the shape
    # +["CurrentAttributesClassName", <allowed-attributes-or-nil>]+ while
    # remaining compatible with the legacy +{"cattr" => "ClassName"}+ form.
    module Normalization
      private

      def normalize(cattrs)
        cattrs.transform_values do |value|
          case value
          when Array
            # already normalized: ["Klass", [:attr, ...]]
            value
          else
            # legacy shape: "Klass"
            [value, nil]
          end
        end
      end
    end

    class Save
      include Sidekiq::ClientMiddleware
      include Normalization

      def initialize(cattrs)
        @cattrs = normalize(cattrs)
      end

      def call(_, job, _, _)
        @cattrs.each do |key, (strklass, allowed)|
          if !job.has_key?(key)
            attrs = filter(strklass.constantize.attributes, allowed)
            # Retries can push the job N times, we don't
            # want retries to reset cattr. #5692, #5090
            job[key] = Serializer.serialize(attrs) if attrs.any?
          end
        end
        yield
      end

      private

      def filter(attrs, allowed)
        return attrs unless allowed

        attrs.select { |attr, _| allowed.include?(attr) }
      end
    end

    class Load
      include Sidekiq::ServerMiddleware
      include Normalization

      def initialize(cattrs)
        @cattrs = normalize(cattrs)
      end

      def call(_, job, *, &block)
        klass_attrs = {}

        @cattrs.each do |key, (strklass, allowed)|
          next unless job.has_key?(key)

          attrs = Serializer.deserialize(job[key]).to_h.transform_keys(&:to_sym)
          # Re-apply the current policy when the job is executed. This covers
          # payloads enqueued before the allowlist was narrowed (e.g. a job
          # sitting in the retry set) and attributes removed from the class.
          attrs = attrs.select { |attr, _| allowed.include?(attr) } if allowed
          klass_attrs[strklass.constantize] = attrs
        end

        wrap(klass_attrs.to_a, &block)
      end

      private

      def wrap(klass_attrs, &block)
        klass, attrs = klass_attrs.shift
        return block.call unless klass

        retried = false

        begin
          set_succeeded = false
          klass.set(attrs) do
            set_succeeded = true
            wrap(klass_attrs, &block)
          end
        rescue NoMethodError
          # Don't retry if the no method error didn't come from current attributes
          raise if retried || set_succeeded

          # It is possible that the `CurrentAttributes` definition
          # was changed before the job started processing.
          attrs = attrs.select { |attr| klass.respond_to?(attr) }
          retried = true
          retry
        end
      end
    end

    class << self
      # +klass_or_array+ accepts a CurrentAttributes class/name, an Array of
      # classes/names, or a Hash mapping a class/name to the Array of attribute
      # names allowed to be persisted. A missing or +nil+ allowlist means every
      # attribute of the class may be persisted.
      def persist(klass_or_array, config = Sidekiq.default_configuration)
        cattrs = build_cattrs_hash(klass_or_array)

        config.client_middleware.prepend Load, cattrs
        config.client_middleware.add Save, cattrs
        config.server_middleware.prepend Load, cattrs
      end

      private

      def build_cattrs_hash(klass_or_array)
        entries =
          if klass_or_array.is_a?(Hash)
            klass_or_array.map { |klass, allowed| [klass, allowed] }
          elsif klass_or_array.is_a?(Array)
            klass_or_array.map { |entry| entry.is_a?(Array) ? entry : [entry, nil] }
          else
            [[klass_or_array, nil]]
          end

        entries.each_with_index.with_object({}) do |(entry, index), hash|
          klass, allowed = entry
          # nil means "no allowlist": every attribute may be persisted.
          allowed = allowed&.map(&:to_sym)
          hash[key_at(index)] = [klass.to_s, allowed]
        end
      end

      def key_at(index)
        (index == 0) ? "cattr" : "cattr_#{index}"
      end
    end
  end
end
