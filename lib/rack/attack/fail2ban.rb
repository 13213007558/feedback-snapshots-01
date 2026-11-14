# frozen_string_literal: true

module Rack
  class Attack
    class Fail2Ban
      class << self
        def filter(discriminator, options)
          bantime   = options[:bantime]   or raise ArgumentError, "Must pass bantime option"
          findtime  = options[:findtime]  or raise ArgumentError, "Must pass findtime option"
          maxretry  = options[:maxretry]  or raise ArgumentError, "Must pass maxretry option"
          observe   = options.fetch(:observe, false)

          if banned?(discriminator, observe: observe)
            # Return true for blocklist
            true
          elsif yield
            fail!(discriminator, bantime, findtime, maxretry, observe: observe)
          end
        end

        def reset(discriminator, options)
          findtime = options[:findtime] or raise ArgumentError, "Must pass findtime option"
          observe  = options.fetch(:observe, false)
          cache(observe).reset_count("#{key_prefix}:count:#{discriminator}", findtime)
          # Clear ban flag just in case it's there
          cache(observe).delete("#{key_prefix}:ban:#{discriminator}")
        end

        def banned?(discriminator, observe: false)
          cache(observe).read("#{key_prefix}:ban:#{discriminator}") ? true : false
        end

        # Explicitly carries a virtual ban, recorded while the rule was in
        # observe mode, into the enforced namespace. Observed bans are never
        # carried over implicitly, so promoting a rule to enforced mode does
        # not suddenly punish users observed during the observation period.
        def promote_observed!(discriminator, bantime)
          return false unless banned?(discriminator, observe: true)

          ban!(discriminator, bantime)
          true
        end

        protected

        def key_prefix
          'fail2ban'
        end

        def fail!(discriminator, bantime, findtime, maxretry, observe: false)
          count = cache(observe).count("#{key_prefix}:count:#{discriminator}", findtime)
          if count >= maxretry
            ban!(discriminator, bantime, observe: observe)
          end

          true
        end

        private

        def ban!(discriminator, bantime, observe: false)
          cache(observe).write("#{key_prefix}:ban:#{discriminator}", 1, bantime)
        end

        def cache(observe = false)
          observe ? Rack::Attack.observed_cache : Rack::Attack.cache
        end
      end
    end
  end
end
