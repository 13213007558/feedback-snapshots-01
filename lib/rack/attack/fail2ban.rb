# frozen_string_literal: true

require 'securerandom'

module Rack
  class Attack
    class Fail2Ban
      # Describes the ban (penalty) currently in effect for a discriminator.
      # +version+ identifies this specific generation of the penalty and is
      # required to lift it manually via .unban.
      BanInfo = Struct.new(:discriminator, :version)

      class << self
        def filter(discriminator, options)
          bantime   = options[:bantime]   or raise ArgumentError, "Must pass bantime option"
          findtime  = options[:findtime]  or raise ArgumentError, "Must pass findtime option"
          maxretry  = options[:maxretry]  or raise ArgumentError, "Must pass maxretry option"

          if banned?(discriminator)
            # Return true for blocklist
            true
          elsif yield
            fail!(discriminator, bantime, findtime, maxretry)
          end
        end

        def reset(discriminator, options)
          findtime = options[:findtime] or raise ArgumentError, "Must pass findtime option"
          cache.reset_count("#{key_prefix}:count:#{discriminator}", findtime)
          # Clear ban flag just in case it's there
          cache.delete("#{key_prefix}:ban:#{discriminator}")
        end

        def banned?(discriminator)
          cache.read("#{key_prefix}:ban:#{discriminator}") ? true : false
        end

        # Returns a BanInfo for the ban currently in effect, or nil when the
        # discriminator is not banned. Reading never refreshes the ban's
        # time to live.
        def ban_info(discriminator)
          version = cache.read("#{key_prefix}:ban:#{discriminator}")
          version && BanInfo.new(discriminator, version)
        end

        # Lifts the ban only when +version+ still identifies the ban
        # currently in effect, so a stale unban request can never cancel a
        # penalty that was issued (or re-issued) after +version+ was read.
        #
        # Returns :unbanned (the ban identified by +version+ is gone; when it
        # was lifted by this call the fail count is reset as well), :changed
        # (a different, newer ban is in effect and was left untouched) or
        # :storage_failure (the cache store could not perform the delete).
        def unban(discriminator, options, version:)
          findtime = options[:findtime] or raise ArgumentError, "Must pass findtime option"

          case cache.delete_if_equal("#{key_prefix}:ban:#{discriminator}", version)
          when :deleted
            cache.reset_count("#{key_prefix}:count:#{discriminator}", findtime)
            :unbanned
          when :absent
            :unbanned
          when :mismatch
            :changed
          else
            :storage_failure
          end
        end

        protected

        def key_prefix
          'fail2ban'
        end

        def fail!(discriminator, bantime, findtime, maxretry)
          count = cache.count("#{key_prefix}:count:#{discriminator}", findtime)
          if count >= maxretry
            ban!(discriminator, bantime)
          end

          true
        end

        private

        def ban!(discriminator, bantime)
          cache.write("#{key_prefix}:ban:#{discriminator}", generate_ban_version, bantime)
        end

        def generate_ban_version
          "#{Time.now.to_i}:#{SecureRandom.hex(8)}"
        end

        def cache
          Rack::Attack.cache
        end
      end
    end
  end
end
