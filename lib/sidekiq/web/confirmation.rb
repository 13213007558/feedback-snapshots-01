# frozen_string_literal: true

require "digest"
require "openssl"
require "securerandom"

module Sidekiq
  class Web
    ##
    # Confirmation tokens bind a destructive Web UI action to the exact
    # entry an operator saw on a Retry/Scheduled/Dead listing.
    #
    # A token records the source set, the entry key (score + jid), the
    # SHA256 digest of the raw job payload, the actions the entry supports
    # and a random nonce.  Because the digest and score are part of the
    # signed payload, a job which is moved by the scheduler and later
    # reappears under the same jid will not validate against the old token.
    #
    # Tokens are signed with a process-independent secret kept in Redis so
    # any Web UI process can verify a token created by another process.
    # Per-action completion is recorded in a short lived Redis key, which
    # lets a replay report that the action already completed instead of
    # pushing a second copy of the job.
    #
    # This class is internal API for the Web UI.
    module Confirmation
      TOKEN_VERSION = 1
      TOKEN_TTL = 3600
      MAX_AGE = 24 * 60 * 60
      SECRET_KEY = "skq-web-action-secret"
      LEDGER_PREFIX = "skq-web-action"

      module_function

      def digest(value)
        Digest::SHA256.hexdigest(value.to_s)
      end

      def issue(set:, key:, value:, actions:, jid:, i: Time.now.to_i)
        payload = {
          "v" => TOKEN_VERSION,
          "s" => set.to_s,
          "k" => key.to_s,
          "d" => digest(value),
          "a" => Array(actions).map(&:to_s),
          "j" => jid.to_s,
          "n" => SecureRandom.hex(12),
          "i" => i.to_i
        }
        encoded = encode(Sidekiq.dump_json(payload))
        "#{encoded}.#{signature(encoded)}"
      end

      # Returns the token payload for a well formed, correctly signed token.
      # Any tampering or malformed input yields nil.
      def decode(token)
        return nil unless token.is_a?(String)

        encoded, sig = token.split(".", 2)
        return nil if encoded.nil? || sig.nil? || encoded.empty?
        return nil unless secure_compare(signature(encoded), sig)

        payload = Sidekiq.load_json(decode64(encoded))
        return nil unless payload.is_a?(Hash) && payload["v"] == TOKEN_VERSION
        return nil unless payload["s"].is_a?(String) && payload["k"].is_a?(String)
        return nil if payload["i"].to_i + MAX_AGE < Time.now.to_i
        return nil unless payload["d"].is_a?(String) && payload["n"].is_a?(String)
        return nil unless payload["a"].is_a?(Array)

        payload
      rescue JSON::ParserError
        nil
      end

      def ledger_key(nonce, action)
        "#{LEDGER_PREFIX}:#{nonce}:#{action}"
      end

      # Atomically claim the right to execute the token's action.  Returns
      # :claimed when this caller should proceed, :completed when the action
      # already finished and :uncertain when another attempt started but never
      # recorded an outcome.
      def claim(nonce, action)
        key = ledger_key(nonce, action)
        created, state, = Sidekiq.redis do |conn|
          conn.multi do |transaction|
            transaction.hsetnx(key, "state", "running")
            transaction.hget(key, "state")
            transaction.expire(key, TOKEN_TTL)
          end
        end

        return :claimed if created == 1 && state == "running"
        return :completed if state == "done"
        :uncertain
      end

      # Read the ledger without claiming it.
      def state(nonce, action)
        case Sidekiq.redis { |conn| conn.hget(ledger_key(nonce, action), "state") }
        when "running" then :claimed
        when "done" then :completed
        else :free
        end
      end

      def finish(nonce, action)
        Sidekiq.redis do |conn|
          conn.multi do |transaction|
            transaction.hset(ledger_key(nonce, action), "state", "done", "finished_at", Time.now.to_i)
            transaction.expire(ledger_key(nonce, action), TOKEN_TTL)
          end
        end
        true
      end

      def release(nonce, action)
        Sidekiq.redis { |conn| conn.del(ledger_key(nonce, action)) }
        true
      end

      def reset_secret!
        Thread.current[:sidekiq_web_action_secret] = nil
      end

      def secret
        cached = Thread.current[:sidekiq_web_action_secret]
        return cached if cached

        value = Sidekiq.redis do |conn|
          current = conn.get(SECRET_KEY)
          unless current
            candidate = SecureRandom.hex(32)
            created = conn.set(SECRET_KEY, candidate, "NX")
            current = created ? candidate : conn.get(SECRET_KEY)
          end
          current
        end
        Thread.current[:sidekiq_web_action_secret] = value
      end

      def signature(encoded)
        OpenSSL::HMAC.hexdigest("SHA256", secret, encoded)
      end

      def encode(string)
        [string].pack("m0").tr("+/", "-_").delete("=")
      end

      def decode64(string)
        padding = "=" * ((4 - string.length % 4) % 4)
        (string.tr("-_", "+/") + padding).unpack1("m0")
      end

      def secure_compare(left, right)
        return false unless left.bytesize == right.bytesize

        OpenSSL.fixed_length_secure_compare(left, right)
      end
    end
  end
end
