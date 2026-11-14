# frozen_string_literal: true

require 'rack/protection'
require 'securerandom'
require 'openssl'
require 'base64'

module Rack
  module Protection
    ##
    # Prevented attack::   CSRF
    # Supported browsers:: all
    # More infos::         http://en.wikipedia.org/wiki/Cross-site_request_forgery
    #
    # This middleware only accepts requests other than <tt>GET</tt>,
    # <tt>HEAD</tt>, <tt>OPTIONS</tt>, <tt>TRACE</tt> if their given access
    # token matches the token included in the session.
    #
    # It checks the <tt>X-CSRF-Token</tt> header and the <tt>POST</tt> form
    # data.
    #
    # It is not OOTB-compatible with the {rack-csrf}[https://rubygems.org/gems/rack_csrf] gem.
    # For that, the following patch needs to be applied:
    #
    #   Rack::Protection::AuthenticityToken.default_options(key: "csrf.token", authenticity_param: "_csrf")
    #
    # == Options
    #
    # [<tt>:authenticity_param</tt>] the name of the param that should contain
    #                                the token on a request. Default value:
    #                                <tt>"authenticity_token"</tt>
    #
    # [<tt>:key</tt>] the name of the param that should contain
    #                 the token in the session. Default value: <tt>:csrf</tt>
    #
    # [<tt>:allow_if</tt>] a proc for custom allow/deny logic. Will be passed <tt>env</tt>
    #                      as the only arg and should return true if the request is allowed,
    #                      regardless of the authenticity token. Default is <tt>nil</tt>,
    #                      which means there is no special logic for allowing requests that
    #                      don't have a valid token.
    #
    # [<tt>:rotation_grace_period</tt>] how many seconds a rotated-out token
    #                                   generation stays valid for non-strict
    #                                   requests. Default value: <tt>300</tt>.
    #
    # [<tt>:max_previous_generations</tt>] how many rotated-out generations are
    #                                      kept at most. Default value: <tt>2</tt>.
    #
    # [<tt>:rotation_policy</tt>] <tt>:grace</tt> to accept unexpired previous
    #                             generations, <tt>:strict</tt> to only accept the
    #                             current generation, or a proc receiving
    #                             <tt>env</tt> and returning either, so sensitive
    #                             actions can opt into <tt>:strict</tt> per
    #                             request. Default value: <tt>:grace</tt>.
    #
    # [<tt>:identity</tt>] a session key (or a proc receiving the session) whose
    #                      value binds token generations to a login identity.
    #                      When the identity changes, previous generations stop
    #                      matching immediately. Default value: <tt>nil</tt>.
    #
    # [<tt>:clock</tt>] a proc returning the current time in epoch seconds.
    #                  Default value: <tt>-> { Time.now.to_i }</tt>.
    #
    # [Rack::Protection::Base options] any option supported by Rack::Protection::Base.
    #
    # == Rotating the token (e.g. after re-authentication)
    #
    #   Rack::Protection::AuthenticityToken.rotate!(session)
    #
    # +rotate!+ installs a fresh root token and keeps the outgoing one as a
    # previous generation, so forms rendered before the rotation keep working
    # for <tt>:rotation_grace_period</tt> seconds. The number of previous
    # generations is capped by <tt>:max_previous_generations</tt> and expired
    # generations are pruned on each rotation; accepting an old token never
    # extends its window. Requests resolved as <tt>:strict</tt> only accept
    # the current generation. Per-form tokens of a previous generation stay
    # bound to their original path and method.
    #
    # The session store must give rotations read-modify-write atomicity per
    # session (a concurrent request writing back a stale snapshot must not
    # resurrect the old root token or drop the previous-generation list), and
    # validation reads must observe the latest rotation (monotonic reads);
    # replication lag effectively widens the grace window. Cookie-based
    # stores cannot revoke tokens for clients that never receive the rotated
    # cookie, so prefer a server-side store when strong invalidation matters.
    #
    # == Example: Forms application
    #
    # To show what the AuthenticityToken does, this section includes a sample
    # program which shows two forms. One with, and one without a CSRF token
    # The one without CSRF token field will get a 403 Forbidden response.
    #
    # Install the gem, then run the program:
    #
    #   gem install 'rack-protection'
    #   puma server.ru
    #
    # Here is <tt>server.ru</tt>:
    #
    #   require 'rack/protection'
    #   require 'rack/session'
    #
    #   app = Rack::Builder.app do
    #     use Rack::Session::Cookie, secret: 'CHANGEMEaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    #     use Rack::Protection::AuthenticityToken
    #
    #     run -> (env) do
    #       [200, {}, [
    #         <<~EOS
    #           <!DOCTYPE html>
    #           <html lang="en">
    #           <head>
    #             <meta charset="UTF-8" />
    #             <title>rack-protection minimal example</title>
    #           </head>
    #           <body>
    #             <h1>Without Authenticity Token</h1>
    #             <p>This takes you to <tt>Forbidden</tt></p>
    #             <form action="" method="post">
    #               <input type="text" name="foo" />
    #               <input type="submit" />
    #             </form>
    #
    #             <h1>With Authenticity Token</h1>
    #             <p>This successfully takes you to back to this form.</p>
    #             <form action="" method="post">
    #               <input type="hidden" name="authenticity_token" value="#{Rack::Protection::AuthenticityToken.token(env['rack.session'])}" />
    #               <input type="text" name="foo" />
    #               <input type="submit" />
    #             </form>
    #           </body>
    #           </html>
    #         EOS
    #       ]]
    #     end
    #   end
    #
    #   run app
    #
    # == Example: Customize which POST parameter holds the token
    #
    # To customize the authenticity parameter for form data, use the
    # <tt>:authenticity_param</tt> option:
    #   use Rack::Protection::AuthenticityToken, authenticity_param: 'your_token_param_name'
    class AuthenticityToken < Base
      TOKEN_LENGTH = 32

      default_options authenticity_param: 'authenticity_token',
                      key: :csrf,
                      allow_if: nil,
                      rotation_grace_period: 300,
                      max_previous_generations: 2,
                      rotation_policy: :grace,
                      identity: nil,
                      clock: -> { Time.now.to_i }

      # Access the token from the given session.  Useful for building a
      # form that should include the current authenticity token.
      def self.token(session, path: nil, method: :post)
        new(nil).mask_authenticity_token(session, path: path, method: method)
      end

      def self.random_token
        SecureRandom.urlsafe_base64(TOKEN_LENGTH, padding: false)
      end

      # Rotate the session's root token, keeping the outgoing one as a
      # previous generation. Extra options (e.g. a custom <tt>:key</tt> or
      # <tt>:clock</tt>) should match the middleware configuration.
      def self.rotate!(session, **options)
        new(nil, options).rotate!(session)
      end

      def accepts?(env)
        session = session(env)
        set_token(session)

        safe?(env) ||
          valid_token?(env, env['HTTP_X_CSRF_TOKEN']) ||
          valid_token?(env, Request.new(env).params[options[:authenticity_param]]) ||
          options[:allow_if]&.call(env)
      rescue StandardError
        false
      end

      def mask_authenticity_token(session, path: nil, method: :post)
        set_token(session)

        real = real_token(session)
        token = if path && method
                  per_form_token(real, path, method)
                else
                  global_token(real)
                end

        mask_token(token)
      end

      # Replaces the session's root token with a fresh one and records the
      # outgoing token as a previous generation, so forms rendered before
      # the rotation stay valid for +options[:rotation_grace_period]+
      # seconds. Previous generations are pruned by age and capped at
      # +options[:max_previous_generations]+.
      def rotate!(session)
        set_token(session)

        generations = previous_generations(session)
        generations.unshift(
          'token' => session[options[:key]],
          'rotated_at' => now,
          'identity' => current_identity(session)
        )
        session[previous_key] =
          prune_generations(generations).first(options[:max_previous_generations])
        session[options[:key]] = self.class.random_token
      end

      GLOBAL_TOKEN_IDENTIFIER = '!real_csrf_token'
      private_constant :GLOBAL_TOKEN_IDENTIFIER

      private

      def set_token(session)
        session[options[:key]] ||= self.class.random_token
      end

      # Checks the client's masked token to see if it matches the
      # session token.
      def valid_token?(env, token)
        return false if token.nil? || !token.is_a?(String) || token.empty?

        session = session(env)

        begin
          token = decode_token(token)
        rescue ArgumentError # encoded_masked_token is invalid Base64
          return false
        end

        # See if it's actually a masked token or not. We should be able
        # to handle any unmasked tokens that we've issued without error.

        if unmasked_token?(token)
          valid_real_tokens(session, env).any? { |real| secure_compare(token, real) }
        elsif masked_token?(token)
          token = unmask_token(token)
          request = Request.new(env)

          valid_real_tokens(session, env).any? do |real|
            secure_compare(token, global_token(real)) ||
              secure_compare(token, real) ||
              secure_compare(token, per_form_token(real, request.path.chomp('/'), request.request_method))
          end
        else
          false # Token is malformed
        end
      end

      # Creates a masked version of the authenticity token that varies
      # on each request. The masking is used to mitigate SSL attacks
      # like BREACH.
      def mask_token(token)
        one_time_pad = SecureRandom.random_bytes(token.length)
        encrypted_token = xor_byte_strings(one_time_pad, token)
        masked_token = one_time_pad + encrypted_token
        encode_token(masked_token)
      end

      # Essentially the inverse of +mask_token+.
      def unmask_token(masked_token)
        # Split the token into the one-time pad and the encrypted
        # value and decrypt it
        token_length = masked_token.length / 2
        one_time_pad = masked_token[0...token_length]
        encrypted_token = masked_token[token_length..]
        xor_byte_strings(one_time_pad, encrypted_token)
      end

      def unmasked_token?(token)
        token.length == TOKEN_LENGTH
      end

      def masked_token?(token)
        token.length == TOKEN_LENGTH * 2
      end

      # Decoded root tokens that may satisfy this request: always the
      # current generation, plus unexpired previous generations bound to
      # the current identity, unless the resolved policy is :strict.
      # This only reads the session, so accepting an old token can never
      # extend its grace window.
      def valid_real_tokens(session, env)
        tokens = [real_token(session)]
        tokens.concat(previous_real_tokens(session)) unless strict_policy?(env)
        tokens
      end

      def previous_real_tokens(session)
        identity = current_identity(session)

        previous_generations(session).select do |generation|
          generation['identity'] == identity &&
            now - generation['rotated_at'] < options[:rotation_grace_period]
        end.map { |generation| decode_token(generation['token']) }
      end

      def strict_policy?(env)
        policy = options[:rotation_policy]
        policy = policy.call(env) if policy.respond_to?(:call)
        policy.to_sym == :strict
      end

      def current_identity(session)
        identity = options[:identity]

        case identity
        when Proc then identity.call(session)
        when nil then nil
        else session[identity]
        end
      end

      def previous_generations(session)
        Array(session[previous_key])
      end

      def previous_key
        "#{options[:key]}.previous"
      end

      def prune_generations(generations)
        generations.reject do |generation|
          now - generation['rotated_at'] >= options[:rotation_grace_period]
        end
      end

      def now
        options[:clock].call
      end

      def real_token(session)
        decode_token(session[options[:key]])
      end

      def global_token(real)
        token_hmac(real, GLOBAL_TOKEN_IDENTIFIER)
      end

      def per_form_token(real, path, method)
        token_hmac(real, "#{path}##{method.downcase}")
      end

      def encode_token(token)
        Base64.urlsafe_encode64(token)
      end

      def decode_token(token)
        Base64.urlsafe_decode64(token)
      end

      def token_hmac(real, identifier)
        OpenSSL::HMAC.digest(
          OpenSSL::Digest.new('SHA256'),
          real,
          identifier
        )
      end

      def xor_byte_strings(s1, s2)
        s2 = s2.dup
        size = s1.bytesize
        i = 0
        while i < size
          s2.setbyte(i, s1.getbyte(i) ^ s2.getbyte(i))
          i += 1
        end
        s2
      end
    end
  end
end
