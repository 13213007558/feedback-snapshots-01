# frozen_string_literal: true

require_relative "gs2_header"

module Net
  class IMAP < Protocol
    module SASL

      # Abstract base class for the SASL mechanisms defined in
      # RFC7628[https://www.rfc-editor.org/rfc/rfc7628]:
      # * OAUTHBEARER[rdoc-ref:OAuthBearerAuthenticator]
      #   (OAuthBearerAuthenticator)
      # * OAUTH10A
      class OAuthAuthenticator
        include GS2Header

        # Matches the
        # {RFC7628 §3.1}[https://www.rfc-editor.org/rfc/rfc7628#section-3.1]
        # +value+ production, which terminates each +kvpair+:
        #
        #   value = *(VCHAR / SP / HTAB / CR / LF / UTF8-2 / UTF8-3 / UTF8-4)
        #
        # In particular, this excludes %x00 and %x01 (+kvsep+), so a validated
        # value can never terminate its own +kvpair+ early or inject
        # additional +kvpairs+.
        RFC7628_VALUE = /\A(?:[^\x00-\x08\x0B\x0C\x0E-\x1F\x7F])*\z/u.freeze

        # Matches a decimal service port number.
        PORT_NUMBER = /\A[0-9]+\z/.freeze

        # Authorization identity: an identity to act as or on behalf of.  The
        # identity form is application protocol specific.  If not provided or
        # left blank, the server derives an authorization identity from the
        # authentication identity.  The server is responsible for verifying the
        # client's credentials and verifying that the identity it associates
        # with the client's authentication identity is allowed to act as (or on
        # behalf of) the authorization identity.
        #
        # For example, an administrator or superuser might take on another role:
        #
        #     imap.authenticate "PLAIN", "root", passwd, authzid: "user"
        #
        attr_reader :authzid
        alias username authzid

        # Hostname to which the client connected.  (optional)
        attr_reader :host

        # Service port to which the client connected.  (optional)
        attr_reader :port

        # HTTP method.  (optional)
        attr_reader :mthd

        # HTTP path data.  (optional)
        attr_reader :path

        # HTTP post data.  (optional)
        attr_reader :post

        # The query string.  (optional)
        attr_reader :qs
        alias query qs

        # Stores the most recent server "challenge".  When authentication fails,
        # this may hold information about the failure reason, as JSON.
        attr_reader :last_server_response

        # Creates an RFC7628[https://www.rfc-editor.org/rfc/rfc7628] OAuth
        # authenticator.
        #
        # ==== Parameters
        #
        # See child classes for required parameter(s).  The following parameters
        # are all optional, but it is worth noting that <b>application protocols
        # are allowed to require</b> #authzid (or other parameters, such as
        # #host or #port) <b>as are specific server implementations</b>.
        #
        # * _optional_ #authzid  ― Authorization identity to act as or on behalf of.
        #
        #   _optional_ #username — An alias for #authzid.
        #
        #   Note that, unlike some other authenticators, +username+ sets the
        #   _authorization_ identity and not the _authentication_ identity.  The
        #   authentication identity is established for the client by the OAuth
        #   token.
        #
        # * _optional_ #host — Hostname to which the client connected.
        # * _optional_ #port — Service port to which the client connected.
        # * _optional_ #mthd — HTTP method
        # * _optional_ #path — HTTP path data
        # * _optional_ #post — HTTP post data
        # * _optional_ #qs   — HTTP query string
        #
        #   _optional_ #query — An alias for #qs
        #
        # Any other keyword parameters are quietly ignored.
        #
        # Every field is validated against its grammar when the authenticator
        # is created, and ArgumentError is raised for any value that cannot be
        # encoded safely---before any part of the client response is sent.
        def initialize(authzid: nil, host: nil, port: nil,
                       username: nil, query: nil,
                       mthd: nil, path: nil, post: nil, qs: nil, **)
          @authzid = authzid || username
          @host    = host
          @port    = port
          @mthd    = mthd
          @path    = path
          @post    = post
          @qs      = qs || query
          @done    = false
          validate_fields!
        end

        # The {RFC7628 §3.1}[https://www.rfc-editor.org/rfc/rfc7628#section-3.1]
        # formatted response.
        def initial_client_response
          kv_pairs = {
            host: host, port: port, mthd: mthd, path: path, post: post, qs: qs,
            auth: authorization, # authorization is implemented by subclasses
          }.compact
          [gs2_header, *kv_pairs.map {|kv| kv.join("=") }, "\1"].join("\1")
        end

        # Returns initial_client_response the first time, then "<tt>^A</tt>".
        def process(data)
          @last_server_response = data
          done? ? "\1" : initial_client_response
        ensure
          @done = true
        end

        # Returns true when the initial client response was sent.
        #
        # The authentication should not succeed unless this returns true, but it
        # does *not* indicate success.
        def done?; @done end

        # Value of the HTTP Authorization header
        #
        # <b>Implemented by subclasses.</b>
        def authorization; raise "must be implemented by subclass" end

        private

        # Raises ArgumentError unless every field can be encoded into the
        # RFC7628 client response without escaping its own slot.  Called from
        # the constructor, so invalid input is rejected before any part of
        # the response can be sent.
        def validate_fields!
          validate_authzid!
          validate_rfc7628_value(:host, host)
          validate_rfc7628_value(:mthd, mthd)
          validate_rfc7628_value(:path, path)
          validate_rfc7628_value(:post, post)
          validate_rfc7628_value(:qs,   qs)
          return if port.nil?
          PORT_NUMBER.match?(port.to_s) or
            raise ArgumentError, "invalid port: %p" % [port]
        end

        # The +authzid+ is encoded into the GS2 header as an RFC5801
        # +saslname+ (which escapes ",", "=", and rejects %x00).  It must
        # additionally not contain %x01 (+kvsep+): although the GS2 grammar
        # is comma-delimited, a %x01 here would be seen as the start of the
        # +kvpair+ region by receivers that split the response on +kvsep+.
        def validate_authzid!
          return if authzid.nil? || authzid == ""
          encoded = gs2_saslname_encode(authzid) # raises on %x00, bad UTF-8
          encoded.include?("\x01") and
            raise ArgumentError, "invalid authzid: contains \\x01 (kvsep)"
        end

        # Raises ArgumentError unless +value+ is +nil+ or matches the
        # RFC7628 +value+ grammar (RFC7628_VALUE).
        def validate_rfc7628_value(name, value)
          return if value.nil?
          str = value.to_s.encode("UTF-8")
          RFC7628_VALUE.match(str) or
            raise ArgumentError, "invalid %s: %p" % [name, str]
        end

      end

      # Authenticator for the "+OAUTHBEARER+" SASL mechanism, specified in
      # RFC7628[https://www.rfc-editor.org/rfc/rfc7628].  Authenticates using
      # OAuth 2.0 bearer tokens, as described in
      # RFC6750[https://www.rfc-editor.org/rfc/rfc6750].  Use via
      # Net::IMAP#authenticate.
      #
      # RFC6750[https://www.rfc-editor.org/rfc/rfc6750] requires Transport Layer
      # Security (TLS) to secure the protocol interaction between the client and
      # the resource server.  TLS _MUST_ be used for +OAUTHBEARER+ to protect
      # the bearer token.
      class OAuthBearerAuthenticator < OAuthAuthenticator

        # Matches the
        # {RFC6750 §2.1}[https://www.rfc-editor.org/rfc/rfc6750#section-2.1]
        # +b64token+ production:
        #
        #   b64token = 1*(ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/")
        #              *"="
        B64TOKEN = /\A[A-Za-z0-9\-._~+\/]+=*\z/.freeze

        # An OAuth 2.0 bearer token.  See {RFC-6750}[https://www.rfc-editor.org/rfc/rfc6750]
        attr_reader :oauth2_token
        alias secret oauth2_token

        # :call-seq:
        #   new(oauth2_token,          **options) -> authenticator
        #   new(authzid, oauth2_token, **options) -> authenticator
        #   new(oauth2_token:,         **options) -> authenticator
        #
        # Creates an Authenticator for the "+OAUTHBEARER+" SASL mechanism.
        #
        # Called by Net::IMAP#authenticate and similar methods on other clients.
        #
        # ==== Parameters
        #
        # * #oauth2_token — An OAuth2 bearer token
        #
        # All other keyword parameters are passed to
        # {super}[rdoc-ref:OAuthAuthenticator::new] (see OAuthAuthenticator).
        # The most common ones are:
        #
        # * _optional_ #authzid  ― Authorization identity to act as or on behalf of.
        #
        #   _optional_ #username — An alias for #authzid.
        #
        #   Note that, unlike some other authenticators, +username+ sets the
        #   _authorization_ identity and not the _authentication_ identity.  The
        #   authentication identity is established for the client by
        #   #oauth2_token.
        #
        # * _optional_ #host — Hostname to which the client connected.
        # * _optional_ #port — Service port to which the client connected.
        #
        # Although only oauth2_token is required by this mechanism, it is worth
        # noting that <b><em>application protocols are allowed to
        # require</em></b> #authzid (<em>or other parameters, such as</em> #host
        # _or_ #port) <b><em>as are specific server implementations</em></b>.
        def initialize(arg1 = nil, arg2 = nil,
                       oauth2_token: nil, secret: nil,
                       **args, &blk)
          username, oauth2_token_arg = arg2.nil? ? [nil, arg1] : [arg1, arg2]
          super(username: username, **args, &blk)
          @oauth2_token = oauth2_token || secret || oauth2_token_arg or
            raise ArgumentError, "missing oauth2_token"
          B64TOKEN.match?(@oauth2_token.to_s) or
            raise ArgumentError,
                  "invalid oauth2_token (must be an RFC6750 b64token)"
        end

        # :call-seq:
        #   initial_response? -> true
        #
        # +OAUTHBEARER+ sends an initial client response.
        def initial_response?; true end

        # Value of the HTTP Authorization header
        def authorization; "Bearer #{oauth2_token}" end

      end
    end

  end
end
