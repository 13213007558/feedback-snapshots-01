# frozen_string_literal: true

# = net/smtp.rb
#
# Copyright (c) 1999-2007 Yukihiro Matsumoto.
#
# Copyright (c) 1999-2007 Minero Aoki.
#
# Written & maintained by Minero Aoki <aamine@loveruby.net>.
#
# Documented by William Webber and Minero Aoki.
#
# This program is free software. You can re-distribute and/or
# modify this program under the same terms as Ruby itself.
#
# See Net::SMTP for documentation.
#

require 'net/protocol'
begin
  require 'openssl'
rescue LoadError
end

module Net
  # Module mixed in to all SMTP error classes
  module SMTPError
    # This *class* is a module for backward compatibility.
    # In later release, this module becomes a class.

    attr_reader :response

    def initialize(response, message: nil)
      if response.is_a?(::Net::SMTP::Response)
        @response = response
        super(message || response.message)
      else
        @response = nil
        super(message || response)
      end
    end
  end

  # Represents an SMTP authentication error.
  class SMTPAuthenticationError < ProtoAuthError
    include SMTPError
  end

  # Represents SMTP error code 4xx, a temporary error.
  class SMTPServerBusy < ProtoServerError
    include SMTPError
  end

  # Represents an SMTP command syntax error (error code 500)
  class SMTPSyntaxError < ProtoSyntaxError
    include SMTPError
  end

  # Represents a fatal SMTP error (error code 5xx, except for 500)
  class SMTPFatalError < ProtoFatalError
    include SMTPError
  end

  # Unexpected reply code returned from server.
  class SMTPUnknownError < ProtoUnknownError
    include SMTPError
  end

  # Command is not supported on server.
  class SMTPUnsupportedCommand < ProtocolError
    include SMTPError
  end

  # Raised when a connection cannot satisfy an applied MTA-STS policy.
  #
  # This is deliberately not an SMTPError because the failure happens before
  # (or independently of) an SMTP response. +reason+ identifies the policy
  # check that failed, for example +:domain_mismatch+, +:mx_mismatch+,
  # +:starttls_unsupported+, +:tls_required+, or +:certificate_identity+.
  class SMTPMTASTSPolicyError < ProtocolError
    attr_reader :reason

    def initialize(message, reason: nil)
      @reason = reason
      super(message)
    end
  end

  # Backwards friendly short name.
  MTASTSPolicyError = SMTPMTASTSPolicyError

  #
  # == What is This Library?
  #
  # This library provides functionality to send internet
  # mail via \SMTP, the Simple Mail Transfer Protocol. For details of
  # \SMTP itself, see [RFC5321[https://www.rfc-editor.org/rfc/rfc5321.txt]].
  # This library also implements \SMTP authentication, which is often
  # necessary for message composers to submit messages to their
  # outgoing \SMTP server, see
  # [RFC6409[https://www.rfc-editor.org/rfc/rfc6409.html]],
  # and [SMTPUTF8[https://www.rfc-editor.org/rfc/rfc6531.txt]], which is
  # necessary to send messages to/from addresses containing characters
  # outside the ASCII range.
  #
  # == What is This Library NOT?
  #
  # This library does NOT provide functions to compose internet mails.
  # You must create them by yourself. If you want better mail support,
  # try the mail[https://rubygems.org/gems/mail] or
  # rmail[https://rubygems.org/gems/rmail] gems, or search for alternatives in
  # {RubyGems.org}[https://rubygems.org/] or {The Ruby
  # Toolbox}[https://www.ruby-toolbox.com/].
  #
  # FYI: the official specification on internet mail is:
  # [RFC5322[https://www.rfc-editor.org/rfc/rfc5322.txt]].
  #
  # == Examples
  #
  # === Sending Messages
  #
  # You must open a connection to an \SMTP server before sending messages.
  # The first argument is the address of your \SMTP server, and the second
  # argument is the port number. Using SMTP.start with a block is the simplest
  # way to do this. This way, the SMTP connection is closed automatically
  # after the block is executed.
  #
  #     require 'net/smtp'
  #     Net::SMTP.start('your.smtp.server', 25) do |smtp|
  #       # Use the SMTP object smtp only in this block.
  #     end
  #
  # Replace 'your.smtp.server' with your \SMTP server. Normally
  # your system manager or internet provider supplies a server
  # for you.
  #
  # Then you can send messages.
  #
  #     msgstr = <<END_OF_MESSAGE
  #     From: Your Name <your@mail.address>
  #     To: Destination Address <someone@example.com>
  #     Subject: test message
  #     Date: Sat, 23 Jun 2001 16:26:43 +0900
  #     Message-Id: <unique.message.id.string@example.com>
  #
  #     This is a test message.
  #     END_OF_MESSAGE
  #
  #     require 'net/smtp'
  #     Net::SMTP.start('your.smtp.server', 25) do |smtp|
  #       smtp.send_message msgstr,
  #                         'your@mail.address',
  #                         'his_address@example.com'
  #     end
  #
  # === Closing the Session
  #
  # You MUST close the SMTP session after sending messages, by calling
  # the #finish method:
  #
  #     # using SMTP#finish
  #     smtp = Net::SMTP.start('your.smtp.server', 25)
  #     smtp.send_message msgstr, 'from@address', 'to@address'
  #     smtp.finish
  #
  # You can also use the block form of SMTP.start or SMTP#start.  This closes
  # the SMTP session automatically:
  #
  #     # using block form of SMTP.start
  #     Net::SMTP.start('your.smtp.server', 25) do |smtp|
  #       smtp.send_message msgstr, 'from@address', 'to@address'
  #     end
  #
  # I strongly recommend this scheme.  This form is simpler and more robust.
  #
  # === HELO domain
  #
  # In almost all situations, you must provide a third argument
  # to SMTP.start or SMTP#start. This is the domain name which you are on
  # (the host to send mail from). It is called the "HELO domain".
  # The \SMTP server will judge whether it should send or reject
  # the SMTP session by inspecting the HELO domain.
  #
  #     Net::SMTP.start('your.smtp.server', 25, helo: 'mail.from.domain') do |smtp|
  #       smtp.send_message msgstr, 'from@address', 'to@address'
  #     end
  #
  # === MTA-STS
  #
  # MTA-STS ([RFC8461[https://www.rfc-editor.org/rfc/rfc8461.html]]) lets a
  # recipient domain publish a policy that requires TLS and constrains the
  # MX hosts a sender may use. This library does not discover or download
  # policies; the application fetches the policy and passes it in:
  #
  #     policy = Net::SMTP::MTASTSPolicy.new(
  #       domain: "example.com",
  #       mode: :enforce,
  #       mx: ["mail.example.com", "*.example.net"],
  #       max_age: 86400,
  #       fetched_at: Time.now
  #     )
  #
  #     Net::SMTP.start("mail.example.com", 25,
  #                     mta_sts_policy: policy,
  #                     mta_sts_domain: "example.com",
  #                     mta_sts_mx_hostname: "mail.example.com") do |smtp|
  #       smtp.send_message msgstr, "from@example.com", "to@example.com"
  #     end
  #
  # An +enforce+ policy requires STARTTLS and a certificate valid for the
  # selected MX host. If the policy cannot be satisfied, the connection is
  # refused with Net::SMTPMTASTSPolicyError before authentication or the
  # mail envelope is sent. +testing+ records the same failures for reporting
  # but still permits delivery; +none+, expired, and absent policies are
  # treated as no active policy.
  #
  # === \SMTP Authentication
  #
  # The Net::SMTP class supports the \SMTP extension for SASL Authentication
  # [RFC4954[https://www.rfc-editor.org/rfc/rfc4954.html]] and the following
  # SASL mechanisms: +PLAIN+, +LOGIN+ _(deprecated)_, and +CRAM-MD5+
  # _(deprecated)_.
  #
  # To use \SMTP authentication, pass extra arguments to
  # SMTP.start or SMTP#start.
  #
  #     # PLAIN
  #     Net::SMTP.start('your.smtp.server', 25,
  #                     user: 'Your Account', secret: 'Your Password', authtype: :plain)
  #
  # Support for other SASL mechanisms-such as +EXTERNAL+, +OAUTHBEARER+,
  # +SCRAM-SHA-256+, and +XOAUTH2+-will be added in a future release.
  #
  # The +LOGIN+ and +CRAM-MD5+ mechanisms are still available for backwards
  # compatibility, but are deprecated and should be avoided.
  #
  class SMTP < Protocol
    VERSION = "0.5.2"

    # The default SMTP port number, 25.
    def SMTP.default_port
      25
    end

    # The default mail submission port number, 587.
    def SMTP.default_submission_port
      587
    end

    # The default SMTPS port number, 465.
    def SMTP.default_tls_port
      465
    end

    class << self
      alias default_ssl_port default_tls_port
    end

    def SMTP.default_ssl_context(ssl_context_params = nil)
      context = OpenSSL::SSL::SSLContext.new
      context.set_params(ssl_context_params || {})
      context
    end

    #
    # Creates a new Net::SMTP object.
    #
    # +address+ is the hostname or ip address of your SMTP
    # server.  +port+ is the port to connect to; it defaults to
    # port 25.
    #
    # If +tls+ is true, enable TLS. The default is false.
    # If +starttls+ is :always, enable STARTTLS, if +:auto+, use STARTTLS when the server supports it,
    # if false, disable STARTTLS.
    #
    # If +tls_verify+ is true, verify the server's certificate. The default is true.
    # If the hostname in the server certificate is different from +address+,
    # it can be specified with +tls_hostname+.
    #
    # Additional SSLContext[https://ruby.github.io/openssl/OpenSSL/SSL/SSLContext.html]
    # params can be added to the +ssl_context_params+ hash argument and are
    # passed to {OpenSSL::SSL::SSLContext#set_params}[https://ruby.github.io/openssl/OpenSSL/SSL/SSLContext.html#method-i-set_params].
    #
    # <tt>tls_verify: true</tt> is equivalent to <tt>ssl_context_params: {
    # verify_mode: OpenSSL::SSL::VERIFY_PEER }</tt>.
    #
    # === MTA-STS policies
    #
    # +mta_sts_policy+ accepts a Net::SMTP::MTASTSPolicy or an equivalent
    # Hash. Net::SMTP does not fetch policies; the application is responsible
    # for retrieving the policy and for passing its fetch time so that
    # +max_age+ can be evaluated. See Net::SMTP::MTASTSPolicy.
    #
    # +mta_sts_domain+ is the recipient domain whose policy is being applied.
    # When omitted, the policy's own domain is used. +mta_sts_mx_hostname+
    # identifies the selected MX when it differs from +address+; it defaults
    # to +address+.
    #
    # +mta_sts_reporter+ is an optional callable invoked as
    # <tt>reporter.call(reason, details)</tt> for policy validation failures.
    #
    # This method does not open the TCP connection.  You can use
    # SMTP.start instead of SMTP.new if you want to do everything
    # at once.  Otherwise, follow SMTP.new with SMTP#start.
    #
    def initialize(address, port = nil, tls: false, starttls: :auto, tls_verify: true, tls_hostname: nil, ssl_context_params: nil,
                   mta_sts_policy: nil, mta_sts_domain: nil, mta_sts_mx_hostname: nil, mta_sts_reporter: nil)
      @address = address
      @port = (port || SMTP.default_port)
      @esmtp = true
      @capabilities = nil
      @socket = nil
      @started = false
      @open_timeout = 30
      @read_timeout = 60
      @error_occurred = false
      @debug_output = nil
      @tls = tls
      @starttls = starttls
      @ssl_context_tls = nil
      @ssl_context_starttls = nil
      @tls_verify = tls_verify
      @tls_hostname = tls_hostname
      @ssl_context_params = ssl_context_params
      self.mta_sts_domain = mta_sts_domain
      self.mta_sts_mx_hostname = mta_sts_mx_hostname
      self.mta_sts_reporter = mta_sts_reporter
      self.mta_sts_policy = mta_sts_policy
    end

    # The structured MTA-STS policy applied to this connection, or +nil+.
    attr_reader :mta_sts_policy

    # Assign an MTA-STS policy. Accepts a Net::SMTP::MTASTSPolicy, a Hash,
    # or +nil+. The policy must be obtained by the application; Net::SMTP
    # never downloads it.
    def mta_sts_policy=(policy)
      @mta_sts_policy = MTASTSPolicy.coerce(policy)
    end

    # The recipient domain whose MTA-STS policy is being applied.
    attr_reader :mta_sts_domain

    def mta_sts_domain=(domain)
      @mta_sts_domain = domain && MTASTSPolicy.normalize_host(domain)
    end

    # The selected MX host name used for policy matching and certificate
    # identity verification. Defaults to #address.
    attr_reader :mta_sts_mx_hostname

    def mta_sts_mx_hostname=(hostname)
      @mta_sts_mx_hostname = hostname && MTASTSPolicy.normalize_host(hostname)
    end

    # Optional callable reporting MTA-STS validation failures.
    attr_accessor :mta_sts_reporter

    # The policy that was found valid and applicable during the current
    # connection, or +nil+ when no valid policy applies (absent, expired,
    # "none" mode, or not applicable to the recipient domain). An enforce
    # policy whose MX pattern does not match the selected MX is rejected
    # before any connection is opened.
    attr_reader :mta_sts_applied_policy

    # True when an enforce policy governs the current connection.
    def mta_sts_enforced?
      !!(@mta_sts_applied_policy && @mta_sts_applied_policy.enforce?)
    end

    # True when a testing policy governs the current connection.
    def mta_sts_testing?
      !!(@mta_sts_applied_policy && @mta_sts_applied_policy.testing?)
    end

    # Validation failures recorded while applying MTA-STS. Each entry is a
    # Hash with a +:reason+ key and contextual details.
    attr_reader :mta_sts_failures

    # If +true+, verify th server's certificate.
    attr_accessor :tls_verify

    # The hostname for verifying hostname in the server certificatate.
    attr_accessor :tls_hostname

    # Hash for additional SSLContext parameters.
    attr_accessor :ssl_context_params

    # Provide human-readable stringification of class state.
    def inspect
      "#<#{self.class} #{@address}:#{@port} started=#{@started}>"
    end

    #
    # Set whether to use ESMTP or not.  This should be done before
    # calling #start.  Note that if #start is called in ESMTP mode,
    # and the connection fails due to a ProtocolError, the SMTP
    # object will automatically switch to plain SMTP mode and
    # retry (but not vice versa).
    #
    attr_accessor :esmtp

    # +true+ if the SMTP object uses ESMTP (which it does by default).
    alias esmtp? esmtp

    # true if server advertises STARTTLS.
    # You cannot get valid value before opening SMTP session.
    def capable_starttls?
      capable?('STARTTLS')
    end

    # true if the EHLO response contains +key+.
    def capable?(key)
      return nil unless @capabilities
      @capabilities[key] ? true : false
    end

    # The server capabilities by EHLO response
    attr_reader :capabilities

    # true if server advertises AUTH PLAIN.
    # You cannot get valid value before opening SMTP session.
    def capable_plain_auth?
      auth_capable?('PLAIN')
    end

    # true if server advertises AUTH LOGIN.
    # You cannot get valid value before opening SMTP session.
    def capable_login_auth?
      auth_capable?('LOGIN')
    end

    # true if server advertises AUTH CRAM-MD5.
    # You cannot get valid value before opening SMTP session.
    def capable_cram_md5_auth?
      auth_capable?('CRAM-MD5')
    end

    # Returns whether the server advertises support for the authentication type.
    # You cannot get valid result before opening SMTP session.
    def auth_capable?(type)
      return nil unless @capabilities
      return false unless @capabilities['AUTH']
      @capabilities['AUTH'].include?(type)
    end

    # Returns supported authentication methods on this server.
    # You cannot get valid value before opening SMTP session.
    def capable_auth_types
      return [] unless @capabilities
      return [] unless @capabilities['AUTH']
      @capabilities['AUTH']
    end

    # true if this object uses SMTP/TLS (SMTPS).
    def tls?
      @tls
    end

    alias ssl? tls?

    # Enables SMTP/TLS (SMTPS: \SMTP over direct TLS connection) for
    # this object.  Must be called before the connection is established
    # to have any effect.  +context+ is a OpenSSL::SSL::SSLContext object.
    def enable_tls(context = nil)
      raise 'openssl library not installed' unless defined?(OpenSSL::VERSION)
      raise ArgumentError, "SMTPS and STARTTLS is exclusive" if @starttls == :always
      @tls = true
      @ssl_context_tls = context
    end

    alias enable_ssl enable_tls

    # Disables SMTP/TLS for this object.  Must be called before the
    # connection is established to have any effect.
    def disable_tls
      @tls = false
      @ssl_context_tls = nil
    end

    alias disable_ssl disable_tls

    # Returns truth value if this object uses STARTTLS.
    # If this object always uses STARTTLS, returns :always.
    # If this object uses STARTTLS when the server support TLS, returns :auto.
    def starttls?
      @starttls
    end

    # true if this object uses STARTTLS.
    def starttls_always?
      @starttls == :always
    end

    # true if this object uses STARTTLS when server advertises STARTTLS.
    def starttls_auto?
      @starttls == :auto
    end

    # Enables SMTP/TLS (STARTTLS) for this object.
    # +context+ is a OpenSSL::SSL::SSLContext object.
    def enable_starttls(context = nil)
      raise 'openssl library not installed' unless defined?(OpenSSL::VERSION)
      raise ArgumentError, "SMTPS and STARTTLS is exclusive" if @tls
      @starttls = :always
      @ssl_context_starttls = context
    end

    # Enables SMTP/TLS (STARTTLS) for this object if server accepts.
    # +context+ is a OpenSSL::SSL::SSLContext object.
    def enable_starttls_auto(context = nil)
      raise 'openssl library not installed' unless defined?(OpenSSL::VERSION)
      raise ArgumentError, "SMTPS and STARTTLS is exclusive" if @tls
      @starttls = :auto
      @ssl_context_starttls = context
    end

    # Disables SMTP/TLS (STARTTLS) for this object.  Must be called
    # before the connection is established to have any effect.
    def disable_starttls
      @starttls = false
      @ssl_context_starttls = nil
    end

    # The address of the SMTP server to connect to.
    attr_reader :address

    # The port number of the SMTP server to connect to.
    attr_reader :port

    # Seconds to wait while attempting to open a connection.
    # If the connection cannot be opened within this time, a
    # Net::OpenTimeout is raised. The default value is 30 seconds.
    attr_accessor :open_timeout

    # Seconds to wait while reading one block (by one read(2) call).
    # If the read(2) call does not complete within this time, a
    # Net::ReadTimeout is raised. The default value is 60 seconds.
    attr_reader :read_timeout

    # Set the number of seconds to wait until timing-out a read(2)
    # call.
    def read_timeout=(sec)
      @socket.read_timeout = sec if @socket
      @read_timeout = sec
    end

    #
    # WARNING: This method causes serious security holes.
    # Use this method for only debugging.
    #
    # Set an output stream for debug logging.
    # You must call this before #start.
    #
    #   # example
    #   smtp = Net::SMTP.new(addr, port)
    #   smtp.set_debug_output $stderr
    #   smtp.start do |smtp|
    #     ....
    #   end
    #
    def debug_output=(arg)
      @debug_output = arg
    end

    alias set_debug_output debug_output=

    #
    # SMTP session control
    #

    #
    # :call-seq:
    #  start(address, port = nil, helo: 'localhost', user: nil, secret: nil, authtype: nil, tls: false, starttls: :auto, tls_verify: true, tls_hostname: nil, ssl_context_params: nil, mta_sts_policy: nil, mta_sts_domain: nil, mta_sts_mx_hostname: nil, mta_sts_reporter: nil) { |smtp| ... }
    #  start(address, port = nil, helo = 'localhost', user = nil, secret = nil, authtype = nil) { |smtp| ... }
    #
    # Creates a new Net::SMTP object and connects to the server.
    #
    # This method is equivalent to:
    #
    #   Net::SMTP.new(address, port, tls_verify: flag, tls_hostname: hostname, ssl_context_params: nil)
    #     .start(helo: helo_domain, user: account, secret: password, authtype: authtype)
    #
    # See also: Net::SMTP.new, #start
    #
    # === Example
    #
    #     Net::SMTP.start('your.smtp.server') do |smtp|
    #       smtp.send_message msgstr, 'from@example.com', ['dest@example.com']
    #     end
    #
    # === Block Usage
    #
    # If called with a block, the newly-opened Net::SMTP object is yielded
    # to the block, and automatically closed when the block finishes.  If called
    # without a block, the newly-opened Net::SMTP object is returned to
    # the caller, and it is the caller's responsibility to close it when
    # finished.
    #
    # === Parameters
    #
    # +address+ is the hostname or ip address of your smtp server.
    #
    # +port+ is the port to connect to; it defaults to port 25.
    #
    # +helo+ is the _HELO_ _domain_ provided by the client to the
    # server (see overview comments); it defaults to 'localhost'.
    #
    # If +tls+ is true, enable TLS. The default is false.
    # If +starttls+ is :always, enable STARTTLS, if +:auto+, use STARTTLS when the server supports it,
    # if false, disable STARTTLS.
    #
    # If +tls_verify+ is true, verify the server's certificate. The default is true.
    # If the hostname in the server certificate is different from +address+,
    # it can be specified with +tls_hostname+.
    #
    # Additional SSLContext[https://ruby.github.io/openssl/OpenSSL/SSL/SSLContext.html]
    # params can be added to the +ssl_context_params+ hash argument and are
    # passed to {OpenSSL::SSL::SSLContext#set_params}[https://ruby.github.io/openssl/OpenSSL/SSL/SSLContext.html#method-i-set_params].
    #
    # <tt>tls_verify: true</tt> is equivalent to <tt>ssl_context_params: {
    # verify_mode: OpenSSL::SSL::VERIFY_PEER }</tt>.
    #
    # +mta_sts_policy+ is a Net::SMTP::MTASTSPolicy (or Hash) that the
    # application obtained elsewhere. Net::SMTP never fetches policies.
    # +mta_sts_domain+ must be the recipient domain the policy covers, and
    # +mta_sts_mx_hostname+ identifies the selected MX (defaulting to
    # +address+). An enforce policy requires STARTTLS and a certificate valid
    # for the selected MX; it cannot be satisfied in plaintext, so it
    # overrides +starttls: :auto+ and +tls_verify: false+. A testing policy
    # records violations through +mta_sts_reporter+ but still allows
    # delivery. Expired policies, "none" policies, and absent policies are
    # treated as no active policy.
    #
    # The remaining arguments are used for \SMTP authentication, if required or
    # desired.
    #
    # +authtype+ is the SASL authentication mechanism.
    #
    # +user+ is the authentication or authorization identity.
    #
    # +secret+ or +password+ is your password or other authentication token.
    #
    # These will be sent to #authenticate as positional arguments-the exact
    # semantics are dependent on the +authtype+.
    #
    # See the discussion of Net::SMTP@SMTP+Authentication in the overview notes.
    #
    # === Errors
    #
    # This method may raise:
    #
    # * Net::SMTPAuthenticationError
    # * Net::SMTPServerBusy
    # * Net::SMTPSyntaxError
    # * Net::SMTPFatalError
    # * Net::SMTPUnknownError
    # * Net::OpenTimeout
    # * Net::ReadTimeout
    # * Net::SMTPMTASTSPolicyError
    # * IOError
    #
    def SMTP.start(address, port = nil, *args, helo: nil,
                   user: nil, secret: nil, password: nil, authtype: nil,
                   tls: false, starttls: :auto,
                   tls_verify: true, tls_hostname: nil, ssl_context_params: nil,
                   mta_sts_policy: nil, mta_sts_domain: nil,
                   mta_sts_mx_hostname: nil, mta_sts_reporter: nil,
                   &block)
      raise ArgumentError, "wrong number of arguments (given #{args.size + 2}, expected 1..6)" if args.size > 4
      helo ||= args[0] || 'localhost'
      user ||= args[1]
      secret ||= password || args[2]
      authtype ||= args[3]
      new(address, port, tls: tls, starttls: starttls, tls_verify: tls_verify, tls_hostname: tls_hostname, ssl_context_params: ssl_context_params,
          mta_sts_policy: mta_sts_policy, mta_sts_domain: mta_sts_domain,
          mta_sts_mx_hostname: mta_sts_mx_hostname, mta_sts_reporter: mta_sts_reporter).start(helo: helo, user: user, secret: secret, authtype: authtype, &block)
    end

    # +true+ if the \SMTP session has been started.
    def started?
      @started
    end

    #
    # :call-seq:
    #  start(helo: 'localhost', user: nil, secret: nil, authtype: nil) { |smtp| ... }
    #  start(helo = 'localhost', user = nil, secret = nil, authtype = nil) { |smtp| ... }
    #
    # Opens a TCP connection and starts the SMTP session.
    #
    # === Parameters
    #
    # +helo+ is the _HELO_ _domain_ that you'll dispatch mails from; see
    # the discussion in the overview notes.
    #
    # The remaining arguments are used for \SMTP authentication, if required or
    # desired.
    #
    # +authtype+ is the SASL authentication mechanism.
    #
    # +user+ is the authentication or authorization identity.
    #
    # +secret+ or +password+ is your password or other authentication token.
    #
    # These will be sent to #authenticate as positional arguments-the exact
    # semantics are dependent on the +authtype+.
    #
    # See the discussion of Net::SMTP@SMTP+Authentication in the overview notes.
    #
    # See also: Net::SMTP.start
    #
    # === Block Usage
    #
    # When this methods is called with a block, the newly-started SMTP
    # object is yielded to the block, and automatically closed after
    # the block call finishes.  Otherwise, it is the caller's
    # responsibility to close the session when finished.
    #
    # === Example
    #
    # This is very similar to the class method SMTP.start.
    #
    #     require 'net/smtp'
    #     smtp = Net::SMTP.new('smtp.mail.server', 25)
    #     smtp.start(helo: helo_domain, user: account, secret: password, authtype: authtype) do |smtp|
    #       smtp.send_message msgstr, 'from@example.com', ['dest@example.com']
    #     end
    #
    # The primary use of this method (as opposed to SMTP.start)
    # is probably to set debugging (#set_debug_output) or ESMTP
    # (#esmtp=), which must be done before the session is
    # started.
    #
    # === Errors
    #
    # If session has already been started, an IOError will be raised.
    #
    # This method may raise:
    #
    # * Net::SMTPAuthenticationError
    # * Net::SMTPServerBusy
    # * Net::SMTPSyntaxError
    # * Net::SMTPFatalError
    # * Net::SMTPUnknownError
    # * Net::OpenTimeout
    # * Net::ReadTimeout
    # * IOError
    #
    def start(*args, helo: nil, user: nil, secret: nil, password: nil, authtype: nil)
      raise ArgumentError, "wrong number of arguments (given #{args.size}, expected 0..4)" if args.size > 4
      helo ||= args[0] || 'localhost'
      user ||= args[1]
      secret ||= password || args[2]
      authtype ||= args[3]
      @mta_sts_failures = []
      @mta_sts_applied_policy = resolve_mta_sts_policy
      if defined?(OpenSSL::VERSION)
        ssl_context_params = effective_ssl_context_params
        if @tls && @ssl_context_tls.nil?
          @ssl_context_tls = SMTP.default_ssl_context(ssl_context_params)
        end
        if (@starttls || (policy_tls_required? && !@tls)) && @ssl_context_starttls.nil?
          @ssl_context_starttls = SMTP.default_ssl_context(ssl_context_params)
        end
        if policy_tls_required?
          apply_policy_tls_requirements(@ssl_context_tls)
          apply_policy_tls_requirements(@ssl_context_starttls)
        end
      elsif policy_tls_required?
        raise mta_sts_error(
          "an MTA-STS policy requires TLS, but the openssl library is not installed",
          :tls_unavailable
        )
      end
      if block_given?
        begin
          do_start helo, user, secret, authtype
          return yield(self)
        ensure
          do_finish
        end
      else
        do_start helo, user, secret, authtype
        return self
      end
    end

    # Finishes the SMTP session and closes TCP connection.
    # Raises IOError if not started.
    def finish
      raise IOError, 'not yet started' unless started?
      do_finish
    end

    private

    def tcp_socket(address, port)
      TCPSocket.open address, port
    end

    def do_start(helo_domain, user, secret, authtype)
      raise IOError, 'SMTP session already started' if @started
      if user || secret || authtype
        check_auth_args authtype, user, secret
      end
      enforced = mta_sts_enforced?
      @mta_sts_satisfied = !enforced
      @error_occurred = false
      s = Timeout.timeout(@open_timeout, Net::OpenTimeout) do
        tcp_socket(@address, @port)
      end
      logging "Connection opened: #{@address}:#{@port}"
      if tls?
        begin
          @socket = new_internet_message_io(tlsconnect(s, @ssl_context_tls))
        rescue OpenSSL::SSL::SSLError => error
          mta_sts_failure(:tls_failure, :server => @address, :error => error) if mta_sts_testing?
          raise
        end
        @mta_sts_satisfied = true if enforced
      else
        @socket = new_internet_message_io(s)
      end
      check_response critical { recv_response() }
      do_helo helo_domain
      if !tls?
        if enforced
          # An enforce policy overrides starttls: false/:auto. A policy-bound
          # connection must never continue in plaintext.
          unless capable_starttls?
            raise mta_sts_error("MTA-STS enforce policy requires STARTTLS, but the server does not advertise it", :starttls_unsupported)
          end
          begin
            starttls
          rescue SMTPError => error
            raise mta_sts_error("MTA-STS enforce policy requires STARTTLS, but the server refused it: #{error.message}", :starttls_refused)
          end
          @socket = new_internet_message_io(tlsconnect(s, @ssl_context_starttls))
          # helo response may be different after STARTTLS
          do_helo helo_domain
          @mta_sts_satisfied = true
        elsif mta_sts_testing?
          if starttls_always?
            # An explicit starttls: :always keeps its hard-failure semantics;
            # testing mode only softens opportunistic STARTTLS.
            if capable_starttls?
              begin
                starttls
                @socket = new_internet_message_io(tlsconnect(s, @ssl_context_starttls))
                do_helo helo_domain
              rescue SMTPError, OpenSSL::SSL::SSLError, SMTPMTASTSPolicyError => error
                mta_sts_failure(:starttls_failed, :server => @address, :error => error)
                raise
              end
            else
              mta_sts_failure(:starttls_unsupported, :server => @address)
              raise SMTPUnsupportedCommand, "STARTTLS is not supported on this server"
            end
          elsif starttls_auto?
            if capable_starttls?
              begin
                starttls
                @socket = new_internet_message_io(tlsconnect(s, @ssl_context_starttls))
                do_helo helo_domain
              rescue SMTPError => error
                # The server declined STARTTLS but the SMTP session is still
                # usable; testing mode reports the failure and continues.
                mta_sts_failure(:starttls_refused, :server => @address, :error => error)
              rescue OpenSSL::SSL::SSLError, SMTPMTASTSPolicyError => error
                mta_sts_failure(:tls_failure, :server => @address, :error => error)
                s, @socket = reconnect_plaintext(s)
                check_response critical { recv_response() }
                do_helo helo_domain
              end
            else
              mta_sts_failure(:starttls_unsupported, :server => @address)
            end
          end
        elsif starttls_always? || (capable_starttls? && starttls_auto?)
          if capable_starttls?
            starttls
            @socket = new_internet_message_io(tlsconnect(s, @ssl_context_starttls))
            # helo response may be different after STARTTLS
            do_helo helo_domain
          elsif starttls_always?
            raise SMTPUnsupportedCommand, "STARTTLS is not supported on this server"
          end
        end
      end
      authenticate user, secret, (authtype || DEFAULT_AUTH_TYPE) if user
      @started = true
    ensure
      unless @started
        # authentication failed, cancel connection.
        s.close if s
        @socket = nil
      end
    end

    def ssl_socket(socket, context)
      OpenSSL::SSL::SSLSocket.new socket, context
    end

    # Testing mode only: abandon the failed TLS transport and open a fresh
    # plaintext one so delivery can proceed as though no policy existed.
    def reconnect_plaintext(old_socket)
      old_socket.close if old_socket && !old_socket.closed?
      @socket = nil
      fresh = Timeout.timeout(@open_timeout, Net::OpenTimeout) do
        tcp_socket(@address, @port)
      end
      logging "Connection reopened: #{@address}:#{@port}"
      [fresh, new_internet_message_io(fresh)]
    end

    # SSLContext parameters for a connection that must honor an MTA-STS
    # policy. Certificate chain and host identity verification are mandatory;
    # the caller cannot turn them off for a policy-bound connection.
    def effective_ssl_context_params
      params = @ssl_context_params&.dup || {}
      if policy_tls_required?
        params[:verify_mode] = OpenSSL::SSL::VERIFY_PEER
        if OpenSSL::SSL::SSLContext.method_defined?(:verify_hostname=)
          params[:verify_hostname] = true
        end
      elsif !params.has_key?(:verify_mode)
        params[:verify_mode] = @tls_verify ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE
      end
      params
    end

    def policy_tls_required?
      policy = @mta_sts_applied_policy
      !!policy && (policy.enforce? || policy.testing?)
    end

    # A caller-supplied SSLContext must not weaken an applied policy. The
    # context is mutated in place so that both the handshake and any
    # introspection by the application see verification enabled. OpenSSL
    # freezes a context once it has been used in a handshake; a frozen
    # context is accepted only if it already enforces verification.
    def apply_policy_tls_requirements(context)
      return unless context
      if context.frozen?
        hostname_verified = !context.respond_to?(:verify_hostname) || context.verify_hostname
        return if context.verify_mode == OpenSSL::SSL::VERIFY_PEER && hostname_verified
        raise mta_sts_error(
          "an SSLContext supplied for an MTA-STS connection does not verify the certificate",
          :tls_misconfigured
        )
      end
      context.verify_mode = OpenSSL::SSL::VERIFY_PEER
      context.verify_hostname = true if context.respond_to?(:verify_hostname=)
    end

    # The host name the certificate must be valid for. An applied policy
    # always pins the identity to the selected MX, overriding tls_hostname.
    def policy_tls_hostname
      return nil unless policy_tls_required?
      selected_mx_hostname
    end

    def selected_mx_hostname
      @mta_sts_mx_hostname || MTASTSPolicy.normalize_host(@address)
    end

    # Determine which policy, if any, governs this connection.
    #
    # The policy is supplied by the caller. It is applicable only when it
    # belongs to the recipient domain being contacted, is not in mode
    # "none", is not expired, and its mx patterns cover the selected MX.
    # A mismatch between the supplied policy domain and the recipient
    # domain is a configuration error and is rejected rather than
    # silently ignored.
    def resolve_mta_sts_policy
      policy = @mta_sts_policy
      return nil if policy.nil?

      recipient_domain = @mta_sts_domain || policy.domain
      if MTASTSPolicy.normalize_host(recipient_domain) != policy.domain
        raise mta_sts_error(
          "MTA-STS policy is for #{policy.domain.inspect}, not the recipient domain #{recipient_domain.inspect}",
          :domain_mismatch
        )
      end

      return nil if policy.none?
      unless policy.valid_at?
        mta_sts_failure(:policy_expired, :domain => policy.domain, :expires_at => policy.expires_at)
        return nil
      end

      mx_hostname = selected_mx_hostname
      unless policy.mx_allowed?(mx_hostname)
        return nil if policy.testing? && mta_sts_failure(:mx_mismatch, :domain => policy.domain, :mx => mx_hostname)
        raise mta_sts_error(
          "MTA-STS policy for #{policy.domain.inspect} does not allow MX #{mx_hostname.inspect}",
          :mx_mismatch
        )
      end

      policy
    end

    def mta_sts_error(message, reason)
      SMTPMTASTSPolicyError.new(message, reason: reason)
    end

    def mta_sts_failure(reason, details = {})
      @mta_sts_failures ||= []
      @mta_sts_failures << { :reason => reason }.merge(details)
      @mta_sts_reporter.call(reason, details) if @mta_sts_reporter
      true
    end

    def tlsconnect(s, context)
      verified = false
      s = ssl_socket(s, context)
      logging "TLS connection started"
      s.sync_close = true
      s.hostname = policy_tls_hostname || @tls_hostname || @address
      ssl_socket_connect(s, @open_timeout)
      verify_policy_identity!(s)
      verified = true
      s
    ensure
      s.close unless verified
    end

    # Defense in depth: even if the underlying OpenSSL context did not
    # enforce the host name, an applied policy requires the certificate to
    # be valid for the selected MX. Failure is treated as a policy failure.
    def verify_policy_identity!(ssl_socket)
      hostname = policy_tls_hostname
      return unless hostname
      return unless OpenSSL::SSL.respond_to?(:verify_certificate_identity)

      certificate = ssl_socket.peer_cert
      if certificate.nil?
        raise mta_sts_error("MTA-STS policy requires the MX to present a certificate", :certificate_identity)
      end
      unless OpenSSL::SSL.verify_certificate_identity(certificate, hostname)
        raise mta_sts_error(
          "certificate presented by MX #{hostname.inspect} is not valid for that name",
          :certificate_identity
        )
      end
    end

    def new_internet_message_io(s)
      InternetMessageIO.new(s, read_timeout: @read_timeout,
                            debug_output: @debug_output)
    end

    def do_helo(helo_domain)
      res = @esmtp ? ehlo(helo_domain) : helo(helo_domain)
      @capabilities = res.capabilities
    rescue SMTPError
      if @esmtp
        @esmtp = false
        @error_occurred = false
        retry
      end
      raise
    end

    def do_finish
      quit if @socket and not @socket.closed? and not @error_occurred
    ensure
      @started = false
      @error_occurred = false
      @mta_sts_applied_policy = nil
      @mta_sts_satisfied = false
      @socket.close if @socket
      @socket = nil
    end

    def requires_smtputf8(address)
      if address.kind_of? Address
        !address.address.ascii_only?
      else
        !address.ascii_only?
      end
    end

    def any_require_smtputf8(addresses)
      addresses.any?{ |a| requires_smtputf8(a) }
    end

    #
    # Message Sending
    #

    public

    #
    # Sends +msgstr+ as a message.  Single CR ("\r") and LF ("\n") found
    # in the +msgstr+, are converted into the CR LF pair.  You cannot send a
    # binary message with this method. +msgstr+ should include both
    # the message headers and body.
    #
    # +from_addr+ is a String or Net::SMTP::Address representing the source mail address.
    #
    # +to_addr+ is a String or Net::SMTP::Address or Array of them, representing
    # the destination mail address or addresses.
    #
    # === Example
    #
    #     Net::SMTP.start('smtp.example.com') do |smtp|
    #       smtp.send_message msgstr,
    #                         'from@example.com',
    #                         ['dest@example.com', 'dest2@example.com']
    #     end
    #
    #     Net::SMTP.start('smtp.example.com') do |smtp|
    #       smtp.send_message msgstr,
    #                         Net::SMTP::Address.new('from@example.com', size: 12345),
    #                         Net::SMTP::Address.new('dest@example.com', notify: :success)
    #     end
    #
    # === Errors
    #
    # This method may raise:
    #
    # * Net::SMTPServerBusy
    # * Net::SMTPSyntaxError
    # * Net::SMTPFatalError
    # * Net::SMTPUnknownError
    # * Net::ReadTimeout
    # * IOError
    #
    def send_message(msgstr, from_addr, *to_addrs)
      to_addrs.flatten!
      raise IOError, 'closed session' unless @socket
      check_mta_sts_delivery(from_addr, to_addrs)
      from_addr = Address.new(from_addr, 'SMTPUTF8') if any_require_smtputf8(to_addrs) && capable?('SMTPUTF8')
      mailfrom from_addr
      rcptto_list(to_addrs) {data msgstr}
    end

    alias send_mail send_message
    alias sendmail send_message   # obsolete

    #
    # Opens a message writer stream and gives it to the block.
    # The stream is valid only in the block, and has these methods:
    #
    # puts(str = '')::       outputs STR and CR LF.
    # print(str)::           outputs STR.
    # printf(fmt, *args)::   outputs sprintf(fmt,*args).
    # write(str)::           outputs STR and returns the length of written bytes.
    # <<(str)::              outputs STR and returns self.
    #
    # If a single CR ("\r") or LF ("\n") is found in the message,
    # it is converted to the CR LF pair.  You cannot send a binary
    # message with this method.
    #
    # === Parameters
    #
    # +from_addr+ is a String or Net::SMTP::Address representing the source mail address.
    #
    # +to_addr+ is a String or Net::SMTP::Address or Array of them, representing
    # the destination mail address or addresses.
    #
    # === Example
    #
    #     Net::SMTP.start('smtp.example.com', 25) do |smtp|
    #       smtp.open_message_stream('from@example.com', ['dest@example.com']) do |f|
    #         f.puts 'From: from@example.com'
    #         f.puts 'To: dest@example.com'
    #         f.puts 'Subject: test message'
    #         f.puts
    #         f.puts 'This is a test message.'
    #       end
    #     end
    #
    # === Errors
    #
    # This method may raise:
    #
    # * Net::SMTPServerBusy
    # * Net::SMTPSyntaxError
    # * Net::SMTPFatalError
    # * Net::SMTPUnknownError
    # * Net::ReadTimeout
    # * IOError
    #
    def open_message_stream(from_addr, *to_addrs, &block)   # :yield: stream
      to_addrs.flatten!
      raise IOError, 'closed session' unless @socket
      check_mta_sts_delivery(from_addr, to_addrs)
      from_addr = Address.new(from_addr, 'SMTPUTF8') if any_require_smtputf8(to_addrs) && capable?('SMTPUTF8')
      mailfrom from_addr
      rcptto_list(to_addrs) {data(&block)}
    end

    alias ready open_message_stream   # obsolete

    private

    # Refuse to put anything on the wire for an enforced connection that did
    # not satisfy its policy. Delivery requires the policy to have been
    # applied and the TLS state to have been established under it.
    def check_mta_sts_delivery(from_addr, to_addrs)
      return unless @mta_sts_applied_policy&.enforce?
      unless @mta_sts_satisfied
        raise mta_sts_error(
          "MTA-STS enforce policy was not satisfied; refusing to send mail",
          :policy_not_satisfied
        )
      end

      recipient_domains = []
      to_addrs.each do |address|
        value = address.kind_of?(Address) ? address.address : address.to_s
        domain = value.rpartition("@").last
        next if domain.empty? || domain == value
        recipient_domains << MTASTSPolicy.normalize_host(domain)
      end
      return if recipient_domains.empty?

      policy_domain = @mta_sts_applied_policy.domain
      unless recipient_domains.all? { |domain| domain == policy_domain }
        raise mta_sts_error(
          "MTA-STS enforce policy for #{policy_domain.inspect} cannot carry mail for " \
            "#{recipient_domains.uniq.inspect}",
          :recipient_domain_mismatch
        )
      end
    end

    public

    #
    # Authentication
    #

    DEFAULT_AUTH_TYPE = :plain

    # Authenticates with the server, using the "AUTH" command.
    #
    # +authtype+ is the name of a SASL authentication mechanism.
    #
    # All arguments-other than +authtype+-are forwarded to the authenticator.
    # Different authenticators may interpret the +user+ and +secret+
    # arguments differently.
    def authenticate(user, secret, authtype = DEFAULT_AUTH_TYPE)
      check_auth_args authtype, user, secret
      authenticator = Authenticator.auth_class(authtype).new(self)
      authenticator.auth(user, secret)
    end

    private

    def check_auth_args(type, *args, **kwargs)
      type ||= DEFAULT_AUTH_TYPE
      klass = Authenticator.auth_class(type) or
        raise ArgumentError, "wrong authentication type #{type}"
      klass.check_args(*args, **kwargs)
    end

    #
    # SMTP command dispatcher
    #

    public

    # Aborts the current mail transaction

    def rset
      getok('RSET')
    end

    def starttls
      getok('STARTTLS')
    end

    def helo(domain)
      getok("HELO #{domain}")
    end

    def ehlo(domain)
      getok("EHLO #{domain}")
    end

    # +from_addr+ is +String+ or +Net::SMTP::Address+
    def mailfrom(from_addr)
      addr = if requires_smtputf8(from_addr) && capable?("SMTPUTF8")
               Address.new(from_addr, "SMTPUTF8")
             else
               Address.new(from_addr)
             end
      getok((["MAIL FROM:<#{addr.address}>"] + addr.parameters).join(' '))
    end

    def rcptto_list(to_addrs)
      raise ArgumentError, 'mail destination not given' if to_addrs.empty?
      to_addrs.flatten.each do |addr|
        rcptto addr
      end
      yield
    end

    # +to_addr+ is +String+ or +Net::SMTP::Address+
    def rcptto(to_addr)
      addr = Address.new(to_addr)
      getok((["RCPT TO:<#{addr.address}>"] + addr.parameters).join(' '))
    end

    # This method sends a message.
    # If +msgstr+ is given, sends it as a message.
    # If block is given, yield a message writer stream.
    # You must write message before the block is closed.
    #
    #   # Example 1 (by string)
    #   smtp.data(<<EndMessage)
    #   From: john@example.com
    #   To: betty@example.com
    #   Subject: I found a bug
    #
    #   Check vm.c:58879.
    #   EndMessage
    #
    #   # Example 2 (by block)
    #   smtp.data {|f|
    #     f.puts "From: john@example.com"
    #     f.puts "To: betty@example.com"
    #     f.puts "Subject: I found a bug"
    #     f.puts ""
    #     f.puts "Check vm.c:58879."
    #   }
    #
    def data(msgstr = nil, &block)   #:yield: stream
      if msgstr and block
        raise ArgumentError, "message and block are exclusive"
      end
      unless msgstr or block
        raise ArgumentError, "message or block is required"
      end
      res = critical {
        check_continue get_response('DATA')
        socket_sync_bak = @socket.io.sync
        begin
          @socket.io.sync = false
          if msgstr
            @socket.write_message msgstr
          else
            @socket.write_message_by_block(&block)
          end
        ensure
          @socket.io.flush
          @socket.io.sync = socket_sync_bak
        end
        recv_response()
      }
      check_response res
      res
    end

    def quit
      getok('QUIT')
    end

    def get_response(reqline)
      validate_line reqline
      @socket.writeline reqline
      recv_response()
    end

    private

    def validate_line(line)
      # A bare CR or LF is not allowed in RFC5321.
      if /[\r\n]/ =~ line
        raise ArgumentError, "A line must not contain CR or LF"
      end
    end

    def getok(reqline)
      validate_line reqline
      res = critical {
        @socket.writeline reqline
        recv_response()
      }
      check_response res
      res
    end

    def recv_response
      buf = ''.dup
      while true
        line = @socket.readline
        buf << line << "\n"
        break unless line[3,1] == '-'   # "210-PIPELINING"
      end
      Response.parse(buf)
    end

    def critical
      return Response.parse('200 dummy reply code') if @error_occurred
      begin
        return yield()
      rescue Exception
        @error_occurred = true
        raise
      end
    end

    def check_response(res)
      unless res.success?
        raise res.exception_class.new(res)
      end
    end

    def check_continue(res)
      unless res.continue?
        raise SMTPUnknownError.new(res, message: "could not get 3xx (#{res.status}: #{res.string})")
      end
    end

    # This class represents a response received by the SMTP server. Instances
    # of this class are created by the SMTP class; they should not be directly
    # created by the user. For more information on SMTP responses, view
    # {Section 4.2 of RFC 5321}[http://tools.ietf.org/html/rfc5321#section-4.2]
    class Response
      # Parses the received response and separates the reply code and the human
      # readable reply text
      def self.parse(str)
        new(str[0,3], str)
      end

      # Creates a new instance of the Response class and sets the status and
      # string attributes
      def initialize(status, string)
        @status = status
        @string = string
      end

      # The three digit reply code of the SMTP response
      attr_reader :status

      # The human readable reply text of the SMTP response
      attr_reader :string

      # Takes the first digit of the reply code to determine the status type
      def status_type_char
        @status[0, 1]
      end

      # Determines whether the response received was a Positive Completion
      # reply (2xx reply code)
      def success?
        status_type_char() == '2'
      end

      # Determines whether the response received was a Positive Intermediate
      # reply (3xx reply code)
      def continue?
        status_type_char() == '3'
      end

      # The first line of the human readable reply text
      def message
        @string.lines.first
      end

      # Creates a CRAM-MD5 challenge. You can view more information on CRAM-MD5
      # on Wikipedia: https://en.wikipedia.org/wiki/CRAM-MD5
      def cram_md5_challenge
        @string.split(/ /)[1].unpack1('m')
      end

      # Returns a hash of the human readable reply text in the response if it
      # is multiple lines. It does not return the first line. The key of the
      # hash is the first word the value of the hash is an array with each word
      # thereafter being a value in the array
      def capabilities
        return {} unless @string[3, 1] == '-'
        h = {}
        @string.lines.drop(1).each do |line|
          k, *v = line[4..-1].split(' ')
          h[k] = v
        end
        h
      end

      # Determines whether there was an error and raises the appropriate error
      # based on the reply code of the response
      def exception_class
        case @status
        when /\A4/  then SMTPServerBusy
        when /\A50/ then SMTPSyntaxError
        when /\A53/ then SMTPAuthenticationError
        when /\A5/  then SMTPFatalError
        else             SMTPUnknownError
        end
      end
    end

    def logging(msg)
      @debug_output << msg + "\n" if @debug_output
    end

    # Address with parametres for MAIL or RCPT command
    class Address
      # mail address [String]
      attr_reader :address
      # parameters [Array<String>]
      attr_reader :parameters

      # :call-seq:
      #  initialize(address, parameter, ...)
      #
      # address +String+ or +Net::SMTP::Address+
      # parameter +String+ or +Hash+
      def initialize(address, *args, **kw_args)
        if address.kind_of? Address
          @address = address.address
          @parameters = address.parameters
        else
          @address = address
          @parameters = []
        end
        @parameters = (parameters + args + [kw_args]).map{|param| Array(param)}.flatten(1).map{|param| Array(param).compact.join('=')}.uniq
      end

      def to_s
        @address
      end
    end
  end   # class SMTP

  SMTPSession = SMTP # :nodoc:
end

require_relative 'smtp/mta_sts_policy'
require_relative 'smtp/authenticator'
Dir.glob("#{__dir__}/smtp/auth_*.rb") do |r|
  require_relative r
end
