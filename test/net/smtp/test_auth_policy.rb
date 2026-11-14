require 'net/smtp'
require 'test/unit'

module Net
  class TestAuthPolicy < Test::Unit::TestCase
    # An SMTP client whose transport is a pre-connected socket pair.  This
    # avoids depending on the ability to bind a TCP port in the test sandbox.
    class ScriptedSMTP < SMTP
      def initialize(socket)
        @fake_socket = socket
        super('localhost')
      end

      private

      def tcp_socket(*)
        @fake_socket
      end

      def tlsconnect(*)
        @fake_socket
      end
    end

    class RecordingAuthenticator < Net::SMTP::Authenticator
      RECORDS = []

      def self.record(mechanism, credential_type, user, secret)
        RECORDS << {
          mechanism: mechanism,
          credential_type: credential_type,
          user: user,
          secret: secret,
        }
      end

      def self.records
        RECORDS
      end

      def self.clear_records
        RECORDS.clear
      end
    end

    class RecordingPlain < Net::SMTP::AuthPlain
      def auth(user, secret)
        RecordingAuthenticator.record(:plain, credential_type, user, secret)
        super
      end
    end

    class RecordingLogin < Net::SMTP::AuthLogin
      def auth(user, secret)
        RecordingAuthenticator.record(:login, credential_type, user, secret)
        super
      end
    end

    class RecordingXoauth2 < Net::SMTP::AuthXoauth2
      def auth(user, secret)
        RecordingAuthenticator.record(:xoauth2, credential_type, user, secret)
        super
      end
    end

    # A custom authenticator that does not declare its credential type.
    class UndeclaredXoauth2 < Net::SMTP::AuthXoauth2
      def self.auth_credential(type = :undefined)
        type == :undefined ? nil : super
      end

      def auth(user, secret)
        RecordingAuthenticator.record(:xoauth2, credential_type, user, secret)
        super
      end
    end

    def setup
      @auth_classes = Net::SMTP::Authenticator.auth_classes.dup
      RecordingAuthenticator.clear_records
      RecordingPlain.auth_type(:plain, credential: :password)
      RecordingLogin.auth_type(:login, credential: :password)
      RecordingXoauth2.auth_type(:xoauth2, credential: :oauth2)
    end

    def teardown
      Net::SMTP::Authenticator.auth_classes.replace(@auth_classes)
      @server_thread&.exit&.join
      @server_socket&.close
      @client_socket&.close
    end

    def records
      RecordingAuthenticator.records
    end

    def ehlo_response(*mechanisms, starttls: false)
      lines = ["250-fakeserver\r\n"]
      lines << "250-STARTTLS\r\n" if starttls
      lines << "250-AUTH #{mechanisms.join(' ')}\r\n" unless mechanisms.empty?
      lines << "250 8BITMIME\r\n"
      lines.join
    end

    def start_server(ehlo, after_starttls: nil, auth_responses: {})
      @server_socket, @client_socket = Object.const_defined?(:UNIXSocket) ?
        UNIXSocket.pair : Socket.pair(:INET, :STREAM, 0)
      @commands = []
      commands = @commands
      auth_responses = auth_responses.dup
      @server_thread = Thread.new(@server_socket) do |sock|
        sock.puts "220 fakeserver\r\n"
        current_ehlo = ehlo
        while (command = sock.gets&.chomp)
          commands << command
          case command
          when /\AEHLO /
            sock.puts current_ehlo
          when "STARTTLS"
            sock.puts "220 2.0.0 Ready to start TLS\r\n"
            current_ehlo = after_starttls || current_ehlo
          when /\AAUTH (.*)/
            args = $1.split(' ')
            mechanism = args[0].upcase
            if mechanism == 'LOGIN' && args.size == 1
              sock.puts "334 VXNlcm5hbWU6\r\n"
              sock.gets
              sock.puts "334 UGFzc3dvcmQ6\r\n"
              sock.gets
            end
            response = auth_responses.fetch(mechanism,
                                            '235 2.7.0 Authentication successful')
            sock.puts response + "\r\n"
          when "QUIT"
            sock.puts "221 2.0.0 Bye\r\n"
            break
          else
            sock.puts "250 2.0.0 Ok\r\n"
          end
        end
      end
      ScriptedSMTP.new(@client_socket)
    end

    def test_policy_selects_first_allowed_mechanism_in_order
      smtp = start_server(ehlo_response('PLAIN', 'LOGIN'))
      smtp.start(user: 'account', secret: 'password',
                 auth_policy: {mechanisms: [:login, :plain],
                               credential: :password}) {}

      assert_equal [:PLAIN, :LOGIN], smtp.auth_mechanisms
      assert_equal 1, records.count { |record| record[:mechanism] == :login }
      assert_equal 0, records.count { |record| record[:mechanism] == :plain }
      assert_match(/\AAUTH LOGIN/, @commands.grep(/\AAUTH /).first)
      assert_equal :LOGIN, smtp.auth_mechanism
    end

    def test_oauth_token_never_reaches_password_mechanisms
      smtp = start_server(ehlo_response('PLAIN', 'LOGIN', 'XOAUTH2'))
      policy = {mechanisms: [:plain, :login, :xoauth2], credential: :oauth2}
      smtp.start(user: 'account', secret: 'selector-secret', auth_policy: policy) {}

      oauth_records = records.select { |record| record[:credential_type] == :oauth2 }
      password_records = records.select { |record| record[:credential_type] == :password }

      assert_equal 1, oauth_records.size
      assert_equal :xoauth2, oauth_records.first[:mechanism]
      assert_equal 'selector-secret', oauth_records.first[:secret]
      assert_equal [], password_records
      assert_equal 0, records.count { |record| [:plain, :login].include?(record[:mechanism]) }
      assert_match(/\AAUTH XOAUTH2 /, @commands.grep(/\AAUTH /).first)
    end

    def test_rejected_authentication_does_not_try_another_mechanism
      smtp = start_server(ehlo_response('PLAIN', 'LOGIN'),
                          auth_responses: {'LOGIN' => '535 5.7.8 rejected'})
      policy = {mechanisms: [:login, :plain], credential: :password}

      error = assert_raise(Net::SMTPAuthenticationError) do
        smtp.start(user: 'account', secret: 'selector-secret', auth_policy: policy) {}
      end
      assert_equal '535', error.response.status

      auth_commands = @commands.grep(/\AAUTH /)
      assert_equal 1, auth_commands.size
      assert_match(/\AAUTH LOGIN/, auth_commands.first)
      assert_equal 0, records.count { |record| record[:mechanism] == :plain }
    end

    def test_unknown_credential_type_is_rejected
      assert_raise(ArgumentError) do
        Net::SMTP::AuthPolicy.new([:plain], credential: :certificate)
      end
      assert_raise(ArgumentError) do
        Net::SMTP::AuthPolicy.new([:plain], credential: :passwrod)
      end
    end

    def test_unknown_mechanism_is_rejected_at_policy_construction
      assert_raise(Net::SMTPAuthMechanismError) do
        Net::SMTP::AuthPolicy.new([:does_not_exist], credential: :password)
      end
    end

    def test_no_eligible_mechanism_is_rejected_before_sending_credentials
      smtp = start_server(ehlo_response('PLAIN', 'LOGIN'))
      policy = {mechanisms: [:xoauth2, :plain], credential: :oauth2}

      error = assert_raise(Net::SMTPAuthMechanismError) do
        smtp.start(user: 'account', secret: 'selector-secret', auth_policy: policy) {}
      end
      assert_match(/no allowed authentication mechanism/, error.message)
      assert_equal [], @commands.grep(/\AAUTH /)
      assert_equal [], records
    end

    def test_duplicate_capabilities_are_merged_and_deduplicated
      smtp = start_server("250-fakeserver\r\n" \
                          "250-AUTH PLAIN PLAIN\r\n" \
                          "250-AUTH LOGIN XOAUTH2\r\n" \
                          "250 8BITMIME\r\n")
      smtp.start {}

      assert_equal [:PLAIN, :LOGIN, :XOAUTH2], smtp.auth_mechanisms
      assert_equal %w[PLAIN LOGIN XOAUTH2], smtp.capable_auth_types
      assert_equal true, smtp.auth_capable?('plain')
    end

    def test_capabilities_after_starttls_are_used_for_selection
      smtp = start_server(ehlo_response('PLAIN', starttls: true),
                          after_starttls: ehlo_response('XOAUTH2'))
      policy = {mechanisms: [:plain, :xoauth2], credential: :oauth2}

      smtp.start(user: 'account', secret: 'selector-secret', auth_policy: policy) {}

      assert_equal [:XOAUTH2], smtp.auth_mechanisms
      assert_equal 1, records.count { |record| record[:mechanism] == :xoauth2 }
      assert_equal 0, records.count { |record| record[:mechanism] == :plain }
      assert @commands.include?('STARTTLS')
    end

    def test_helo_fallback_cannot_expose_auth_capabilities
      smtp = start_server("250-fakeserver\r\n" \
                          "250-AUTH PLAIN LOGIN\r\n" \
                          "250 8BITMIME\r\n")
      # Force the client to fall back to HELO, then provide a malformed
      # multi-line HELO response that looks like EHLO extensions.
      smtp.define_singleton_method(:ehlo) do |_|
        raise Net::SMTPFatalError.new('500 EHLO rejected')
      end
      helo_response = Net::SMTP::Response.parse("250-fakeserver\r\n250-AUTH PLAIN\r\n250 8BITMIME\r\n")
      smtp.define_singleton_method(:helo) { |_| helo_response }

      smtp.start {}

      assert_equal false, smtp.esmtp?
      assert_equal [], smtp.auth_mechanisms
      assert_equal false, smtp.auth_capable?('PLAIN')
      assert_nil smtp.capabilities['AUTH']
      assert_equal false, smtp.capable?('AUTH')
    ensure
      smtp.finish if smtp&.started?
    end

    def test_capability_removed_after_tls_is_not_used
      smtp = start_server(ehlo_response('XOAUTH2', starttls: true),
                          after_starttls: ehlo_response('PLAIN'))
      policy = {mechanisms: [:xoauth2], credential: :oauth2}

      assert_raise(Net::SMTPAuthMechanismError) do
        smtp.start(user: 'account', secret: 'selector-secret', auth_policy: policy) {}
      end
      assert_equal [], @commands.grep(/\AAUTH /)
    end

    def test_explicit_authtype_entry_is_unchanged
      smtp = start_server(ehlo_response('XOAUTH2', 'PLAIN'))
      smtp.start(authtype: :xoauth2, user: 'account', secret: 'token') {}

      assert_equal "AUTH XOAUTH2 dXNlcj1hY2NvdW50AWF1dGg9QmVhcmVyIHRva2VuAQE=",
                   @commands.grep(/\AAUTH /).last
      assert_equal 1, records.count { |record| record[:mechanism] == :xoauth2 }
    end

    def test_explicit_authtype_is_available_without_a_policy
      smtp = start_server(ehlo_response('PLAIN', 'LOGIN'))
      smtp.start

      assert smtp.authenticate('account', 'password', :plain).success?
      assert_equal "AUTH PLAIN AGFjY291bnQAcGFzc3dvcmQ=", @commands.grep(/\AAUTH /).last
      assert_equal 1, records.count { |record| record[:mechanism] == :plain }
      assert_equal :PLAIN, smtp.auth_mechanism
    ensure
      smtp.finish if smtp&.started?
    end

    def test_unknown_advertised_capability_does_not_crash_selection
      smtp = start_server(ehlo_response('PLAIN', 'FUTURE-MECH'))
      policy = {mechanisms: [:plain, :unknown_but_advertised], credential: :password}

      # The policy's own unknown name is rejected at construction instead of
      # being silently ignored.
      assert_raise(Net::SMTPAuthMechanismError) do
        Net::SMTP::AuthPolicy.new([:unknown_but_advertised], :password)
      end

      # An unknown mechanism that is only *advertised* is ignored.
      smtp.start(user: 'account', secret: 'password',
                 auth_policy: {mechanisms: [:plain], credential: :password}) {}
      assert_equal [:PLAIN, :"FUTURE-MECH"], smtp.auth_mechanisms
      assert_equal 'PLAIN', @commands.grep(/\AAUTH /).first.split(' ')[1]
    end

    def test_policy_can_be_passed_in_positional_authtype_slot
      smtp = start_server(ehlo_response('PLAIN', 'LOGIN'))
      policy = Net::SMTP::AuthPolicy.new([:login, :plain], credential: :password)
      smtp.start('myname', 'account', 'password', policy) {}

      assert_equal 'LOGIN', @commands.grep(/\AAUTH /).first.split(' ')[1]
      assert_equal :LOGIN, smtp.auth_mechanism
    end

    def test_helper_accepts_policy_or_explicit_list_and_credential
      smtp = start_server(ehlo_response('PLAIN', 'LOGIN'))
      smtp.start {}  # establishes capabilities without authenticating

      assert_equal :LOGIN, smtp.select_auth_mechanism([:login, :plain], :password)
      assert_equal :LOGIN, smtp.select_auth_mechanism(mechanisms: [:login, :plain],
                                                      credential: :password)
      assert_equal :PLAIN, smtp.select_auth_mechanism(Net::SMTP::AuthPolicy.new([:plain], :password))
      assert_equal :LOGIN, smtp.select_auth_mechanism(policy: {mechanisms: [:login],
                                                              credential: :password})
      assert_nil smtp.auth_mechanism
    ensure
      smtp.finish if smtp&.started?
    end

    def test_separated_keywords_select_single_mechanism
      smtp = start_server(ehlo_response('PLAIN', 'LOGIN'))
      smtp.start(user: 'account', secret: 'password',
                 mechanisms: [:login, :plain], credential: :password) {}

      assert_equal 'LOGIN', @commands.grep(/\AAUTH /).first.split(' ')[1]
      assert_equal :LOGIN, smtp.auth_mechanism
    end

    def test_separated_keywords_are_also_available_on_instance_start
      smtp = start_server(ehlo_response('PLAIN', 'LOGIN'))
      instance = ScriptedSMTP.new(@client_socket)
      instance.start(user: 'account', secret: 'password',
                     allowed: [:plain, :login], credential_type: :password) {}

      assert_equal 'PLAIN', @commands.grep(/\AAUTH /).first.split(' ')[1]
      assert_equal :PLAIN, instance.auth_mechanism
    end

    def test_authenticate_with_policy_attempts_only_selection
      smtp = start_server(ehlo_response('PLAIN', 'LOGIN', 'XOAUTH2'))
      smtp.start

      smtp.authenticate_with_policy('account', 'token',
                                    policy: {mechanisms: [:plain, :xoauth2],
                                             credential: :oauth2})
      assert_equal 1, records.count { |record| record[:credential_type] == :oauth2 }
      assert_equal [], records.select { |record| record[:mechanism] == :plain }
      assert_equal :XOAUTH2, smtp.auth_mechanism
    ensure
      smtp.finish if smtp&.started?
    end

    def test_policy_rejects_mutually_exclusive_explicit_type
      smtp = start_server(ehlo_response('PLAIN'))
      assert_raise(ArgumentError) do
        smtp.start(user: 'account', secret: 'password', authtype: :plain,
                   auth_policy: {mechanisms: [:plain], credential: :password}) {}
      end
      assert_raise(ArgumentError) do
        smtp.start(user: 'account', secret: 'password', authtype: :plain,
                   mechanisms: [:plain], credential: :password) {}
      end
    end

    def test_duplicate_policy_entries_are_ignored_preserving_order
      policy = Net::SMTP::AuthPolicy.new([:login, 'LOGIN', :plain], credential: :password)
      assert_equal [:LOGIN, :PLAIN], policy.mechanisms
    end

    def test_custom_authenticator_without_declaration_infers_oauth_by_mechanism_name
      UndeclaredXoauth2.auth_type(:xoauth2)
      smtp = start_server(ehlo_response('PLAIN', 'XOAUTH2'))

      assert_equal :oauth2, Net::SMTP::Authenticator.credential_for(:xoauth2)
      smtp.start(user: 'account', secret: 'token',
                 auth_policy: {mechanisms: [:plain, :xoauth2], credential: :oauth2}) {}

      assert_equal [], records.select { |record| record[:mechanism] == :plain }
      assert_equal 1, records.count { |record| record[:credential_type] == :oauth2 }
      assert_equal "AUTH XOAUTH2 dXNlcj1hY2NvdW50AWF1dGg9QmVhcmVyIHRva2VuAQE=",
                   @commands.grep(/\AAUTH /).last
    end
  end
end
