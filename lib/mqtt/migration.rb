module MQTT
  # Strict checks and helpers for migrating a connection between MQTT 3.1.0
  # and MQTT 3.1.1 without changing the identity presented to the server.
  #
  # The migration is deliberately conservative:
  # * client_id is never generated or replaced
  # * a persistent session requires an explicit client_id
  # * a CONNACK only counts as a resumed session when Session Present is 1
  # * a failed attempt is never retried with another version or client_id
  module Migration
    # Versions that may be compared or migrated between
    SUPPORTED_VERSIONS = %w[3.1 3.1.0 3.1.1].freeze

    # MQTT 3.1.1 CONNACK Connect Return code values
    RETURN_CODES = {
      0x00 => 'Connection Accepted',
      0x01 => 'Connection refused: unacceptable protocol version',
      0x02 => 'Connection refused: client identifier rejected',
      0x03 => 'Connection refused: server unavailable',
      0x04 => 'Connection refused: bad user name or password',
      0x05 => 'Connection refused: not authorised'
    }.freeze

    # Attributes that define the identity presented in the CONNECT packet
    IDENTITY_ATTRIBUTES = [
      :client_id,
      :clean_session,
      :username,
      :password,
      :will_topic,
      :will_payload,
      :will_qos,
      :will_retain
    ].freeze

    # Outcome of one in-memory connection attempt
    class Result
      attr_reader :version, :client_id, :bytes_sent, :session_present, :error,
                  :connect_count

      def initialize(attributes = {})
        @version = attributes[:version]
        @client_id = attributes[:client_id]
        @bytes_sent = attributes[:bytes_sent]
        @session_present = attributes[:session_present]
        @connected = attributes[:connected]
        @error = attributes[:error]
        @connect_count = attributes[:connect_count] || 0
      end

      # True if the server sent an accepted CONNACK
      def connected?
        !!@connected
      end
      alias accepted? connected?

      # True if the server reported that it resumed stored session state
      def session_resumed?
        connected? && !@session_present.nil? && @session_present
      end

      # True if this attempt failed
      def failure?
        !@error.nil?
      end
    end

    # Normalise a protocol version name
    def self.normalise_version(version)
      value = version.to_s
      value == '3.1' ? '3.1.0' : value
    end

    # Raise unless the version is one that this library can encode.
    def self.check_version!(version)
      unless SUPPORTED_VERSIONS.include?(version.to_s)
        raise MQTT::MigrationError, "Unsupported protocol version: #{version}"
      end

      normalise_version(version)
    end

    # Capture the identity attributes of a client.
    #
    # The returned Hash keeps the client_id exactly as configured, including
    # nil and empty values: those are meaningful and must not be replaced.
    def self.identity(client)
      IDENTITY_ATTRIBUTES.each_with_object({}) do |name, hash|
        hash[name] = client.public_send(name)
      end
    end

    # Configuration that cannot preserve identity when written to the wire.
    #
    # Returns an Array of human readable problems. An empty Array means the
    # configuration can be encoded without silently changing any field.
    def self.problems(client, version = nil)
      version = begin
        check_version!(version || client.version)
      rescue MQTT::MigrationError => e
        return [e.message]
      end

      problems = []
      client_id = client.client_id
      empty_id = client_id.nil? || client_id.to_s.empty?

      if client.respond_to?(:client_id_generated?) && client.client_id_generated?
        problems << 'client_id was generated locally instead of being supplied'
      end

      if empty_id
        if version == '3.1.0'
          problems << 'client_id is required for MQTT 3.1.0'
        elsif !client.clean_session
          problems << 'client_id is required when clean_session is false'
        elsif client.respond_to?(:strict_client_id) && client.strict_client_id
          problems << 'client_id is required when strict_client_id is enabled'
        end
      elsif !utf8?(client_id)
        problems << 'client_id is not valid UTF-8'
      elsif version == '3.1.0' && client_id.to_s.bytesize > 23
        problems << 'client_id is longer than 23 bytes, which MQTT 3.1.0 cannot carry'
      end

      if version == '3.1.0'
        [:username, :password, :will_topic, :will_payload].each do |name|
          value = client.public_send(name)
          next if value.nil?

          unless utf8?(value)
            problems << "#{name} is not valid UTF-8, which MQTT 3.1.0 cannot carry"
          end
        end
      else
        [:username, :will_topic].each do |name|
          value = client.public_send(name)
          next if value.nil?

          problems << "#{name} is not valid UTF-8" unless utf8?(value)
        end
      end

      unless client.keep_alive.to_i.between?(0, 0xffff)
        problems << 'keep_alive must be between 0 and 65535'
      end

      if client.password && client.username.nil?
        problems << 'password is set without a username'
      end

      if client.will_topic.nil?
        if client.will_retain || client.will_qos.to_i != 0
          problems << 'will_qos/will_retain is set without a will_topic'
        end
        unless client.will_payload.nil? || client.will_payload.to_s.empty?
          problems << 'will_payload is set without a will_topic'
        end
      elsif client.will_topic.to_s.empty?
        problems << 'will_topic is empty'
      end

      unless client.will_qos.to_i.between?(0, 2)
        problems << 'will_qos must be 0, 1 or 2'
      end

      if client.clean_session && client.require_session_resumed
        problems << 'cannot require a resumed session when clean_session is true'
      end

      problems
    end

    # Raise MQTT::MigrationError unless the configuration can be encoded with
    # exactly the identity, credentials and Will that were configured.
    def self.check!(client, version = nil)
      problems = problems(client, version)
      return true if problems.empty?

      raise MQTT::MigrationError, problems.join('; ')
    end

    # Compare the identity of a client before and after a change.
    #
    # Returns an Array of attribute names that changed. Credentials and the
    # Will are included, so a rewrite cannot pass unnoticed. String fields are
    # compared as bytes, because the same bytes may be labelled UTF-8 in one
    # version and binary in the other without any change to the payload.
    def self.changed_attributes(before, after)
      IDENTITY_ATTRIBUTES.select do |name|
        !same_identity_value?(before[name], after[name])
      end
    end

    # True if a value can be encoded as a UTF-8 string
    def self.utf8?(value)
      value.to_s.dup.force_encoding('UTF-8').valid_encoding?
    end

    # Compare one identity value, treating strings as byte sequences
    def self.same_identity_value?(left, right)
      if left.is_a?(String) && right.is_a?(String)
        left.b == right.b
      else
        left == right
      end
    end

    # Build the CONNECT packet for a client and an explicit version.
    def self.connect_packet(client, version)
      version = check_version!(version)
      check!(client, version)

      MQTT::Packet::Connect.new(
        :version => version,
        :clean_session => client.clean_session,
        :keep_alive => client.keep_alive,
        :client_id => client.client_id,
        :username => client.username,
        :password => client.password,
        :will_topic => client.will_topic,
        :will_payload => client.will_payload,
        :will_qos => client.will_qos,
        :will_retain => client.will_retain
      )
    end

    # Serialise a CONNECT packet without opening a socket.
    def self.handshake_bytes(client, version = nil)
      begin
        connect_packet(client, version || client.version).to_s
      rescue MQTT::MigrationError
        raise
      rescue ::StandardError => e
        raise MQTT::MigrationError, e.message
      end
    end

    # Check that the flags in a parsed CONNECT match the payload fields and
    # that the packet does not contain fields that its flags do not announce.
    #
    # Raise MigrationError when the flags and payload disagree, or when the
    # ClientId rules for the packet's version are not met.
    def self.validate_connect_packet!(packet)
      flags = packet.connect_flags.to_i
      version = normalise_version(packet.version)

      if (flags & 0x01) != 0
        raise MQTT::MigrationError, 'Reserved flag in Connect flags is not zero'
      end

      if (flags & 0x40) != 0 && (flags & 0x80).zero?
        raise MQTT::MigrationError, 'Password flag set without User Name flag'
      end

      if (flags & 0x04).zero? && (flags & 0x38) != 0
        raise MQTT::MigrationError, 'Will QoS and Will Retain must be zero when Will flag is not set'
      end

      if (flags & 0x04) != 0 && ((flags & 0x18) >> 3) == 0x03
        raise MQTT::MigrationError, 'Invalid Will QoS value of 3'
      end

      # The flags must also agree with the fields that were actually parsed.
      if (flags & 0x04) != 0
        if packet.will_topic.nil? || packet.will_payload.nil?
          raise MQTT::MigrationError, 'Will flag set but Will fields are missing'
        end
      elsif !packet.will_topic.nil?
        raise MQTT::MigrationError, 'Will topic present but Will flag is not set'
      end

      if (flags & 0x80) != 0
        if packet.username.nil?
          raise MQTT::MigrationError, 'User Name flag set but User Name is missing'
        end
      elsif !packet.username.nil?
        raise MQTT::MigrationError, 'User Name present but User Name flag is not set'
      end

      if (flags & 0x40) != 0
        if packet.password.nil?
          raise MQTT::MigrationError, 'Password flag set but Password is missing'
        end
      elsif !packet.password.nil?
        raise MQTT::MigrationError, 'Password present but Password flag is not set'
      end

      if version == '3.1.0'
        if packet.client_id.nil? || packet.client_id.bytesize.zero?
          raise MQTT::MigrationError, 'ClientId must not be empty for MQTT 3.1.0'
        end
        if packet.client_id.bytesize > 23
          raise MQTT::MigrationError, 'ClientId is too long for MQTT 3.1.0'
        end
      elsif packet.client_id.nil? && !packet.clean_session
        raise MQTT::MigrationError, 'ClientId must be present when clean_session is false'
      end

      true
    end

    # Parse a complete CONNECT packet, rejecting a mismatched body length.
    def self.parse_connect(bytes)
      buffer = bytes.dup
      packet = MQTT::Packet.parse_header(buffer)
      unless packet.is_a?(MQTT::Packet::Connect)
        raise MQTT::ProtocolException, "Packet was not a CONNECT: #{packet.class}"
      end
      packet.parse_body(buffer)
      packet
    end

    # The identity carried by a parsed CONNECT packet, in the same shape as
    # MQTT::Migration.identity.
    def self.packet_identity(packet)
      {
        :client_id => packet.client_id,
        :clean_session => packet.clean_session,
        :username => packet.username,
        :password => packet.password,
        :will_topic => packet.will_topic,
        :will_payload => packet.will_payload,
        :will_qos => packet.will_qos,
        :will_retain => packet.will_retain
      }
    end

    # Compare the complete CONNECT packets produced for two protocol versions.
    #
    # The comparison is over the exact bytes sent on the wire, not just the
    # parsed attributes: protocol name and level necessarily differ, everything
    # else must be representable without being rewritten.
    def self.compare_handshakes(client, from_version, to_version)
      from_version = check_version!(from_version)
      to_version = check_version!(to_version)

      check!(client, from_version)
      check!(client, to_version)

      from_bytes = handshake_bytes(client, from_version)
      to_bytes = handshake_bytes(client, to_version)

      from_packet = parse_connect(from_bytes)
      to_packet = parse_connect(to_bytes)
      validate_connect_packet!(from_packet)
      validate_connect_packet!(to_packet)

      from_identity = packet_identity(from_packet)
      to_identity = packet_identity(to_packet)

      {
        :from_version => from_version,
        :to_version => to_version,
        :from_bytes => from_bytes,
        :to_bytes => to_bytes,
        :identical => from_bytes == to_bytes,
        :from_packet => from_packet,
        :to_packet => to_packet,
        :from_identity => from_identity,
        :to_identity => to_identity,
        :changed => changed_attributes(from_identity, to_identity)
      }
    end

    # Describe why a CONNACK must not be treated as a successful connection
    # to the previously stored session.
    #
    # Returns nil only for a zero return code. When clean_session is false it
    # additionally requires Session Present = 1: a zero return code alone means
    # that the network connection was accepted, not that the old session was
    # resumed. With clean_session true, Session Present must be 0.
    #
    # The following are never proof of a resumed session:
    # * return code 0x00 with Session Present = 0 and clean_session false
    # * any non-zero return code (0x01..0x05 or unknown)
    # * a CONNACK with reserved/illegal flags
    # * any packet that is not a CONNACK
    def self.session_problem(connack, clean_session)
      unless connack.is_a?(MQTT::Packet::Connack)
        return 'response was not a CONNACK'
      end

      if connack.return_code != 0x00
        return RETURN_CODES.fetch(connack.return_code, "error code #{connack.return_code}")
      end

      if clean_session && connack.session_present
        # MQTT-3.2.2-1: with CleanSession=1 a server MUST send Session Present=0.
        return 'Session Present set for a clean session'
      end

      if !clean_session && !connack.session_present
        return 'Session Present is not set: the server did not resume the session'
      end

      nil
    end

    # Server responses that must never be treated as a successful connection
    # to the previous session, with the reason why.
    def self.successful_session_response?(connack, clean_session)
      session_problem(connack, clean_session).nil?
    end

    # Connect one client once, for one version, over an in-memory transport.
    #
    # server_response is the exact CONNACK (or other) bytes that the server
    # sends. There is no retry: a refusal is returned in the Result as an
    # error, and the client_id is left exactly as supplied.
    def self.connect_once(client, version, server_response)
      version = check_version!(version)
      check!(client, version)

      client.version = version
      client_id_before = client.client_id
      connect_count = { :value => 0 }

      transport, server = MQTT::MemoryTransport.pair

      server_endpoint = Thread.new do
        Thread.current.report_on_exception = false
        begin
          loop do
            packet = MQTT::Packet.read(server)
            next unless packet.is_a?(MQTT::Packet::Connect)

            connect_count[:value] += 1
            server.write(server_response)
          end
        rescue IOError, SystemCallError, MQTT::ProtocolException
          nil
        end
      end

      error = nil
      connected = false
      start_read_thread_before = client.start_read_thread
      begin
        client.transport = transport
        client.start_read_thread = false
        client.connect
        connected = true
      rescue ::Exception => e
        error = e
      ensure
        client.start_read_thread = start_read_thread_before
        client.disconnect(false) if client.respond_to?(:disconnect)
        client.transport = nil
        server.close
        server_endpoint.join(0.5)
        server_endpoint.kill if server_endpoint.alive?
        transport.close
      end

      unless same_identity_value?(client.client_id, client_id_before)
        raise MQTT::MigrationError, 'client_id changed during a connection attempt'
      end

      Result.new(
        :version => version,
        :client_id => client.client_id,
        :bytes_sent => transport.written.dup,
        :session_present => client.session_present,
        :connected => connected,
        :error => error,
        :connect_count => connect_count[:value]
      )
    end

    # Connect a client once, strictly, without any fallback.
    #
    # This is the production entry point for a migration window:
    # * the client_id is never generated and must be explicit
    # * the configured identity is snapshotted and compared afterwards
    # * a persistent session requires Session Present = 1 when requested
    # * any failure closes the socket and re-raises; no other version and no
    #   other client_id is attempted
    def self.connect!(client, version = nil, require_session_resumed = nil)
      version = check_version!(version || client.version)

      if client.respond_to?(:strict_client_id=)
        client.strict_client_id = true
      end
      unless require_session_resumed.nil?
        client.require_session_resumed = require_session_resumed
      end

      before = identity(client)
      check!(client, version)
      client.version = version
      bytes_sent = handshake_bytes(client, version)

      begin
        client.connect
      rescue ::Exception
        # connect already closed the socket. The version is left at the value
        # that was actually attempted and is never used for an automatic
        # retry: the caller decides what, if anything, happens next.
        raise
      end

      after = identity(client)
      changed = changed_attributes(before, after)
      unless changed.empty?
        client.disconnect(false)
        raise MQTT::MigrationError,
              "Identity changed during connect: #{changed.join(', ')}"
      end

      unless client.version.to_s == version
        client.disconnect(false)
        raise MQTT::MigrationError,
              "Protocol version changed during connect: #{client.version}"
      end

      Result.new(
        :version => version,
        :client_id => client.client_id,
        :bytes_sent => bytes_sent,
        :session_present => client.session_present,
        :connected => true,
        :error => nil
      )
    end

    # Compare the complete bytes of two handshakes, each sent once over an
    # in-memory transport, and confirm the identity did not change.
    #
    # server_response is the same reply for both attempts. A refusal is
    # returned in the Result rather than retried.
    def self.compare_connections(client, from_version, to_version, server_response = nil)
      server_response ||= connack(0x00, false)

      check!(client, from_version)
      check!(client, to_version)

      before = identity(client)
      from_result = connect_once(client, from_version, server_response)
      after_from = identity(client)

      if changed_attributes(before, after_from).any?
        raise MQTT::MigrationError,
              "Identity changed during comparison: #{changed_attributes(before, after_from).join(', ')}"
      end
      to_result = connect_once(client, to_version, server_response)
      after_to = identity(client)

      if changed_attributes(before, after_to).any?
        raise MQTT::MigrationError,
              "Identity changed during comparison: #{changed_attributes(before, after_to).join(', ')}"
      end

      {
        :from_result => from_result,
        :to_result => to_result,
        :from_bytes => from_result.bytes_sent,
        :to_bytes => to_result.bytes_sent,
        :identical => from_result.bytes_sent == to_result.bytes_sent,
        :changed => changed_attributes(after_from, after_to),
        :client_identity => after_to
      }
    end

    # Build a CONNACK for use as a server response.
    def self.connack(return_code = 0x00, session_present = false)
      MQTT::Packet::Connack.new(
        :return_code => return_code,
        :session_present => session_present
      ).to_s
    end
  end
end
