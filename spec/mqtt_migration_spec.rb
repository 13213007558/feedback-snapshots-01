$:.unshift(File.dirname(__FILE__))

require 'spec_helper'
require 'mqtt'

describe MQTT::Migration do
  def client(options = {})
    MQTT::Client.new({
      :host => 'localhost',
      :client_id => 'stable-client',
      :clean_session => false,
      :username => 'user',
      :password => 'secret',
      :keep_alive => 60
    }.merge(options))
  end

  describe "identity snapshot" do
    it "keeps an empty client id empty" do
      identity = MQTT::Migration.identity(client(:client_id => '', :clean_session => true))
      expect(identity[:client_id]).to eq('')
    end

    it "keeps a nil client id nil" do
      identity = MQTT::Migration.identity(client(:client_id => nil, :clean_session => true))
      expect(identity[:client_id]).to be_nil
    end

    it "keeps an empty password empty instead of treating it as absent" do
      identity = MQTT::Migration.identity(client(:password => ''))
      expect(identity[:password]).to eq('')
    end

    it "includes the Will attributes" do
      subject = client
      subject.set_will('will/topic', 'bye', true, 2)
      identity = MQTT::Migration.identity(subject)
      expect(identity[:will_topic]).to eq('will/topic')
      expect(identity[:will_payload]).to eq('bye')
      expect(identity[:will_qos]).to eq(2)
      expect(identity[:will_retain]).to be_truthy
    end
  end

  describe "strict configuration checks" do
    it "accepts a persistent session with an explicit client id" do
      expect(MQTT::Migration.problems(client)).to be_empty
      expect(MQTT::Migration.check!(client)).to be(true)
    end

    it "rejects a persistent session without a client id" do
      subject = client(:client_id => nil)
      expect(MQTT::Migration.problems(subject)).to include(
        'client_id is required when clean_session is false'
      )
    end

    it "rejects an empty client id for MQTT 3.1.0" do
      subject = client(:client_id => '', :clean_session => true)
      expect(MQTT::Migration.problems(subject, '3.1.0')).to include(
        'client_id is required for MQTT 3.1.0'
      )
    end

    it "allows an empty client id only with a clean session in MQTT 3.1.1" do
      subject = client(:client_id => '', :clean_session => true)
      expect(MQTT::Migration.problems(subject, '3.1.1')).to be_empty

      subject.clean_session = false
      expect(MQTT::Migration.problems(subject, '3.1.1')).to include(
        'client_id is required when clean_session is false'
      )
    end

    it "rejects strict mode with an empty client id" do
      subject = client(:client_id => '', :clean_session => true, :strict_client_id => true)
      expect(MQTT::Migration.problems(subject)).to include(
        'client_id is required when strict_client_id is enabled'
      )
    end

    it "rejects a password without a username" do
      subject = client(:username => nil)
      expect(MQTT::Migration.problems(subject)).to include(
        'password is set without a username'
      )
    end

    it "rejects Will QoS without a Will topic" do
      subject = client(:will_qos => 1)
      expect(MQTT::Migration.problems(subject)).to include(
        'will_qos/will_retain is set without a will_topic'
      )
    end

    it "rejects Will Retain without a Will topic" do
      subject = client(:will_retain => true)
      expect(MQTT::Migration.problems(subject)).to include(
        'will_qos/will_retain is set without a will_topic'
      )
    end

    it "rejects an empty Will topic" do
      subject = client(:will_topic => '')
      expect(MQTT::Migration.problems(subject)).to include('will_topic is empty')
    end

    it "rejects a Will payload without a Will topic" do
      subject = client(:will_payload => 'bye')
      expect(MQTT::Migration.problems(subject)).to include(
        'will_payload is set without a will_topic'
      )
    end

    it "allows an empty Will payload alongside a Will topic" do
      subject = client(:will_topic => 'will/topic', :will_payload => '')
      expect(MQTT::Migration.problems(subject)).to be_empty
    end

    it "rejects a Will QoS of 3" do
      subject = client(:will_topic => 't', :will_qos => 3)
      expect(MQTT::Migration.problems(subject)).to include('will_qos must be 0, 1 or 2')
    end

    it "rejects a client id longer than 23 bytes for MQTT 3.1.0" do
      subject = client(:client_id => 'x' * 24)
      expect(MQTT::Migration.problems(subject, '3.1.0')).to include(
        'client_id is longer than 23 bytes, which MQTT 3.1.0 cannot carry'
      )
    end

    it "rejects a username that MQTT 3.1.0 cannot carry as UTF-8" do
      subject = client(:username => "user\xFF")
      expect(MQTT::Migration.problems(subject, '3.1.0')).to include(
        'username is not valid UTF-8, which MQTT 3.1.0 cannot carry'
      )
    end

    it "rejects requiring a resumed session for a clean session" do
      subject = client(:clean_session => true, :require_session_resumed => true)
      expect(MQTT::Migration.problems(subject)).to include(
        'cannot require a resumed session when clean_session is true'
      )
    end

    it "rejects a client id that the client generated itself" do
      subject = client(:client_id => nil, :clean_session => true, :version => '3.1.0')
      subject.instance_variable_set(:@client_id_generated, true)
      subject.instance_variable_set(:@client_id, 'rubyabcdefghijklmnop')

      expect(MQTT::Migration.problems(subject, '3.1.0')).to include(
        'client_id was generated locally instead of being supplied'
      )
    end

    it "rejects a keep-alive value that does not fit in 16 bits" do
      subject = client(:keep_alive => 65_536)
      expect(MQTT::Migration.problems(subject)).to include(
        'keep_alive must be between 0 and 65535'
      )
    end

    it "raises MigrationError from check!" do
      subject = client(:username => nil)
      expect {
        MQTT::Migration.check!(subject)
      }.to raise_error(MQTT::MigrationError, /password is set without a username/)
    end
  end

  describe "complete CONNECT handshake bytes" do
    it "encodes the MQTT 3.1.0 handshake exactly" do
      subject = client(:client_id => 'myclient', :clean_session => true,
                       :keep_alive => 15, :username => nil, :password => nil)
      expect(MQTT::Migration.handshake_bytes(subject, '3.1.0')).to eq(
        "\x10\x16\x00\x06MQIsdp\x03\x02\x00\x0f\x00\x08myclient"
      )
    end

    it "encodes the MQTT 3.1.1 handshake exactly" do
      subject = client(:client_id => 'myclient', :clean_session => true,
                       :keep_alive => 15, :username => nil, :password => nil)
      expect(MQTT::Migration.handshake_bytes(subject, '3.1.1')).to eq(
        "\x10\x14\x00\x04MQTT\x04\x02\x00\x0f\x00\x08myclient"
      )
    end

    it "encodes an empty client id for a clean MQTT 3.1.1 session" do
      subject = client(:client_id => '', :clean_session => true,
                       :keep_alive => 15, :username => nil, :password => nil)

      expect(MQTT::Migration.handshake_bytes(subject, '3.1.1')).to eq(
        "\x10\x0c\x00\x04MQTT\x04\x02\x00\x0f\x00\x00".b
      )
    end

    it "refuses to compare an empty client id against MQTT 3.1.0" do
      subject = client(:client_id => '', :clean_session => true,
                       :keep_alive => 15, :username => nil, :password => nil)

      expect {
        MQTT::Migration.compare_handshakes(subject, '3.1.0', '3.1.1')
      }.to raise_error(MQTT::MigrationError, /client_id is required for MQTT 3.1.0/)
    end

    it "encodes an empty password with the Password Flag set" do
      subject = client(:client_id => 'myclient', :clean_session => true,
                       :keep_alive => 15, :username => 'username', :password => '')
      expect(MQTT::Migration.handshake_bytes(subject, '3.1.1')).to eq(
        "\x10\x20" \
        "\x00\x04MQTT" \
        "\x04\xc2\x00\x0f" \
        "\x00\x08myclient" \
        "\x00\x08username" \
        "\x00\x00".b
      )
    end

    it "encodes a nil password with the Password Flag clear" do
      subject = client(:client_id => 'myclient', :clean_session => true,
                       :keep_alive => 15, :username => 'username', :password => nil)
      expect(MQTT::Migration.handshake_bytes(subject, '3.1.1')).to eq(
        "\x10\x1e" \
        "\x00\x04MQTT" \
        "\x04\x82\x00\x0f" \
        "\x00\x08myclient" \
        "\x00\x08username".b
      )
    end

    it "keeps client id, credentials and Will identical across versions" do
      subject = client(:client_id => 'stable-client',
                       :username => "user-\xC3\xA9".dup.force_encoding('UTF-8'),
                       :password => 'secret')
      subject.set_will('will/topic', 'bye', true, 2)

      result = MQTT::Migration.compare_handshakes(subject, '3.1.0', '3.1.1')

      expect(result[:changed]).to be_empty
      expect(result[:identical]).to be(false)
      expect(result[:from_identity]).to eq(result[:to_identity])
      expect(result[:to_identity][:will_payload]).to eq('bye')
      expect(result[:to_identity][:will_qos]).to eq(2)
      expect(result[:to_identity][:will_retain]).to be_truthy
    end

    it "preserves a binary Will payload byte-for-byte in MQTT 3.1.1" do
      subject = client(:client_id => 'stable-client', :username => 'user',
                       :password => 'secret')
      subject.set_will('will/topic', "bye\xFF\x00".b, false, 1)

      bytes = MQTT::Migration.handshake_bytes(subject, '3.1.1')
      expect(bytes).to include("\x00\x0Awill/topic\x00\x05bye\xFF\x00".b)

      parsed = MQTT::Migration.parse_connect(bytes)
      expect(parsed.will_payload.b).to eq("bye\xFF\x00".b)
    end

    it "refuses to compare a binary Will payload against MQTT 3.1.0" do
      subject = client(:client_id => 'stable-client', :username => 'user',
                       :password => 'secret')
      subject.set_will('will/topic', "bye\xFF\x00".b, false, 1)

      expect {
        MQTT::Migration.compare_handshakes(subject, '3.1.0', '3.1.1')
      }.to raise_error(MQTT::MigrationError, /will_payload is not valid UTF-8/)
    end

    it "keeps an empty Will payload as a present, zero-length field" do
      subject = client(:client_id => 'stable-client', :username => nil, :password => nil)
      subject.set_will('will/topic', '', false, 0)
      ball = MQTT::Migration.handshake_bytes(subject, '3.1.1')
      expect(ball).to include("\x00\x0awill/topic\x00\x00".b)
    end

    it "does not silently drop a Will that differs in content" do
      subject = client
      subject.set_will('will/topic', 'bye', false, 0)
      result = MQTT::Migration.compare_handshakes(subject, '3.1.0', '3.1.1')
      parsed = MQTT::Migration.parse_connect(result[:to_bytes])
      expect(parsed.will_topic).to eq('will/topic')
      expect(parsed.will_payload).to eq('bye')
    end

    it "raises when a configuration cannot be encoded at all" do
      subject = client(:client_id => '')
      expect {
        MQTT::Migration.handshake_bytes(subject, '3.1.0')
      }.to raise_error(MQTT::MigrationError, /client_id/)
    end
  end

  describe "checking flags against payload" do
    def parse(bytes)
      MQTT::Packet.parse(bytes)
    end

    it "rejects the reserved Connect flag bit" do
      expect {
        parse("\x10\x0c\x00\x04MQTT\x04\x03\x00\x0f\x00\x00")
      }.to raise_error(MQTT::ProtocolException, /Reserved flag/)
    end

    it "rejects a Password Flag without a User Name Flag" do
      expect {
        parse("\x10\x0c\x00\x04MQTT\x04\x40\x00\x0f\x00\x00")
      }.to raise_error(MQTT::ProtocolException, /Password flag set without User Name flag/)
    end

    it "rejects Will QoS/Retain when the Will Flag is not set" do
      expect {
        parse("\x10\x0c\x00\x04MQTT\x04\x0a\x00\x0f\x00\x00")
      }.to raise_error(MQTT::ProtocolException, /Will QoS and Will Retain must be zero/)
    end

    it "rejects a Will QoS value of 3" do
      expect {
        parse("\x10\x0c\x00\x04MQTT\x04\x1c\x00\x0f\x00\x00")
      }.to raise_error(MQTT::ProtocolException, /Invalid Will QoS value of 3/)
    end

    it "rejects an empty client id with clean session false" do
      expect {
        parse("\x10\x0c\x00\x04MQTT\x04\x00\x00\x0f\x00\x00")
      }.to raise_error(MQTT::ProtocolException, /Empty Client Identifier requires Clean Session/)
    end

    it "allows an empty client id with clean session true" do
      packet = parse("\x10\x0c\x00\x04MQTT\x04\x02\x00\x0f\x00\x00")
      expect(packet.client_id).to eq('')
      expect(packet.clean_session).to be_truthy
    end

    it "rejects extra bytes after the payload" do
      expect {
        parse("\x10\x0d\x00\x04MQTT\x04\x02\x00\x0f\x00\x00\x00")
      }.to raise_error(MQTT::ProtocolException, /Extra bytes at end of Connect packet/)
    end

    it "rejects a truncated username field" do
      expect {
        parse("\x10\x10\x00\x04MQTT\x04\x82\x00\x0f\x00\x00\x00\x05ab")
      }.to raise_error(MQTT::ProtocolException, /Truncated User Name field/)
    end

    it "rejects a truncated Will Topic field" do
      expect {
        parse("\x10\x10\x00\x04MQTT\x04\x06\x00\x0f\x00\x00\x00\x05ab")
      }.to raise_error(MQTT::ProtocolException, /Truncated Will Topic field/)
    end

    it "rejects a missing username field when the flag is set" do
      expect {
        parse("\x10\x0c\x00\x04MQTT\x04\x82\x00\x0f\x00\x00")
      }.to raise_error(MQTT::ProtocolException, /Missing User Name field/)
    end

    it "rejects a legacy 3.1 packet whose User Name flag has no field" do
      packet = MQTT::Migration.parse_connect(
        "\x10\x16\x00\x06MQIsdp\x03\x80\x00\x0a\x00\x08myclient"
      )
      expect {
        MQTT::Migration.validate_connect_packet!(packet)
      }.to raise_error(MQTT::MigrationError, /User Name flag set but User Name is missing/)
    end

    it "accepts a legacy 3.1 packet whose flags and fields agree" do
      packet = MQTT::Migration.parse_connect(
        "\x10\x16\x00\x06MQIsdp\x03\x00\x00\x0a\x00\x08myclient"
      )
      expect(MQTT::Migration.validate_connect_packet!(packet)).to be(true)
    end
  end

  describe "CONNACK responses that do not prove a resumed session" do
    it "treats return code 0x00 with Session Present 0 as not resumed" do
      connack = MQTT::Packet::Connack.new(:return_code => 0x00, :session_present => false)
      expect(MQTT::Migration.session_problem(connack, false)).to match(/did not resume/)
      expect(MQTT::Migration.successful_session_response?(connack, false)).to be(false)
    end

    it "treats Session Present 1 as resumed for a persistent session" do
      connack = MQTT::Packet::Connack.new(:return_code => 0x00, :session_present => true)
      expect(MQTT::Migration.session_problem(connack, false)).to be_nil
    end

    it "treats each non-zero return code as a refusal" do
      (0x01..0x05).each do |code|
        connack = MQTT::Packet::Connack.new(:return_code => code)
        expect(MQTT::Migration.session_problem(connack, false)).to match(/refused/)
      end
    end

    it "treats an unknown return code as a refusal" do
      connack = MQTT::Packet::Connack.new(:return_code => 0xAA)
      expect(MQTT::Migration.session_problem(connack, false)).to match(/error code 170/)
    end

    it "treats a non-CONNACK packet as a failure" do
      expect(MQTT::Migration.session_problem(MQTT::Packet::Pingresp.new, false)).to match(/not a CONNACK/)
    end

    it "treats Session Present 1 with a clean session as a protocol failure" do
      connack = MQTT::Packet::Connack.new(:return_code => 0x00, :session_present => true)
      expect(MQTT::Migration.session_problem(connack, true)).to match(/clean session/)
    end
  end

  describe "single in-memory connection attempt" do
    it "accepts a resumed session over the in-memory transport" do
      subject = client(:clean_session => false, :require_session_resumed => true, :ack_timeout => 2)
      result = MQTT::Migration.connect_once(
        subject, '3.1.1', MQTT::Migration.connack(0x00, true)
      )

      expect(result.connected?).to be(true)
      expect(result.session_resumed?).to be(true)
      expect(result.connect_count).to eq(1)
      expect(result.client_id).to eq('stable-client')
      expect(result.bytes_sent).to eq(MQTT::Migration.handshake_bytes(subject, '3.1.1'))
      expect(subject.client_id).to eq('stable-client')
      expect(subject.version).to eq('3.1.1')
    end

    it "fails without retry when the session was not resumed" do
      subject = client(:clean_session => false, :require_session_resumed => true, :ack_timeout => 2)
      result = MQTT::Migration.connect_once(
        subject, '3.1.1', MQTT::Migration.connack(0x00, false)
      )

      expect(result.connected?).to be(false)
      expect(result.error).to be_a(MQTT::SessionNotResumedException)
      expect(result.connect_count).to eq(1)
      expect(subject.connected?).to be(false)
      expect(subject.version).to eq('3.1.1')
      expect(subject.client_id).to eq('stable-client')
    end

    it "fails without retry for each refusal return code" do
      (0x01..0x05).each do |code|
        subject = client(:ack_timeout => 2)
        result = MQTT::Migration.connect_once(
          subject, '3.1.1', MQTT::Migration.connack(code, false)
        )

        expect(result.connected?).to be(false)
        expect(result.error).to be_a(MQTT::ProtocolException)
        expect(result.connect_count).to eq(1)
        expect(subject.version).to eq('3.1.1')
        expect(subject.client_id).to eq('stable-client')
      end
    end

    it "fails without retry when the response is not a CONNACK" do
      subject = client(:ack_timeout => 2)
      result = MQTT::Migration.connect_once(subject, '3.1.1', "\xD0\x00")

      expect(result.connected?).to be(false)
      expect(result.error).to be_a(MQTT::ProtocolException)
      expect(result.connect_count).to eq(1)
    end

    it "closes the transport and reports the failed state after a refusal" do
      subject = client(:ack_timeout => 2)
      MQTT::Migration.connect_once(subject, '3.1.1', MQTT::Migration.connack(0x05, false))

      expect(subject.connected?).to be(false)
      expect(subject.transport).to be_nil
    end

    it "does not generate a client id for MQTT 3.1.0 in strict mode" do
      subject = client(:client_id => nil, :clean_session => true, :ack_timeout => 2)
      expect {
        MQTT::Migration.connect_once(subject, '3.1.0', MQTT::Migration.connack(0x00, false))
      }.to raise_error(MQTT::MigrationError, /client_id/)
      expect(subject.client_id).to be_nil
    end

    it "preserves an empty client id and clean session in the sent bytes" do
      subject = client(:client_id => '', :clean_session => true,
                       :keep_alive => 15, :username => nil, :password => nil,
                       :ack_timeout => 2)
      result = MQTT::Migration.connect_once(
        subject, '3.1.1', MQTT::Migration.connack(0x00, false)
      )

      expect(result.connected?).to be(true)
      expect(result.bytes_sent).to eq(
        "\x10\x0c\x00\x04MQTT\x04\x02\x00\x0f\x00\x00".b
      )
      expect(subject.client_id).to eq('')
    end
  end


  describe "end-to-end in-memory handshake comparison" do
    it "keeps the same client identifier in both versions" do
      subject = client(:client_id => 'stable-client', :username => nil, :password => nil)
      MQTT::Migration.check!(subject)
      cmp = MQTT::Migration.compare_handshakes(subject, '3.1.0', '3.1.1')
      expect(cmp[:changed]).to be_empty
      expect(cmp[:from_packet].client_id).to eq('stable-client')
      expect(cmp[:to_packet].client_id).to eq('stable-client')
    end

    it "keeps an empty password present in both versions" do
      subject = client(:client_id => 'stable-client', :username => 'user', :password => '')
      MQTT::Migration.check!(subject)
      cmp = MQTT::Migration.compare_handshakes(subject, '3.1.0', '3.1.1')
      expect(cmp[:changed]).to be_empty
      expect(cmp[:from_packet].password).to eq('')
      expect(cmp[:to_packet].password).to eq('')
    end

    it "keeps a missing password absent in both versions" do
      subject = client(:client_id => 'stable-client', :username => 'user', :password => nil)
      cmp = MQTT::Migration.compare_handshakes(subject, '3.1.0', '3.1.1')
      expect(cmp[:from_packet].password).to be_nil
      expect(cmp[:to_packet].password).to be_nil
    end

    it "keeps the Will in both versions" do
      subject = client(:client_id => 'stable-client', :username => nil, :password => nil)
      subject.set_will('will/topic', 'bye', true, 1)
      cmp = MQTT::Migration.compare_handshakes(subject, '3.1.0', '3.1.1')
      expect(cmp[:changed]).to be_empty
      [:will_topic, :will_payload, :will_qos, :will_retain].each do |name|
        expect(cmp[:from_identity][name]).to eq(cmp[:to_identity][name])
      end
    end

    it "rejects a configuration that would need a generated client id" do
      subject = client(:client_id => nil, :clean_session => true, :strict_client_id => true)
      expect {
        MQTT::Migration.compare_handshakes(subject, '3.1.0', '3.1.1')
      }.to raise_error(MQTT::MigrationError, /client_id/)
    end

    it "rejects an illegal flag combination before sending anything" do
      subject = client(:username => nil)
      expect {
        MQTT::Migration.handshake_bytes(subject, '3.1.1')
      }.to raise_error(MQTT::MigrationError, /password is set without a username/)
    end
  end


  describe "interactive comparison over the in-memory transport" do
    it "sends each version once and reports both handshakes" do
      subject = client(:clean_session => false, :require_session_resumed => true,
                       :ack_timeout => 2)
      result = MQTT::Migration.compare_connections(
        subject, '3.1.0', '3.1.1', MQTT::Migration.connack(0x00, true)
      )

      expect(result[:from_result].connect_count).to eq(1)
      expect(result[:to_result].connect_count).to eq(1)
      expect(result[:changed]).to be_empty
      expect(result[:from_bytes]).to eq(MQTT::Migration.handshake_bytes(subject, '3.1.0'))
      expect(result[:to_bytes]).to eq(MQTT::Migration.handshake_bytes(subject, '3.1.1'))
      expect(subject.client_id).to eq('stable-client')
    end

    it "reports a refusal from both attempts without retrying" do
      subject = client(:require_session_resumed => true, :ack_timeout => 2)
      result = MQTT::Migration.compare_connections(
        subject, '3.1.0', '3.1.1', MQTT::Migration.connack(0x05, false)
      )

      expect(result[:from_result].failure?).to be(true)
      expect(result[:to_result].failure?).to be(true)
      expect(result[:from_result].connect_count).to eq(1)
      expect(result[:to_result].connect_count).to eq(1)
      expect(subject.client_id).to eq('stable-client')
    end
  end

  describe "strict connect entry point" do
    it "refuses to connect with an implicit client id" do
      subject = client(:client_id => nil, :clean_session => true, :ack_timeout => 2)
      expect {
        MQTT::Migration.connect!(subject, '3.1.0')
      }.to raise_error(MQTT::MigrationError, /client_id/)
      expect(subject.client_id).to be_nil
    end

    it "leaves version and identity unchanged when the attempt is refused" do
      subject = client(:version => '3.1.0', :client_id => nil,
                       :clean_session => true, :ack_timeout => 2)
      expect {
        MQTT::Migration.connect!(subject, '3.1.1')
      }.to raise_error(MQTT::MigrationError, /client_id/)
      expect(subject.version).to eq('3.1.0')
      expect(subject.client_id).to be_nil
    end
  end
end
