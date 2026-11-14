# encoding: BINARY
# Encoding is set to binary, so that the binary packets aren't validated as UTF-8

$:.unshift(File.dirname(__FILE__))

require 'spec_helper'
require 'mqtt'
require 'socket'
require 'stringio'
require 'timeout'

# Wraps one end of a socket pair and keeps an in-memory record of every
# byte that arrives and leaves through the proxy. This gives each test a
# complete, comparable transcript for both sides of the connection.
module ProxySpecSupport
  class RecordingSocket
    attr_reader :received, :sent

    def initialize(io)
      @io = io
      @received = ''.dup.force_encoding(Encoding::BINARY)
      @sent = ''.dup.force_encoding(Encoding::BINARY)
    end

    def to_io
      @io
    end

    def getbyte
      byte = @io.getbyte
      @received << byte unless byte.nil?
      byte
    end

    def read(length)
      data = @io.read(length)
      @received << data unless data.nil?
      data
    end

    def write(data)
      data = data.to_s
      @sent << data
      @io.write(data)
      data.bytesize
    end

    def close
      @io.close unless @io.closed?
    end

    def closed?
      @io.closed?
    end
  end
end

describe MQTT::Proxy do
  def packet_bytes(*packets)
    packets.map(&:to_s).join
  end

  def build_proxy(client_filter = nil, server_filter = nil)
    proxy = MQTT::Proxy.allocate
    proxy.instance_variable_set(:@client_filter, client_filter)
    proxy.instance_variable_set(:@server_filter, server_filter)
    proxy.instance_variable_set(:@select_timeout, 5)
    proxy.instance_variable_set(:@logger, Logger.new(IO::NULL))
    proxy
  end

  def start_connection(client_filter = nil, server_filter = nil)
    @client_app, client_proxy = UNIXSocket.pair
    @server_app, server_proxy = UNIXSocket.pair
    @client_side = ProxySpecSupport::RecordingSocket.new(client_proxy)
    @server_side = ProxySpecSupport::RecordingSocket.new(server_proxy)
    @errors = []
    @proxy = build_proxy(client_filter, server_filter)
    @thread = Thread.new do
      if Thread.current.respond_to?(:report_on_exception=)
        Thread.current.report_on_exception = false
      end
      begin
        @proxy.send(:process_packets, @client_side, @server_side)
      rescue Exception => exp
        @errors << exp
      end
    end
  end

  def stop_connection
    if @thread
      @thread.kill if @thread.alive?
      @thread.join(1)
    end
    [@client_side, @server_side].each do |socket|
      begin
        socket.close
      rescue IOError
        nil
      end
    end
    [@client_app, @server_app].each do |socket|
      begin
        socket.close unless socket.closed?
      rescue IOError
        nil
      end
    end
  end

  def wait_for_error
    Timeout.timeout(5) do
      sleep 0.01 until !@errors.empty? || !@thread.alive?
    end
    @errors.first
  end

  def receive_packet(socket, timeout = 5)
    selected = IO.select([socket], nil, nil, timeout)
    raise "Timed out waiting for a packet after #{timeout} seconds" if selected.nil?
    MQTT::Packet.read(socket)
  end

  def expect_no_packet(socket, timeout = 0.2)
    selected = IO.select([socket], nil, nil, timeout)
    expect(selected).to be_nil
  end

  after(:each) do
    stop_connection if defined?(@thread) && !@thread.nil?
  end

  describe MQTT::Proxy::Session do
    it "rejects a rewritten QoS" do
      session = MQTT::Proxy::Session.new
      filter = lambda do |packet|
        packet.qos = 2
        packet
      end

      expect {
        session.handle(
          MQTT::Proxy::Session::CLIENT_TO_SERVER,
          MQTT::Packet::Publish.new(:id => 1, :qos => 1, :topic => 'a', :payload => 'x'),
          filter
        )
      }.to raise_error(MQTT::Proxy::InvalidRewrite, /changed QoS/)
    end

    it "rejects a filter that changes a packet into another type" do
      session = MQTT::Proxy::Session.new
      filter = lambda do |_packet|
        MQTT::Packet::Puback.new(:id => 1)
      end

      expect {
        session.handle(
          MQTT::Proxy::Session::CLIENT_TO_SERVER,
          MQTT::Packet::Publish.new(:id => 1, :qos => 1, :topic => 'a', :payload => 'x'),
          filter
        )
      }.to raise_error(MQTT::Proxy::InvalidRewrite, /another packet type/)
    end

    it "rejects a filter that tries to change an acknowledgement identifier" do
      session = MQTT::Proxy::Session.new
      session.handle(
        MQTT::Proxy::Session::CLIENT_TO_SERVER,
        MQTT::Packet::Publish.new(:id => 1, :qos => 1, :topic => 'a', :payload => 'x'),
        lambda { |packet| packet.id = 10; packet }
      )

      filter = lambda do |packet|
        packet.id = 11
        packet
      end

      expect {
        session.handle(
          MQTT::Proxy::Session::SERVER_TO_CLIENT,
          MQTT::Packet::Puback.new(:id => 10),
          filter
        )
      }.to raise_error(MQTT::Proxy::InvalidRewrite, /must not change the packet identifier/)
    end

    it "returns nil for an acknowledgement that has no matching flow" do
      session = MQTT::Proxy::Session.new

      expect(
        session.handle(
          MQTT::Proxy::Session::SERVER_TO_CLIENT,
          MQTT::Packet::Puback.new(:id => 42)
        )
      ).to be_nil
    end

    it "does not share mappings between sessions" do
      filter = lambda do |packet|
        packet.id = 500
        packet
      end

      first = MQTT::Proxy::Session.new
      first.handle(
        MQTT::Proxy::Session::CLIENT_TO_SERVER,
        MQTT::Packet::Publish.new(:id => 1, :qos => 1, :topic => 'a', :payload => 'x'),
        filter
      )

      second = MQTT::Proxy::Session.new
      expect(
        second.handle(
          MQTT::Proxy::Session::SERVER_TO_CLIENT,
          MQTT::Packet::Puback.new(:id => 500)
        )
      ).to be_nil
    end
  end

  describe "rewriting a QoS 1 publish from the client" do
    it "translates PUBACK back to the client's identifier" do
      calls = []
      client_filter = lambda do |packet|
        if packet.is_a?(MQTT::Packet::Publish)
          calls << packet.id
          packet.topic = 'public/sensors'
          packet.id = 101
        end
        packet
      end

      start_connection(client_filter)
      original = MQTT::Packet::Publish.new(
        :id => 7, :qos => 1, :topic => 'private/sensors', :payload => 'hello'
      )
      rewritten = MQTT::Packet::Publish.new(
        :id => 101, :qos => 1, :topic => 'public/sensors', :payload => 'hello'
      )
      puback = MQTT::Packet::Puback.new(:id => 101)
      translated_puback = MQTT::Packet::Puback.new(:id => 7)

      @client_app.write(original)
      server_publish = receive_packet(@server_app)
      expect(server_publish.id).to eq(101)
      expect(server_publish.topic).to eq('public/sensors')
      expect(server_publish.qos).to eq(1)

      @server_app.write(puback)
      client_ack = receive_packet(@client_app)
      expect(client_ack.class).to eq(MQTT::Packet::Puback)
      expect(client_ack.id).to eq(7)
      expect(calls).to eq([7])

      expect(@client_side.received).to eq(packet_bytes(original))
      expect(@server_side.sent).to eq(packet_bytes(rewritten))
      expect(@server_side.received).to eq(packet_bytes(puback))
      expect(@client_side.sent).to eq(packet_bytes(translated_puback))
    end

    it "does not forward a PUBACK that uses the client's original identifier" do
      client_filter = lambda do |packet|
        if packet.is_a?(MQTT::Packet::Publish)
          packet.id = 101
        end
        packet
      end

      start_connection(client_filter)
      original = MQTT::Packet::Publish.new(
        :id => 7, :qos => 1, :topic => 'private/sensors', :payload => 'hello'
      )
      rewritten = MQTT::Packet::Publish.new(
        :id => 101, :qos => 1, :topic => 'private/sensors', :payload => 'hello'
      )

      @client_app.write(original)
      expect(receive_packet(@server_app).id).to eq(101)

      # The broker only knows the rewritten identifier, so an acknowledgement
      # carrying 7 cannot belong to this flow and must not be passed to the
      # client as a success.
      @server_app.write(MQTT::Packet::Puback.new(:id => 7))
      expect_no_packet(@client_app)
      expect(@client_side.sent).to be_empty

      @server_app.write(MQTT::Packet::Puback.new(:id => 101))
      expect(receive_packet(@client_app).id).to eq(7)

      expect(@client_side.received).to eq(packet_bytes(original))
      expect(@server_side.sent).to eq(packet_bytes(rewritten))
    end
  end

  describe "rewriting a QoS 2 publish from the client" do
    it "keeps PUBREC, PUBREL and PUBCOMP correlated on both sides" do
      client_filter = lambda do |packet|
        if packet.is_a?(MQTT::Packet::Publish)
          packet.topic = 'public/sensors'
          packet.id = 202
        end
        packet
      end

      start_connection(client_filter)
      original = MQTT::Packet::Publish.new(
        :id => 9, :qos => 2, :topic => 'private/sensors', :payload => 'hello'
      )
      rewritten = MQTT::Packet::Publish.new(
        :id => 202, :qos => 2, :topic => 'public/sensors', :payload => 'hello'
      )
      server_pubrec = MQTT::Packet::Pubrec.new(:id => 202)
      client_pubrec = MQTT::Packet::Pubrec.new(:id => 9)
      client_pubrel = MQTT::Packet::Pubrel.new(:id => 9)
      server_pubrel = MQTT::Packet::Pubrel.new(:id => 202)
      server_pubcomp = MQTT::Packet::Pubcomp.new(:id => 202)
      client_pubcomp = MQTT::Packet::Pubcomp.new(:id => 9)

      @client_app.write(original)
      expect(receive_packet(@server_app).id).to eq(202)

      @server_app.write(server_pubrec)
      expect(receive_packet(@client_app).id).to eq(9)

      @client_app.write(client_pubrel)
      expect(receive_packet(@server_app).id).to eq(202)

      @server_app.write(server_pubcomp)
      expect(receive_packet(@client_app).id).to eq(9)

      expect(@client_side.received).to eq(
        packet_bytes(original, client_pubrel)
      )
      expect(@server_side.sent).to eq(
        packet_bytes(rewritten, server_pubrel)
      )
      expect(@server_side.received).to eq(
        packet_bytes(server_pubrec, server_pubcomp)
      )
      expect(@client_side.sent).to eq(
        packet_bytes(client_pubrec, client_pubcomp)
      )
    end

    it "does not forward an uncorrelated PUBREL or PUBCOMP" do
      client_filter = lambda do |packet|
        if packet.is_a?(MQTT::Packet::Publish)
          packet.id = 202
        end
        packet
      end

      start_connection(client_filter)
      original = MQTT::Packet::Publish.new(
        :id => 9, :qos => 2, :topic => 'private/sensors', :payload => 'hello'
      )
      rewritten = MQTT::Packet::Publish.new(
        :id => 202, :qos => 2, :topic => 'private/sensors', :payload => 'hello'
      )

      @client_app.write(original)
      expect(receive_packet(@server_app).id).to eq(202)

      @server_app.write(MQTT::Packet::Pubrel.new(:id => 202))
      expect_no_packet(@client_app)

      @server_app.write(MQTT::Packet::Pubcomp.new(:id => 202))
      expect_no_packet(@client_app)
      expect(@client_side.sent).to be_empty

      expect(@client_side.received).to eq(packet_bytes(original))
      expect(@server_side.sent).to eq(packet_bytes(rewritten))
    end
  end

  describe "retransmitted packets" do
    it "reuses the first rewritten identifier instead of rewriting again" do
      rewritten_ids = []
      client_filter = lambda do |packet|
        if packet.is_a?(MQTT::Packet::Publish)
          # Deliberately allocates a new identifier on every invocation, so a
          # second call would be visible in the recorded byte stream.
          rewritten_ids << 900 + rewritten_ids.length
          packet.topic = 'public/sensors'
          packet.id = rewritten_ids.last
        end
        packet
      end

      start_connection(client_filter)
      original = MQTT::Packet::Publish.new(
        :id => 7, :qos => 1, :topic => 'private/sensors', :payload => 'hello'
      )
      duplicate = MQTT::Packet::Publish.new(
        :id => 7, :qos => 1, :topic => 'private/sensors', :payload => 'hello',
        :duplicate => true
      )
      rewritten = MQTT::Packet::Publish.new(
        :id => 900, :qos => 1, :topic => 'public/sensors', :payload => 'hello'
      )
      rewritten_duplicate = MQTT::Packet::Publish.new(
        :id => 900, :qos => 1, :topic => 'public/sensors', :payload => 'hello',
        :duplicate => true
      )

      @client_app.write(original)
      first = receive_packet(@server_app)
      expect(first.id).to eq(900)

      @client_app.write(duplicate)
      second = receive_packet(@server_app)
      expect(second.id).to eq(900)
      expect(second.duplicate).to be_truthy
      expect(rewritten_ids).to eq([900])

      @server_app.write(MQTT::Packet::Puback.new(:id => 900))
      expect(receive_packet(@client_app).id).to eq(7)

      expect(@client_side.received).to eq(packet_bytes(original, duplicate))
      expect(@server_side.sent).to eq(
        packet_bytes(rewritten, rewritten_duplicate)
      )
    end

    it "reuses the first rewrite for a server-to-client retransmission" do
      rewritten_ids = []
      server_filter = lambda do |packet|
        if packet.is_a?(MQTT::Packet::Publish)
          rewritten_ids << 300 + rewritten_ids.length
          packet.topic = 'public/from-server'
          packet.id = rewritten_ids.last
        end
        packet
      end

      start_connection(nil, server_filter)
      original = MQTT::Packet::Publish.new(
        :id => 21, :qos => 1, :topic => 'private/from-server', :payload => 'hello'
      )
      duplicate = MQTT::Packet::Publish.new(
        :id => 21, :qos => 1, :topic => 'private/from-server', :payload => 'hello',
        :duplicate => true
      )
      rewritten = MQTT::Packet::Publish.new(
        :id => 300, :qos => 1, :topic => 'public/from-server', :payload => 'hello'
      )
      rewritten_duplicate = MQTT::Packet::Publish.new(
        :id => 300, :qos => 1, :topic => 'public/from-server', :payload => 'hello',
        :duplicate => true
      )

      @server_app.write(original)
      expect(receive_packet(@client_app).id).to eq(300)

      @server_app.write(duplicate)
      retransmitted = receive_packet(@client_app)
      expect(retransmitted.id).to eq(300)
      expect(retransmitted.duplicate).to be_truthy
      expect(rewritten_ids).to eq([300])

      @client_app.write(MQTT::Packet::Puback.new(:id => 300))
      expect(receive_packet(@server_app).id).to eq(21)

      expect(@server_side.received).to eq(
        packet_bytes(
          original,
          duplicate
        )
      )
      expect(@client_side.received).to eq(
        packet_bytes(MQTT::Packet::Puback.new(:id => 300))
      )
      expect(@client_side.sent).to eq(
        packet_bytes(rewritten, rewritten_duplicate)
      )
    end

    it "reuses the first rewrite during a QoS 2 handshake" do
      rewritten_ids = []
      client_filter = lambda do |packet|
        if packet.is_a?(MQTT::Packet::Publish)
          rewritten_ids << 950 + rewritten_ids.length
          packet.id = rewritten_ids.last
        end
        packet
      end

      start_connection(client_filter)
      original = MQTT::Packet::Publish.new(
        :id => 11, :qos => 2, :topic => 'a', :payload => 'x'
      )
      duplicate = MQTT::Packet::Publish.new(
        :id => 11, :qos => 2, :topic => 'a', :payload => 'x',
        :duplicate => true
      )
      rewritten = MQTT::Packet::Publish.new(:id => 950, :qos => 2, :topic => 'a', :payload => 'x')
      rewritten_duplicate = MQTT::Packet::Publish.new(
        :id => 950, :qos => 2, :topic => 'a', :payload => 'x', :duplicate => true
      )
      client_pubrec = MQTT::Packet::Pubrec.new(:id => 11)
      client_pubrel = MQTT::Packet::Pubrel.new(:id => 11)
      server_pubrel = MQTT::Packet::Pubrel.new(:id => 950)
      server_pubcomp = MQTT::Packet::Pubcomp.new(:id => 950)
      client_pubcomp = MQTT::Packet::Pubcomp.new(:id => 11)

      @client_app.write(original)
      expect(receive_packet(@server_app).id).to eq(950)

      @client_app.write(duplicate)
      retransmitted = receive_packet(@server_app)
      expect(retransmitted.id).to eq(950)
      expect(retransmitted.duplicate).to be_truthy

      @server_app.write(MQTT::Packet::Pubrec.new(:id => 950))
      expect(receive_packet(@client_app).id).to eq(11)

      @client_app.write(client_pubrel)
      expect(receive_packet(@server_app).id).to eq(950)

      @server_app.write(server_pubcomp)
      expect(receive_packet(@client_app).id).to eq(11)

      expect(rewritten_ids).to eq([950])
      expect(@client_side.received).to eq(
        packet_bytes(original, duplicate, client_pubrel)
      )
      expect(@server_side.sent).to eq(
        packet_bytes(rewritten, rewritten_duplicate, server_pubrel)
      )
      expect(@server_side.received).to eq(
        packet_bytes(MQTT::Packet::Pubrec.new(:id => 950), server_pubcomp)
      )
      expect(@client_side.sent).to eq(
        packet_bytes(client_pubrec, client_pubcomp)
      )
    end

    it "translates a retransmitted PUBREL and PUBCOMP after completion" do
      client_filter = lambda do |packet|
        if packet.is_a?(MQTT::Packet::Publish)
          packet.topic = 'public'
          packet.id = 950
        end
        packet
      end

      start_connection(client_filter)
      publish = MQTT::Packet::Publish.new(
        :id => 11, :qos => 2, :topic => 'private', :payload => 'hello'
      )
      rewritten = MQTT::Packet::Publish.new(
        :id => 950, :qos => 2, :topic => 'public', :payload => 'hello'
      )

      @client_app.write(publish)
      expect(receive_packet(@server_app).id).to eq(950)

      @server_app.write(MQTT::Packet::Pubrec.new(:id => 950))
      expect(receive_packet(@client_app).id).to eq(11)

      @client_app.write(MQTT::Packet::Pubrel.new(:id => 11))
      expect(receive_packet(@server_app).id).to eq(950)

      @server_app.write(MQTT::Packet::Pubcomp.new(:id => 950))
      expect(receive_packet(@client_app).id).to eq(11)

      # The sender may retransmit PUBREL after completion; it must still be
      # translated with the retired mapping rather than opening a new flow.
      @client_app.write(MQTT::Packet::Pubrel.new(:id => 11))
      expect(receive_packet(@server_app).id).to eq(950)

      # Likewise the receiver may retransmit PUBCOMP.
      @server_app.write(MQTT::Packet::Pubcomp.new(:id => 950))
      expect(receive_packet(@client_app).id).to eq(11)

      expect(@client_side.received).to eq(
        packet_bytes(
          publish,
          MQTT::Packet::Pubrel.new(:id => 11),
          MQTT::Packet::Pubrel.new(:id => 11)
        )
      )
      expect(@server_side.sent).to eq(
        packet_bytes(
          rewritten,
          MQTT::Packet::Pubrel.new(:id => 950),
          MQTT::Packet::Pubrel.new(:id => 950)
        )
      )
      expect(@server_side.received).to eq(
        packet_bytes(
          MQTT::Packet::Pubrec.new(:id => 950),
          MQTT::Packet::Pubcomp.new(:id => 950),
          MQTT::Packet::Pubcomp.new(:id => 950)
        )
      )
      expect(@client_side.sent).to eq(
        packet_bytes(
          MQTT::Packet::Pubrec.new(:id => 11),
          MQTT::Packet::Pubcomp.new(:id => 11),
          MQTT::Packet::Pubcomp.new(:id => 11)
        )
      )
    end

    it "rejects a retransmission that does not match the original publish" do
      client_filter = lambda do |packet|
        if packet.is_a?(MQTT::Packet::Publish)
          packet.id = 900
        end
        packet
      end

      start_connection(client_filter)
      original = MQTT::Packet::Publish.new(
        :id => 7, :qos => 1, :topic => 'private/sensors', :payload => 'hello'
      )
      changed = MQTT::Packet::Publish.new(
        :id => 7, :qos => 1, :topic => 'private/sensors', :payload => 'different',
        :duplicate => true
      )

      @client_app.write(original)
      expect(receive_packet(@server_app).id).to eq(900)

      @client_app.write(changed)
      expect(wait_for_error).to be_a(MQTT::Proxy::InvalidRewrite)
      expect(@server_side.sent).to eq(packet_bytes(MQTT::Packet::Publish.new(
        :id => 900, :qos => 1, :topic => 'private/sensors', :payload => 'hello'
      )))
    end

    it "rejects a rewritten retransmission with no known flow" do
      client_filter = lambda do |packet|
        if packet.is_a?(MQTT::Packet::Publish)
          packet.id = 900
        end
        packet
      end

      start_connection(client_filter)
      duplicate = MQTT::Packet::Publish.new(
        :id => 7, :qos => 1, :topic => 'private/sensors', :payload => 'hello',
        :duplicate => true
      )

      @client_app.write(duplicate)
      expect(wait_for_error).to be_a(MQTT::Proxy::InvalidRewrite)
      expect(@server_side.sent).to be_empty
    end
  end

  describe "simultaneous use of the same identifier in both directions" do
    it "keeps two unrewritten QoS 1 conversations with the same id separate" do
      start_connection

      client_publish = MQTT::Packet::Publish.new(
        :id => 7, :qos => 1, :topic => 'client', :payload => 'from client'
      )
      server_publish = MQTT::Packet::Publish.new(
        :id => 7, :qos => 1, :topic => 'server', :payload => 'from server'
      )

      @client_app.write(client_publish)
      expect(receive_packet(@server_app).id).to eq(7)

      @server_app.write(server_publish)
      expect(receive_packet(@client_app).id).to eq(7)

      # A client-direction PUBACK can only acknowledge the server's publish,
      # because that is the only flow travelling server -> client with id 7.
      @client_app.write(MQTT::Packet::Puback.new(:id => 7))
      expect(receive_packet(@server_app).id).to eq(7)

      # And a server-direction PUBACK can only acknowledge the client's.
      @server_app.write(MQTT::Packet::Puback.new(:id => 7))
      expect(receive_packet(@client_app).id).to eq(7)

      expect(@client_side.received).to eq(
        packet_bytes(
          client_publish,
          MQTT::Packet::Puback.new(:id => 7)
        )
      )
      expect(@server_side.received).to eq(
        packet_bytes(
          server_publish,
          MQTT::Packet::Puback.new(:id => 7)
        )
      )
    end

    it "keeps two QoS 2 conversations separate" do
      client_filter = lambda do |packet|
        if packet.is_a?(MQTT::Packet::Publish)
          packet.topic = 'client/public'
          packet.id = 407
        end
        packet
      end
      server_filter = lambda do |packet|
        if packet.is_a?(MQTT::Packet::Publish)
          packet.topic = 'server/public'
          packet.id = 507
        end
        packet
      end

      start_connection(client_filter, server_filter)
      client_publish = MQTT::Packet::Publish.new(
        :id => 7, :qos => 2, :topic => 'client/private', :payload => 'from client'
      )
      server_publish = MQTT::Packet::Publish.new(
        :id => 7, :qos => 2, :topic => 'server/private', :payload => 'from server'
      )

      @client_app.write(client_publish)
      expect(receive_packet(@server_app).id).to eq(407)

      @server_app.write(server_publish)
      expect(receive_packet(@client_app).id).to eq(507)

      # Broker acknowledges the client's publish.
      @server_app.write(MQTT::Packet::Pubrec.new(:id => 407))
      expect(receive_packet(@client_app).id).to eq(7)

      # Client acknowledges the broker's publish.
      @client_app.write(MQTT::Packet::Pubrec.new(:id => 507))
      expect(receive_packet(@server_app).id).to eq(7)

      # Both publishers now release their own identifier.
      @client_app.write(MQTT::Packet::Pubrel.new(:id => 7))
      client_pubrel = receive_packet(@server_app)
      expect(client_pubrel.id).to eq(407)

      @server_app.write(MQTT::Packet::Pubrel.new(:id => 7))
      server_pubrel = receive_packet(@client_app)
      expect(server_pubrel.id).to eq(507)

      # And both receivers complete their own handshake.
      @server_app.write(MQTT::Packet::Pubcomp.new(:id => 407))
      expect(receive_packet(@client_app).id).to eq(7)

      @client_app.write(MQTT::Packet::Pubcomp.new(:id => 507))
      expect(receive_packet(@server_app).id).to eq(7)

      expect(@client_side.received).to eq(
        packet_bytes(
          client_publish,
          MQTT::Packet::Pubrec.new(:id => 507),
          MQTT::Packet::Pubrel.new(:id => 7),
          MQTT::Packet::Pubcomp.new(:id => 507)
        )
      )
      expect(@server_side.received).to eq(
        packet_bytes(
          server_publish,
          MQTT::Packet::Pubrec.new(:id => 407),
          MQTT::Packet::Pubrel.new(:id => 7),
          MQTT::Packet::Pubcomp.new(:id => 407)
        )
      )
    end

    it "keeps two differently rewritten QoS 1 conversations separate" do
      client_filter = lambda do |packet|
        if packet.is_a?(MQTT::Packet::Publish)
          packet.topic = 'client/public'
          packet.id = 407
        end
        packet
      end
      server_filter = lambda do |packet|
        if packet.is_a?(MQTT::Packet::Publish)
          packet.topic = 'server/public'
          packet.id = 507
        end
        packet
      end

      start_connection(client_filter, server_filter)

      client_publish = MQTT::Packet::Publish.new(
        :id => 7, :qos => 1, :topic => 'client/private', :payload => 'from client'
      )
      server_publish = MQTT::Packet::Publish.new(
        :id => 7, :qos => 1, :topic => 'server/private', :payload => 'from server'
      )
      client_rewritten = MQTT::Packet::Publish.new(
        :id => 407, :qos => 1, :topic => 'client/public', :payload => 'from client'
      )
      server_rewritten = MQTT::Packet::Publish.new(
        :id => 507, :qos => 1, :topic => 'server/public', :payload => 'from server'
      )

      @client_app.write(client_publish)
      expect(receive_packet(@server_app).id).to eq(407)

      @server_app.write(server_publish)
      expect(receive_packet(@client_app).id).to eq(507)

      # Each side acknowledges the identifier it saw, and each PUBACK must
      # return to the other side under that side's original identifier.
      @server_app.write(MQTT::Packet::Puback.new(:id => 407))
      expect(receive_packet(@client_app).id).to eq(7)

      @client_app.write(MQTT::Packet::Puback.new(:id => 507))
      expect(receive_packet(@server_app).id).to eq(7)

      expect(@client_side.received).to eq(
        packet_bytes(
          client_publish,
          MQTT::Packet::Puback.new(:id => 507)
        )
      )
      expect(@server_side.received).to eq(
        packet_bytes(
          server_publish,
          MQTT::Packet::Puback.new(:id => 407)
        )
      )
      expect(@server_side.sent).to eq(
        packet_bytes(
          client_rewritten,
          MQTT::Packet::Puback.new(:id => 7)
        )
      )
      expect(@client_side.sent).to eq(
        packet_bytes(
          server_rewritten,
          MQTT::Packet::Puback.new(:id => 7)
        )
      )
    end
  end

  describe "rewrites that cannot be correlated" do
    it "refuses a rewritten identifier that is already in use" do
      client_filter = lambda do |packet|
        if packet.is_a?(MQTT::Packet::Publish)
          packet.topic = 'public'
          packet.id = 500
        end
        packet
      end

      start_connection(client_filter)
      first = MQTT::Packet::Publish.new(
        :id => 1, :qos => 1, :topic => 'private/a', :payload => 'one'
      )
      second = MQTT::Packet::Publish.new(
        :id => 2, :qos => 1, :topic => 'private/b', :payload => 'two'
      )
      first_rewritten = MQTT::Packet::Publish.new(
        :id => 500, :qos => 1, :topic => 'public', :payload => 'one'
      )

      @client_app.write(first)
      expect(receive_packet(@server_app).id).to eq(500)

      @client_app.write(second)
      expect(wait_for_error).to be_a(MQTT::Proxy::InvalidRewrite)
      expect(@server_side.sent).to eq(packet_bytes(first_rewritten))
      expect(@client_side.sent).to be_empty
    end

    it "does not fabricate a success acknowledgement for a dropped publish" do
      client_filter = lambda do |_packet|
        nil
      end

      start_connection(client_filter)
      publish = MQTT::Packet::Publish.new(
        :id => 7, :qos => 1, :topic => 'private/sensors', :payload => 'hello'
      )

      @client_app.write(publish)
      expect_no_packet(@server_app)
      expect(@server_side.received).to be_empty

      @server_app.write(MQTT::Packet::Puback.new(:id => 7))
      expect_no_packet(@client_app)
      expect(@client_side.sent).to be_empty
      expect(@client_side.received).to eq(packet_bytes(publish))
    end

    it "refuses to rewrite a retransmission that has no matching flow" do
      client_filter = lambda do |packet|
        if packet.is_a?(MQTT::Packet::Publish)
          packet.id = 600
        end
        packet
      end

      start_connection(client_filter)
      first = MQTT::Packet::Publish.new(
        :id => 3, :qos => 1, :topic => 'a', :payload => 'one'
      )
      reuse = MQTT::Packet::Publish.new(
        :id => 3, :qos => 1, :topic => 'a', :payload => 'two'
      )
      first_rewritten = MQTT::Packet::Publish.new(
        :id => 600, :qos => 1, :topic => 'a', :payload => 'one'
      )

      @client_app.write(first)
      expect(receive_packet(@server_app).id).to eq(600)

      @server_app.write(MQTT::Packet::Puback.new(:id => 601))
      expect_no_packet(@client_app)

      @server_app.write(MQTT::Packet::Puback.new(:id => 600))
      expect(receive_packet(@client_app).id).to eq(3)

      # The first flow is complete, so identifier 3 is fresh again and may be
      # rewritten. A DUP packet claiming identifier 3 while the new flow is
      # active would not match, and is rejected by the retransmission check.
      @client_app.write(reuse)
      expect(receive_packet(@server_app).id).to eq(600)

      @client_app.write(MQTT::Packet::Publish.new(
        :id => 3, :qos => 1, :topic => 'a', :payload => 'stale', :duplicate => true
      ))
      expect(wait_for_error).to be_a(MQTT::Proxy::InvalidRewrite)

      expect(@client_side.received).to eq(
        packet_bytes(
          first,
          reuse,
          MQTT::Packet::Publish.new(
            :id => 3, :qos => 1, :topic => 'a', :payload => 'stale', :duplicate => true
          )
        )
      )
      expect(@server_side.sent).to eq(
        packet_bytes(first_rewritten, MQTT::Packet::Publish.new(
          :id => 600, :qos => 1, :topic => 'a', :payload => 'two'
        ))
      )
    end
  end

  describe "connection isolation" do
    it "does not let a mapping from a previous connection acknowledge a new one" do
      client_filter = lambda do |packet|
        if packet.is_a?(MQTT::Packet::Publish)
          packet.topic = 'public'
          packet.id = packet.payload == 'old' ? 700 : 800
        end
        packet
      end

      start_connection(client_filter)
      old_publish = MQTT::Packet::Publish.new(
        :id => 7, :qos => 1, :topic => 'private', :payload => 'old'
      )
      @client_app.write(old_publish)
      expect(receive_packet(@server_app).id).to eq(700)
      expect(@server_side.sent).to eq(packet_bytes(MQTT::Packet::Publish.new(
        :id => 700, :qos => 1, :topic => 'public', :payload => 'old'
      )))

      # Simulate the old connection disappearing without its flow ever being
      # acknowledged. The mapping must die with it.
      stop_connection

      start_connection(client_filter)

      # A late acknowledgement from the previous session must be ignored on
      # the new connection rather than translated to the new client's id.
      @server_app.write(MQTT::Packet::Puback.new(:id => 700))
      expect_no_packet(@client_app)
      expect(@client_side.sent).to be_empty

      new_publish = MQTT::Packet::Publish.new(
        :id => 7, :qos => 1, :topic => 'private', :payload => 'new'
      )
      @client_app.write(new_publish)
      expect(receive_packet(@server_app).id).to eq(800)

      @server_app.write(MQTT::Packet::Puback.new(:id => 800))
      expect(receive_packet(@client_app).id).to eq(7)

      expect(@client_side.sent).to eq(
        packet_bytes(MQTT::Packet::Puback.new(:id => 7))
      )
    end
  end
end
