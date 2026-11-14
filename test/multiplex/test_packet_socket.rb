require_relative '../common'
require 'logger'
require 'socket'
require 'net/ssh/buffer'
require 'net/ssh/multiplex/proxy_transport'

module NetSSH
  class TestPacketSocket < NetSSHTest
    def setup
      skip "ControlMaster needs UNIX sockets" if Gem.win_platform?
      @local, @peer = UNIXSocket.pair(:STREAM)
      @local.extend(Net::SSH::Multiplex::PacketSocket)
      @local.logger = Logger.new(IO::NULL)
    end

    def teardown
      @local.close unless @local.closed?
      @peer.close unless @peer.closed?
    end

    def frame(payload, padding: 0)
      [payload.bytesize + 1, padding].pack('NC') + payload
    end

    def test_round_trips_a_connection_packet
      payload = Net::SSH::Buffer.from(:byte, 93, :string, "echo hi").to_s
      @local.send_packet(Net::SSH::Buffer.from(:byte, 93, :string, "echo hi"))
      length, padding = @peer.read(5).unpack('NC')
      assert_equal payload.bytesize + 1, length
      assert_equal 0, padding
      assert_equal payload, @peer.read(payload.bytesize)
    end

    def test_reads_a_framed_packet
      payload = Net::SSH::Buffer.from(:byte, 200, :long, 7).to_s
      @peer.write(frame(payload))
      packet = @local.next_packet(:block, 2)
      assert_equal 200, packet.type
      assert_equal 7, packet.read_long
    end

    def test_buffers_a_partial_packet
      whole = frame(Net::SSH::Buffer.from(:byte, 95).to_s)
      @peer.write(whole.byteslice(0, 2))
      assert_nil @local.next_packet(:nonblock)
      @peer.write(whole.byteslice(2..-1))
      packet = @local.next_packet(:block, 2)
      assert_equal 95, packet.type
    end

    def test_rejects_an_oversized_length
      @peer.write([Net::SSH::Multiplex::PacketSocket::MAX_PACKET_SIZE + 1, 0].pack('NC'))
      assert_raises(Net::SSH::Exception) { @local.next_packet(:block, 2) }
    end

    def test_rejects_bad_padding
      @peer.write([3, 5].pack('NC') + 'ab')
      assert_raises(Net::SSH::Exception) { @local.next_packet(:block, 2) }
    end

    def test_a_closed_master_disconnects
      @peer.close
      assert_raises(Net::SSH::Disconnect) { @local.next_packet(:block, 2) }
    end

    def test_unknown_read_mode_is_rejected
      assert_raises(ArgumentError) { @local.next_packet(:sideways) }
    end
  end
end
