# encoding: BINARY

require 'json'
require 'mqtt/forensics/capture'

module MQTT
  module Forensics
    # Builds a Capture from on-disk fragment descriptions. Two layouts are
    # supported so partial, mid-session captures can be expressed faithfully.
    #
    # 1. JSON document:
    #   {
    #     "fragments": [
    #       {"direction": "client", "encoding": "hex",
    #        "data": "10..", "captured_at": 1700.5, "source": "c0"},
    #       {"direction": "broker", "encoding": "base64", "data": "...."}
    #     ]
    #   }
    #
    # 2. JSON Lines (.jsonl): one fragment object per line.
    #
    # encoding is "hex" (default), "base64" or "binary" (a raw byte string).
    # Every other field is optional; missing timestamps stay unknown rather
    # than being fabricated.
    module Loader
      DIRECTIONS = {
        'client' => :client, 'c' => :client, 'out' => :client,
        'broker' => :broker, 'b' => :broker, 'server' => :broker, 'in' => :broker
      }.freeze

      def self.load(path)
        content = File.binread(path)
        if File.extname(path).casecmp?('.jsonl') || looks_like_jsonl?(content)
          load_jsonl(content)
        else
          load_json(content)
        end
      end

      def self.load_json(content)
        doc = JSON.parse(content)
        entries = doc.is_a?(Array) ? doc : doc.fetch('fragments')
        build(entries)
      end

      def self.load_jsonl(content)
        entries = content.lines.map(&:strip).reject(&:empty?).map { |line| JSON.parse(line) }
        build(entries)
      end

      def self.build(entries)
        capture = Capture.new
        entries.each do |entry|
          direction = resolve_direction(entry['direction'])
          data = decode(entry['encoding'] || 'hex', entry['data'])
          capture.add(direction, data, entry['captured_at'], entry['source'])
        end
        capture
      end

      def self.resolve_direction(value)
        dir = DIRECTIONS[value.to_s.downcase]
        raise ArgumentError, "unknown direction #{value.inspect} (use client or broker)" if dir.nil?

        dir
      end

      def self.decode(encoding, data)
        case encoding.to_s.downcase
        when 'hex'
          clean = data.to_s.gsub(/\s|0x/i, '')
          raise ArgumentError, 'hex fragment has an odd number of nibbles' unless clean.bytesize.even?

          [clean].pack('H*').b
        when 'base64'
          begin
            require 'base64'
          rescue LoadError
            raise ArgumentError, 'base64 encoding requested but the optional "base64" library is unavailable; use hex or binary'
          end
          Base64.strict_decode64(data.to_s).b
        when 'binary', 'raw', 'bytes'
          data.to_s.dup.force_encoding('ASCII-8BIT')
        else
          raise ArgumentError, "unsupported encoding #{encoding.inspect}"
        end
      end

      def self.looks_like_jsonl?(content)
        lines = content.lines.map(&:strip).reject(&:empty?)
        return false if lines.size <= 1

        lines.all? { |line| line.start_with?('{') && line.end_with?('}') }
      end
    end
  end
end
