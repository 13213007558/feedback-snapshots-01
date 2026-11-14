# encoding: BINARY

# Offline, reassembly-tolerant analysis of captured MQTT byte streams.
#
# This namespace never opens a network connection. It consumes raw fragments
# captured from the two directions of an MQTT transport connection,
# reassembles and decodes them with MQTT::Packet, correlates the resulting
# events into a timeline, and reports protocol-timing deviations while
# keeping capture incompleteness explicitly separate from proven violations.
require 'mqtt'
require 'mqtt/forensics/frame'
require 'mqtt/forensics/capture'
require 'mqtt/forensics/analyzer'
require 'mqtt/forensics/report'
require 'mqtt/forensics/loader'
require 'mqtt/forensics/demo'

module MQTT
  module Forensics
    # Convenience entry point. Accepts an array of Fragment-like arguments:
    #   MQTT::Forensics.analyze([
    #     [:client, raw_bytes, captured_at, source],
    #     [:broker, raw_bytes, captured_at, source]
    #   ])
    # Returns a Report.
    def self.analyze(fragments)
      capture = Capture.new
      fragments.each do |item|
        if item.is_a?(Fragment)
          capture.add_fragment(item)
        else
          direction, bytes, captured_at, source = item
          capture.add(direction, bytes, captured_at, source)
        end
      end
      Analyzer.new(capture).analyze
    end
  end
end
