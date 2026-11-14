# encoding: utf-8
# frozen_string_literal: true
require 'date'
require 'mail/received_chain/parser'

module Mail
  class ReceivedChain
    # Parses the date-time portion of a Received field without discarding the
    # original text.  The resulting Timestamp records what the mail claims,
    # what Ruby could parse, and how trustworthy the instant is.
    module TimeParser
      ZONE_OFFSETS = {
        'UT' => 0, 'UTC' => 0, 'GMT' => 0, 'Z' => 0,
        'EST' => -5 * 3600, 'EDT' => -4 * 3600,
        'CST' => -6 * 3600, 'CDT' => -5 * 3600,
        'MST' => -7 * 3600, 'MDT' => -6 * 3600,
        'PST' => -8 * 3600, 'PDT' => -7 * 3600,
        'AST' => -4 * 3600, 'ADT' => -3 * 3600,
        'NST' => -(3 * 3600 + 1800), 'NDT' => -(2 * 3600 + 1800),
        'BST' => 1 * 3600, 'CET' => 1 * 3600, 'CEST' => 2 * 3600,
        'EET' => 2 * 3600, 'EEST' => 3 * 3600, 'MSK' => 3 * 3600,
        'JST' => 9 * 3600, 'KST' => 9 * 3600,
        'AEST' => 10 * 3600, 'AEDT' => 11 * 3600,
        'NZST' => 12 * 3600, 'NZDT' => 13 * 3600
      }.freeze

      Timestamp = Struct.new(
        :raw, :parsed, :utc, :offset_seconds, :offset_text, :zone_label,
        :zone_label_offset, :offset_consistent, :offset_present,
        :offset_meaning, :comparable, :error, :labels, :missing_components,
        keyword_init: true
      ) do
        def valid?
          !parsed.nil?
        end

        def to_h
          {
            'raw' => raw,
            'parsed' => parsed && parsed.iso8601,
            'utc' => utc && utc.iso8601,
            'offset_seconds' => offset_seconds,
            'offset_text' => offset_text,
            'zone_label' => zone_label,
            'zone_label_offset_seconds' => zone_label_offset,
            'offset_consistent' => offset_consistent,
            'offset_present' => offset_present,
            'offset_meaning' => offset_meaning,
            'comparable' => comparable,
            'error' => error
          }
        end
      end

      class << self
        def parse(text)
          raw = text.nil? ? nil : text.to_s.strip
          return build(raw: raw, error: 'missing timestamp') if raw.nil? || raw.empty?

          comment_list = Parser.comments(raw)
          labels = labels_from(comment_list)
          bare = Parser.remove_comments(raw).strip

          numeric = bare.match(/([+-])(\d{2}):?(\d{2})\s*\z/)
          offset_text = numeric && "#{numeric[1]}#{numeric[2]}#{numeric[3]}"
          trailing_zone = bare.match(/(?:\s|^)([A-Za-z]{1,5})\s*\z/)
          raw_zone_token = trailing_zone && trailing_zone[1].upcase
          zone_token = raw_zone_token if raw_zone_token && recognized_zone?(raw_zone_token)
          zone_token ||= labels.find { |label| recognized_zone?(label) }
          unrecognized_zone =
            if raw_zone_token && !recognized_zone?(raw_zone_token)
              raw_zone_token
            end

          parsed =
            begin
              DateTime.parse(bare)
            rescue StandardError => error
              return build(raw: raw, labels: labels, error: "#{error.class}: #{error.message}")
            end

          offset_present = !offset_text.nil? || !zone_token.nil?
          offset_seconds = (parsed.offset * 86_400).to_i
          unknown_offset = offset_text == '-0000'

          label_entries = labels.map do |label|
            [label, ZONE_OFFSETS[label.upcase]]
          end

          known_labels = label_entries.reject { |(_, offset)| offset.nil? }
          label_offset = known_labels.first && known_labels.first[1]
          zone_label = known_labels.first && known_labels.first[0]
          distinct_label_offsets = known_labels.map(&:last).uniq

          declared_offsets = []
          declared_offsets << offset_seconds if offset_text
          declared_offsets << ZONE_OFFSETS[zone_token] if zone_token && ZONE_OFFSETS[zone_token]
          declared_offsets.concat(distinct_label_offsets)
          declared_offsets.compact!

          consistent =
            if unknown_offset
              true
            elsif declared_offsets.empty?
              true
            else
              declared_offsets.uniq.size == 1
            end

          comparable = offset_present && !unknown_offset && unrecognized_zone.nil?
          missing = missing_components(bare)

          build(
            raw: raw,
            parsed: parsed,
            utc: parsed.to_time.utc,
            offset_seconds: offset_seconds,
            offset_text: offset_text,
            zone_label: zone_label || zone_token || unrecognized_zone,
            zone_label_offset: label_offset || (zone_token && ZONE_OFFSETS[zone_token]),
            offset_consistent: consistent,
            offset_present: offset_present,
            offset_meaning:
              if unknown_offset
                'unknown'
              elsif unrecognized_zone
                'unrecognized_zone'
              elsif offset_present
                'explicit'
              else
                'assumed_utc'
              end,
            comparable: comparable,
            labels: labels,
            missing_components: missing
          )
        end

        def labels_from(comment_list)
          comment_list.select { |comment| comment.depth == 1 }.flat_map do |comment|
            comment.text.to_s.scan(/\b([A-Za-z]{1,5})\b/).flatten
          end.map(&:upcase).uniq
        end

        def recognized_zone?(token)
          ZONE_OFFSETS.key?(token.to_s.upcase)
        end

        def missing_components(value)
          missing = []
          missing << 'day-of-week' unless value.match?(/\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\b/i)
          missing << 'seconds' unless value.match?(/\d{1,2}:\d{2}:\d{2}/)
          missing
        end

        private

        def build(raw:, parsed: nil, utc: nil, offset_seconds: nil, offset_text: nil,
                  zone_label: nil, zone_label_offset: nil, offset_consistent: nil,
                  offset_present: false, offset_meaning: nil, comparable: false,
                  labels: [], missing_components: [], error: nil)
          Timestamp.new(
            raw: raw,
            parsed: parsed,
            utc: utc,
            offset_seconds: offset_seconds,
            offset_text: offset_text,
            zone_label: zone_label,
            zone_label_offset: zone_label_offset,
            offset_consistent: offset_consistent,
            offset_present: offset_present,
            offset_meaning: offset_meaning,
            comparable: comparable,
            labels: labels,
            missing_components: missing_components,
            error: error
          )
        end
      end
    end
  end
end
