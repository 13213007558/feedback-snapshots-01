# encoding: utf-8
# frozen_string_literal: true
require 'strscan'
require 'uri'

require 'mail/constants'
require 'mail/unsubscribe/errors'
require 'mail/unsubscribe/evidence'
require 'mail/unsubscribe/header_field'
require 'mail/unsubscribe/candidate'
require 'mail/unsubscribe/action'

module Mail
  module Unsubscribe
    # Parses one-click unsubscribe metadata out of a message.
    #
    # This class only inspects the header block.  It neither resolves nor
    # fetches any URI, so a message containing a hostile List-Unsubscribe
    # field cannot cause a request merely by being parsed.
    class Parser
      LIST_UNSUBSCRIBE = 'list-unsubscribe'
      LIST_UNSUBSCRIBE_POST = 'list-unsubscribe-post'
      ONE_CLICK = /\Alist-unsubscribe=one-click\z/i

      attr_reader :reason

      def initialize(source, dkim_evidence = nil, **options)
        @header = extract_header(source)
        evidence = dkim_evidence
        evidence ||= options[:dkim_evidence]
        evidence ||= options[:evidence]
        evidence ||= options[:dkim]
        @evidence = evidence
        @reason = nil
      end

      def parse(*arguments, **options)
        analyze(*arguments, **options).action
      end

      def parse!(*arguments, **options)
        result = analyze(*arguments, **options)
        return result.action if result.action

        raise NotEligibleError, "Message is not eligible for one-click unsubscribe: #{result.reason}"
      end

      # Returns a Result carrying both the action and the refusal reason.
      def analyze(*arguments, **options)
        apply_evidence(arguments, options) unless arguments.empty? && options.empty?
        @reason = nil
        result = analyze_eligibility
        @reason = result.reason
        result
      end

      # Returned by #analyze: either a pending action or a refusal reason.
      Result = Struct.new(:action, :reason) do
        def action?
          !action.nil?
        end
      end

      private

      def analyze_eligibility
        grouped = grouped_instances
        return failure(:missing_list_unsubscribe) if grouped[LIST_UNSUBSCRIBE].nil?
        return failure(:missing_list_unsubscribe_post) if grouped[LIST_UNSUBSCRIBE_POST].nil?

        posts = grouped[LIST_UNSUBSCRIBE_POST]
        return failure(:duplicate_list_unsubscribe_post) unless posts.size == 1

        post = posts.first
        return failure(:invalid_list_unsubscribe_post) unless one_click_post?(post)

        return failure(:missing_dkim_evidence) if @evidence.nil?

        evidences = coerce_evidence
        return failure(:invalid_dkim_evidence) if evidences.empty?
        return failure(:invalid_dkim_evidence) unless evidences.any?(&:valid?)

        unsubscribe_fields = grouped[LIST_UNSUBSCRIBE]
        both_covered = []
        post_covered = false

        evidences.each do |evidence|
          next unless evidence.valid?

          coverage = coverage_map(evidence, grouped)
          post_keys = coverage.keys.select { |key| key.start_with?("#{LIST_UNSUBSCRIBE_POST}#") }
          unsubscribe_keys = coverage.keys.select { |key| key.start_with?("#{LIST_UNSUBSCRIBE}#") }

          post_covered ||= post_keys.any?
          next if post_keys.empty? || unsubscribe_keys.empty?

          # The same signature must cover both header types.  Coverage from
          # different signatures is never combined.
          both_covered << [evidence, coverage]
        end

        return failure(:uncovered_list_unsubscribe_post) unless post_covered
        return failure(:uncovered_list_unsubscribe) if both_covered.empty?

        votes = []
        malformed = false

        both_covered.each do |evidence, coverage|
          # With duplicate instances, a bare header name only tells us the
          # name appeared in h=, not which concrete instance was signed.
          # Require the verifier to identify that instance explicitly so an
          # appended, unsigned header can never become the target.
          if unsubscribe_fields.size > 1
            info = coverage[unsubscribe_fields.find { |f| coverage.key?(f.key) }&.key]
            unless info && info[:explicit]
              return failure(:ambiguous_list_unsubscribe)
            end
          end

          selected = unsubscribe_fields.select { |field| coverage.key?(field.key) }
          return failure(:ambiguous_list_unsubscribe) unless selected.size == 1

          field = selected.first
          parsed = parse_unsubscribe_field(field)
          unless parsed
            malformed = true
            next
          end

          votes << { field: field, parsed: parsed, evidence: evidence }
        end

        return failure(:invalid_list_unsubscribe) if votes.empty? && malformed
        return failure(:uncovered_list_unsubscribe) if votes.empty?

        distinct_targets = votes.map { |vote| vote[:parsed][:target].uri.to_s }.uniq
        distinct_fields = votes.map { |vote| vote[:field].key }.uniq

        if distinct_targets.size > 1 || distinct_fields.size > 1
          return failure(:ambiguous_list_unsubscribe)
        end

        # Several verified signatures may cover the same concrete instance.
        # Prefer the one the caller marked with the strongest explicit
        # selector, but never merge coverage across different instances.
        vote = votes.max_by do |candidate|
          info = coverage_map(candidate[:evidence], grouped)[candidate[:field].key]
          info && info[:explicit] ? 1 : 0
        end

        action = Action.new(
          uri: vote[:parsed][:target].uri,
          candidates: vote[:parsed][:candidates],
          list_unsubscribe: vote[:field],
          list_unsubscribe_post: post,
          evidence: vote[:evidence]
        )
        Result.new(action, nil)
      end

      def failure(reason)
        Result.new(nil, reason)
      end

      def apply_evidence(arguments, options)
        value = arguments.first
        value ||= options[:dkim_evidence]
        value ||= options[:evidence]
        value ||= options[:dkim]
        @evidence = value
      end

      def extract_header(source)
        if source.respond_to?(:header)
          source.header
        elsif source.is_a?(Mail::Header)
          source
        elsif source.is_a?(String)
          Mail::Message.new(source).header
        else
          raise ArgumentError, "Expected a Mail::Message, Mail::Header, or raw message String: #{source.inspect}"
        end
      end

      def grouped_instances
        grouped = {}
        fields = @header.fields

        fields.each do |field|
          name = field.name.to_s.downcase
          next unless name == LIST_UNSUBSCRIBE || name == LIST_UNSUBSCRIBE_POST

          value = field.unparsed_value
          value = field.value if value.nil?
          grouped[name] ||= []
          grouped[name] << HeaderField.new(field.name.to_s, unfold(value), nil)
        end

        grouped.each_value do |instances|
          instances.reverse.each_with_index do |instance, bottom_index|
            instance.index = bottom_index
          end
        end

        grouped
      end

      def unfold(value)
        value.to_s.gsub(Constants::UNFOLD_WS, '\\1').strip
      end

      def one_click_post?(field)
        ONE_CLICK.match?(field.value)
      end

      def coerce_evidence
        return [] if @evidence.nil?

        Evidence.coerce_all(@evidence)
      rescue ArgumentError
        []
      end

      # Returns a map of concrete header field key to coverage details for
      # one verified signature.  Repeated names in h= protect successive
      # instances from the bottom of the header block; an explicit
      # +name:index+ selector protects exactly that bottom-based instance,
      # and a +value+ selector protects an instance with that exact value.
      def coverage_map(evidence, grouped)
        covered = {}
        plain_counts = Hash.new(0)
        explicit = Hash.new { |hash, key| hash[key] = [] }

        evidence.entries.each do |entry|
          name, index, value = entry
          name = name.to_s.downcase
          next if name.empty?

          if index
            explicit[name] << [index, value, true]
          elsif value
            explicit[name] << [nil, value, true]
          else
            plain_counts[name] += 1
          end
        end

        plain_counts.each do |name, count|
          instances = grouped[name]
          next unless instances

          instances.each do |instance|
            next unless instance.index < count

            covered[instance.key] = { explicit: false, count: count }
          end
        end

        explicit.each do |name, selectors|
          instances = grouped[name]
          next unless instances

          selectors.each do |index, value, explicit_flag|
            candidates = index ? instances.select { |i| i.index == index } : instances

            if value.nil?
              candidates.each do |instance|
                covered[instance.key] = { explicit: explicit_flag }
              end
            else
              normalized = unfold(value)
              candidates.each do |instance|
                next unless instance.value == normalized
                covered[instance.key] = { explicit: explicit_flag }
              end
            end
          end
        end

        covered
      end

      # Accepts the strict angle-bracket list from RFC 2369.  Anything
      # outside the grammar rejects the whole field rather than silently
      # dropping a possibly hostile candidate.
      def parse_unsubscribe_field(field)
        body = field.value
        return nil if body.empty?

        scanner = StringScanner.new(body)
        candidates = []

        loop do
          scanner.skip(/\s*/)
          break if scanner.eos?
          return nil unless scanner.scan(/</)

          closing = scanner.string.index('>', scanner.pos)
          return nil unless closing

          raw = scanner.string[scanner.pos...closing]
          return nil unless valid_uri_text?(raw)

          uri = parse_uri(raw)
          return nil unless uri

          case uri
          when URI::HTTPS
            return nil if uri.host.nil? || uri.host.empty?
            return nil if uri.userinfo
          when URI::MailTo
            return nil if uri.to.to_s.empty?
          else
            return nil
          end
          return nil if uri.fragment

          candidates << Candidate.new(uri, raw)
          scanner.pos = closing + 1
          scanner.skip(/\s*/)

          if scanner.eos?
            break
          elsif scanner.scan(/,/)
            trailing = StringScanner.new(scanner.string[scanner.pos..-1])
            trailing.skip(/\s*/)
            return nil if trailing.eos?
            next
          else
            return nil
          end
        end

        return nil if candidates.empty?

        https = candidates.select(&:https?)
        return nil unless https.size == 1

        { candidates: candidates.freeze, target: https.first }
      end

      def valid_uri_text?(raw)
        return false if raw.empty?

        raw.each_codepoint.all? do |codepoint|
          codepoint > 0x20 && codepoint < 0x7f &&
            codepoint != 0x22 && codepoint != 0x3c && codepoint != 0x3e &&
            codepoint != 0x5c
        end
      end

      def parse_uri(raw)
        URI.parse(raw)
      rescue URI::Error, ArgumentError
        nil
      end
    end
  end
end
