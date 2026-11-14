# encoding: utf-8
# frozen_string_literal: true
require 'mail/constants'

module Mail
  class ReceivedChain
    # Parses the body of a single Received field into top-level clauses.
    #
    # Received field bodies are a sequence of name/value pairs (from, by, via,
    # with, id, for) followed by a date-time.  Comments may contain arbitrary
    # text, including words such as "by" and bracketed addresses.  Those
    # comment contents are evidence in themselves, but they must never be
    # mistaken for top-level clauses or for the hop's real host.
    module Parser
      KEYWORDS = %w[from by via with id for].freeze

      Comment = Struct.new(:text, :depth, :offset, :finish, :parent_text,
                           :claims, :addresses, keyword_init: true) do
        def to_h
          {
            'text' => text,
            'depth' => depth,
            'claims' => claims || [],
            'addresses' => addresses || []
          }
        end
      end

      AddressEvidence = Struct.new(:address, :bracketed, :ip, :depth, :text, keyword_init: true) do
        def to_h
          {
            'address' => address,
            'bracketed' => bracketed,
            'ip' => ip,
            'depth' => depth,
            'text' => text
          }
        end
      end

      class Endpoint
        attr_reader :raw, :host, :normalized_host, :mailbox, :address,
                    :address_source, :comment_addresses, :address_depth,
                    :address_comment_text

        def initialize(raw: nil, host: nil, mailbox: nil, address: nil,
                       address_source: nil, comment_addresses: [],
                       address_depth: nil, address_comment_text: nil)
          @raw = raw
          @host = host
          @normalized_host = Parser.normalize_host(host)
          @mailbox = mailbox
          @address = address
          @address_source = address_source
          @comment_addresses = comment_addresses
          @address_depth = address_depth
          @address_comment_text = address_comment_text
        end

        def to_h
          {
            'raw' => raw,
            'host' => host,
            'normalized_host' => normalized_host,
            'mailbox' => mailbox,
            'address' => address,
            'address_source' => address_source && address_source.to_s,
            'address_depth' => address_depth,
            'address_comment_text' => address_comment_text,
            'comment_addresses' => comment_addresses.map(&:to_h)
          }
        end
      end

      Clause = Struct.new(:keyword, :value, :start, :finish, keyword_init: true) do
        def to_h
          { 'keyword' => keyword, 'value' => value }
        end
      end

      Parsed = Struct.new(:value, :info, :timestamp, :leading, :clauses,
                          :comments, :from, :by, :via, :with, :id,
                          :for_addresses, keyword_init: true) do
        def clause(name)
          found = clauses[name.to_s]
          found && found.value
        end

        def to_h
          {
            'value' => value,
            'info' => info,
            'timestamp' => timestamp,
            'leading' => leading,
            'clauses' => clauses.transform_values(&:to_h),
            'from' => from && from.to_h,
            'by' => by && by.to_h,
            'via' => via,
            'with' => with,
            'protocol' => protocol,
            'id' => self.id,
            'for_addresses' => for_addresses,
            'comments' => comments.map(&:to_h)
          }
        end

        def protocol
          Parser.protocol_from(with) || Parser.protocol_from(via)
        end
      end

      class << self
        def parse(value)
          text = safe_string(value)
          return empty_parse(text) if text.nil? || text.strip.empty?

          # Match Mail::Field's unfolding: remove the line break before folding
          # whitespace but keep the whitespace itself.
          text = text.gsub(/\r?\n([ \t]+)/, '\\1')

          comment_list = comments(text)
          separator = top_level_semicolons(text).last
          info_end = separator || text.length
          info = text[0...info_end].to_s.strip
          timestamp = separator ? text[(separator + 1)..-1].to_s.strip : nil

          clauses = clauses(text, info_end)
          leading_end = clauses.empty? ? info_end : clauses.values.first.start
          leading = text[0...leading_end].to_s.strip

          from = endpoint(clauses['from'], comment_list)
          by = endpoint(clauses['by'], comment_list)

          Parsed.new(
            value: text,
            info: info,
            timestamp: timestamp,
            leading: leading.empty? ? nil : leading,
            clauses: clauses,
            comments: comment_list,
            from: from,
            by: by,
            via: presence(clauses['via']&.value),
            with: presence(clauses['with']&.value),
            id: presence(clauses['id']&.value),
            for_addresses: addresses_in(clauses['for']&.value)
          )
        end

        # All comments in a string, outermost first.  Nested comments are
        # recorded with a depth greater than one, and their text is kept
        # separate from the enclosing comment.
        def comments(text)
          text = safe_string(text).to_s
          found = []
          stack = []
          in_quote = false
          index = 0

          while index < text.length
            char = text[index]

            if !stack.empty? && char == '\\'
              index += 2
              next
            end

            if char == '"'
              in_quote = !in_quote
              index += 1
              next
            end

            unless in_quote
              if char == '('
                stack << index
              elsif char == ')' && !stack.empty?
                start = stack.pop
                raw = text[(start + 1)...index].to_s
                clean_text = strip_nested_comments(raw)
                found << Comment.new(
                  text: clean_text,
                  depth: stack.length + 1,
                  offset: start,
                  finish: index,
                  parent_text: raw,
                  claims: embedded_claims(clean_text),
                  addresses: bracketed_addresses(clean_text)
                )
              end
            end

            index += 1
          end

          found.sort_by!(&:offset)
          found
        end

        # Removes comments from a string, replacing them with spaces.  The
        # result keeps quoted strings intact and is safe to tokenize.
        def remove_comments(text)
          text = safe_string(text).to_s
          output = +''
          depth = 0
          in_quote = false
          index = 0

          while index < text.length
            char = text[index]

            if depth > 0
              if char == '\\'
                index += 2
                next
              elsif char == '('
                depth += 1
              elsif char == ')'
                depth -= 1
              end
              output << ' '
              index += 1
              next
            end

            if char == '"'
              in_quote = !in_quote
              output << char
            elsif char == '(' && !in_quote
              depth = 1
              output << ' '
            else
              output << char
            end

            index += 1
          end

          output
        end

        def protocol_from(value)
          return nil if value.nil?

          stripped = value.strip
          if stripped.start_with?('(') && stripped.end_with?(')')
            inner = stripped[1..-2].to_s.strip
            match = inner.match(/\A[A-Za-z][A-Za-z0-9+._-]*\z/)
            return match[0].downcase if match
          end

          token = remove_comments(stripped).strip.split(/\s+/, 2).first
          token && token.downcase
        end

        def normalize_host(host)
          return nil if host.nil?
          name = safe_string(host).strip
          return nil if name.empty?
          name = name[1..-2] if name.start_with?('[') && name.end_with?(']')
          name = name.sub(/\Aipv6:/i, '')
          name = name.sub(/[.,;:]+\z/, '')
          name.downcase
        end

        def ip_literal?(value)
          return false if value.nil?
          require 'ipaddr'
          IPAddr.new(value.to_s.sub(/\Aipv6:/i, ''))
          true
        rescue ArgumentError, IPAddr::InvalidAddressError
          false
        end

        private

        def empty_parse(text)
          Parsed.new(
            value: text,
            info: text.to_s.strip,
            timestamp: nil,
            leading: nil,
            clauses: {},
            comments: [],
            from: nil,
            by: nil,
            via: nil,
            with: nil,
            id: nil,
            for_addresses: []
          )
        end

        def clauses(text, limit)
          positions = top_level_keywords(text, limit)
          result = {}

          positions.each_with_index do |(keyword, start), index|
            stop = positions[index + 1] ? positions[index + 1][1] : limit
            value = text[(start + keyword.length)...stop].to_s.strip
            result[keyword] ||= Clause.new(keyword: keyword, value: value, start: start, finish: stop)
          end

          result
        end

        def endpoint(clause, comment_list)
          return nil if clause.nil? || clause.value.strip.empty?

          relevant = comments_within(comment_list, clause.start, clause.finish)
          token = leading_token(remove_comments(clause.value))
          token = token.sub(/[,\s]+\z/, '') if token
          return nil if token.nil? || token.empty?

          host = nil
          mailbox = nil
          address = nil
          source = nil

          if token.start_with?('"') && token.end_with?('"') && token.length > 1
            host = token[1..-2]
          elsif token.start_with?('<') && token.include?('@')
            mailbox = token.sub(/\A</, '').sub(/>\z/, '')
            host = mailbox.split('@').last
          elsif token.include?('@')
            mailbox = token.sub(/\A</, '').sub(/>\z/, '')
            host = mailbox.split('@').last
          elsif token.start_with?('[') && token.end_with?(']')
            host = token[1..-2].sub(/\Aipv6:/i, '')
            address = host
            source = :address_literal
          elsif ip_literal?(token)
            host = token
            address = token.sub(/\Aipv6:/i, '')
            source = :address_literal
          else
            host = token
          end

          comment_addresses = addresses_in_comments(relevant)
          address_depth = nil
          address_comment_text = nil
          if source.nil? && (preferred = preferred_comment_address(comment_addresses))
            address = preferred.address
            source = :comment
            address_depth = preferred.depth
            address_comment_text = preferred.text
          end

          Endpoint.new(
            raw: clause.value.strip,
            host: host,
            mailbox: mailbox,
            address: address,
            address_source: source,
            comment_addresses: comment_addresses,
            address_depth: address_depth,
            address_comment_text: address_comment_text
          )
        end

        # Only syntactically valid IP literals may stand in as a hop address.
        # Bracketed prose such as "[unix socket]" stays comment evidence.
        def preferred_comment_address(comment_addresses)
          usable = comment_addresses.select(&:ip)
          usable.find { |entry| entry.depth == 1 } ||
            usable.find(&:bracketed) ||
            usable.first
        end

        def comments_within(comment_list, start, finish)
          comment_list.select { |comment| comment.offset > start && comment.finish < finish }
        end

        def addresses_in_comments(comment_list)
          comment_list.flat_map do |comment|
            text = comment.text.to_s
            found = text.scan(/\[([^\[\]]+)\]/).flatten.map do |address|
              clean = address.sub(/\Aipv6:/i, '').sub(/[.,;]+\z/, '')
              AddressEvidence.new(
                address: clean,
                bracketed: true,
                ip: ip_literal?(clean),
                depth: comment.depth,
                text: text.strip
              )
            end
            found.concat(ipv4_addresses(text, comment.depth))
            found
          end
        end

        def ipv4_addresses(text, depth)
          text.to_s.scan(/(?<!\[)\b(?:\d{1,3}\.){3}\d{1,3}\b(?![^\[]*\])/).flatten.map do |address|
            AddressEvidence.new(
              address: address,
              bracketed: false,
              ip: ip_literal?(address),
              depth: depth,
              text: text.to_s.strip
            )
          end.reject { |entry| !entry.ip }
        end

        def addresses_in(value)
          return [] if value.nil?
          text = remove_comments(value)
          addresses = text.scan(/<([^<>]+)>/).flatten
          addresses.concat(text.scan(/(?<![\w<])([^\s<>]+@[^\s<>]+)/).flatten)
          addresses.map(&:strip).reject(&:empty?).uniq
        end

        def top_level_keywords(text, limit)
          positions = []
          depth = 0
          in_quote = false
          index = 0

          while index < limit
            char = text[index]

            if depth > 0
              if char == '\\'
                index += 2
                next
              elsif char == '('
                depth += 1
              elsif char == ')'
                depth -= 1
              end
            else
              if char == '('
                depth += 1
              elsif char == '"'
                in_quote = !in_quote
              elsif !in_quote && (keyword = keyword_at(text, index))
                positions << [keyword, index]
                index += keyword.length
                next
              end
            end

            index += 1
          end

          positions
        end

        def top_level_semicolons(text)
          found = []
          depth = 0
          in_quote = false
          index = 0

          while index < text.length
            char = text[index]

            if depth > 0
              if char == '\\'
                index += 2
                next
              elsif char == '('
                depth += 1
              elsif char == ')'
                depth -= 1
              end
            else
              if char == '('
                depth += 1
              elsif char == '"'
                in_quote = !in_quote
              elsif char == ';' && !in_quote
                found << index
              end
            end

            index += 1
          end

          found
        end

        # First token of a string, treating a leading quoted string as one
        # token.  Comments must already have been removed.
        def leading_token(text)
          value = text.to_s.strip
          return value if value.empty?
          if value.start_with?('"')
            index = 1
            while index < value.length
              if value[index] == '\\'
                index += 2
                next
              elsif value[index] == '"'
                return value[0..index]
              end
              index += 1
            end
            return value.split(/\s+/, 2).first
          end
          value.split(/\s+/, 2).first
        end

        def strip_nested_comments(text)
          output = +''
          depth = 0
          in_quote = false
          index = 0

          while index < text.length
            char = text[index]

            if depth > 0
              if char == '\\'
                index += 2
                next
              elsif char == '('
                depth += 1
              elsif char == ')'
                depth -= 1
              end
              index += 1
              next
            end

            if char == '\\'
              output << text[index + 1].to_s
              index += 2
              next
            elsif char == '(' && !in_quote
              depth = 1
              output << ' '
            elsif char == '"'
              in_quote = !in_quote
              output << char
            else
              output << char
            end

            index += 1
          end

          output.gsub(/\s+/, ' ').strip
        end

        # Transfers that look like Received clauses but occur inside a
        # comment.  They are recorded as rejected claims; they never become
        # clauses or hops.
        def embedded_claims(text)
          text.to_s.scan(/(?:\A|\s)(from|by|via|with|id|for)\s+(\[[^\]]+\]|[^\s(),;]+)/i).map do |keyword, target|
            {
              'keyword' => keyword.downcase,
              'target' => target.sub(/[.,;:]+\z/, ''),
              'treated_as_hop' => false
            }
          end
        end

        def bracketed_addresses(text)
          text.to_s.scan(/\[([^\[\]]+)\]/).flatten.map do |address|
            address.sub(/\Aipv6:/i, '').sub(/[.,;]+\z/, '')
          end
        end

        def keyword_at(text, index)
          KEYWORDS.find do |keyword|
            next false unless text[index, keyword.length]&.casecmp?(keyword)
            before = index.zero? ? nil : text[index - 1]
            after = text[index + keyword.length]
            (before.nil? || before.match?(/\s/)) && (after.nil? || after.match?(/\s/))
          end
        end

        def presence(value)
          value.nil? || value.strip.empty? ? nil : value.strip
        end

        def safe_string(value)
          return nil if value.nil?
          string = value.to_s
          if string.encoding == Encoding::ASCII_8BIT
            string = string.dup.force_encoding(Encoding::UTF_8)
          end
          string.valid_encoding? ? string : string.scrub
        end
      end
    end
  end
end
