module Brakeman
  # Conservatively determines whether a regular expression used for format
  # validation is anchored to the entire string.
  #
  # This is intentionally a small structural parser instead of a textual
  # check. In particular, seeing `\A` at the start of the source and `\z`
  # at the end is not enough: alternation can put those anchors in different
  # branches, and an escaped backslash or an extended-mode comment can make
  # them literals instead of anchors.
  #
  # Anything the parser does not understand is treated as unanchored.
  class ValidationRegexParser
    ParseError = Class.new(StandardError)

    MAX_SOURCE_LENGTH = 100_000
    UNPROVEN_PROBLEM = "The regular expression could not be proven to anchor both ends.".freeze

    Token = Struct.new(:type, :value, :source)
    Node = Struct.new(:type, :value, :children, :source, :quantifier)

    ZERO_WIDTH_ESCAPES = %w[\\b \\B \\G].freeze
    ZERO_WIDTH_ATOMS = %w[^ $].freeze

    attr_reader :problem

    def initialize source, extended: false
      @source = source
      @extended = extended
      @tokens = []
      @index = 0
      @problem = nil
      @extended_comment_anchor = nil
      @escaped_backslash_anchor = false
    end

    def anchored?
      return unproven unless tokenize

      @tree = parse_alternation
      raise ParseError unless eof?

      anchored = !contains_reset_start?(@tree) && left_anchored?(@tree) && right_anchored?(@tree)

      if anchored
        true
      else
        @problem = build_problem
        false
      end
    rescue ParseError, ArgumentError
      unproven
    end

    private

    def tokenize
      raise ParseError if @source.nil? || @source.length > MAX_SOURCE_LENGTH

      extended_stack = [@extended]
      index = 0
      length = @source.length

      while index < length
        extended = extended_stack.last
        char = @source[index]

        if extended && char =~ /\s/
          index += 1
          next
        end

        if extended && char == "#"
          index = scan_extended_comment(index)
          next
        end

        case char
        when "\\"
          index = scan_escape(index)
        when "["
          index = scan_character_class(index)
        when "("
          index = scan_group_start(index, extended_stack, extended)
        when ")"
          index = scan_group_end(index, extended_stack)
        when "|"
          @tokens << Token.new(:alternation, nil, "|")
          index += 1
        when "*", "+", "?"
          index = scan_quantifier(index)
        when "{"
          if quantifier?(index)
            index = scan_quantifier(index)
          else
            @tokens << Token.new(:atom, char, char)
            index += 1
          end
        when "^", "$"
          @tokens << Token.new(:zero_width, char, char)
          index += 1
        when "."
          @tokens << Token.new(:atom, char, char)
          index += 1
        else
          @tokens << Token.new(:atom, char, char)
          index += 1
        end
      end

      raise ParseError unless extended_stack.length == 1
      true
    end

    def unproven
      @problem = UNPROVEN_PROBLEM
      false
    end

    def scan_extended_comment index
      start = index + 1
      index = start
      index += 1 while index < @source.length && @source[index] != "\n"
      comment = @source[start...index]

      if comment =~ /\\[AzZ]/
        @extended_comment_anchor = comment.strip
      end

      index
    end

    def scan_group_end index, extended_stack
      @tokens << Token.new(:group_end, nil, ")")
      extended_stack.pop
      raise ParseError if extended_stack.empty?
      index + 1
    end

    def scan_escape index
      escaped = @source[index + 1]
      raise ParseError if escaped.nil?

      if escaped == "\\" && ["z", "Z"].include?(@source[index + 2])
        @escaped_backslash_anchor = true
      end

      return scan_escaped_character(index, escaped) if ["x", "u", "p", "P", "g", "k", "o", "c", "C", "N"].include?(escaped)

      source = @source[index, 2]

      case escaped
      when "A"
        @tokens << Token.new(:anchor_start, nil, source)
      when "z"
        @tokens << Token.new(:anchor_end, nil, source)
      when "Z"
        @tokens << Token.new(:anchor_end_soft, nil, source)
      when "b", "B", "G"
        @tokens << Token.new(:zero_width, "\\#{escaped}", source)
      when "K"
        @tokens << Token.new(:reset_start, "\\K", source)
      else
        @tokens << Token.new(:atom, source, source)
      end

      index + 2
    end

    def scan_escaped_character index, escaped
      start = index

      case escaped
      when "x"
        if @source[index + 2] == "{"
          closing = @source.index("}", index + 3)
          raise ParseError unless closing
          index = closing + 1
        else
          index += 2
          index += 1 while index < @source.length && @source[index] =~ /[0-9A-Fa-f]/
        end
      when "u"
        if @source[index + 2] == "{"
          closing = @source.index("}", index + 3)
          raise ParseError unless closing
          index = closing + 1
        else
          index += 6
        end
      when "p", "P", "g", "k", "o", "N"
        if @source[index + 2] == "{"
          closing = @source.index("}", index + 3)
          raise ParseError unless closing
          index = closing + 1
        elsif @source[index + 2] == "<"
          closing = @source.index(">", index + 3)
          raise ParseError unless closing
          index = closing + 1
        elsif @source[index + 2] == "'"
          closing = @source.index("'", index + 3)
          raise ParseError unless closing
          index = closing + 1
        else
          index += 2
        end
      when "c", "C"
        index += 3
      else
        index += 2
      end

      source = @source[start...index]
      @tokens << Token.new(:atom, source, source)
      index
    end

    def scan_character_class index
      start = index
      index += 1
      index += 1 if @source[index] == "^"
      index += 1 if @source[index] == "]"

      while index < @source.length
        case @source[index]
        when "\\"
          index += 2
        when "["
          if @source[index + 1] == ":"
            closing = @source.index(":]", index + 2)
            raise ParseError unless closing
            index = closing + 2
          else
            index += 1
          end
        when "]"
          source = @source[start..index]
          @tokens << Token.new(:atom, source, source)
          return index + 1
        else
          index += 1
        end
      end

      raise ParseError
    end

    def scan_group_start index, extended_stack, extended
      if @source[index, 3] == "(?#"
        return scan_inline_comment(index)
      end

      kind, prefix_length, new_extended = group_prefix(index, extended)
      prefix = @source[index, prefix_length]

      if kind == :flags_only
        extended_stack[-1] = new_extended
        return index + prefix_length
      end

      @tokens << Token.new(:group_start, kind, prefix)
      extended_stack << new_extended
      index + prefix_length
    end

    def group_prefix index, extended
      if @source[index, 3] == "(?:"
        [:noncapture, 3, extended]
      elsif @source[index, 3] == "(?="
        [:lookahead, 3, extended]
      elsif @source[index, 3] == "(?!"
        [:negative_lookahead, 3, extended]
      elsif @source[index, 4] == "(?<="
        [:lookbehind, 4, extended]
      elsif @source[index, 4] == "(?<!"
        [:negative_lookbehind, 4, extended]
      elsif @source[index, 3] == "(?>"
        [:atomic, 3, extended]
      elsif @source[index, 3] == "(?<" || @source[index, 3] == "(?'"
        match = /\A\(\?(?:<([A-Za-z_]\w*)>|'([A-Za-z_]\w*)')/.match(@source[index..])
        raise ParseError unless match
        [:named, match[0].length, extended]
      elsif @source[index, 2] == "(?"
        match = /\A\(\?([imx]*)(?:-([imx]*))?([:)])/.match(@source[index..])
        raise ParseError unless match
        new_extended = apply_flags(extended, match[1], match[2])
        if match[3] == ":"
          [:flags, match[0].length, new_extended]
        else
          [:flags_only, match[0].length, new_extended]
        end
      else
        [:capture, 1, extended]
      end
    end

    def apply_flags extended, enabled, disabled
      result = extended
      result = true if enabled.include?("x")
      result = false if disabled && disabled.include?("x")
      result
    end

    def scan_inline_comment index
      index += 3
      while index < @source.length
        if @source[index] == "\\"
          index += 2
        elsif @source[index] == ")"
          return index + 1
        else
          index += 1
        end
      end

      raise ParseError
    end

    def quantifier? index
      !!/\A\{\d*(?:,\d*)?\}/.match(@source[index..])
    end

    def scan_quantifier index
      start = index

      if @source[index] == "{"
        match = /\A\{\d*(?:,\d*)?\}/.match(@source[index..])
        raise ParseError unless match
        value = match[0]
        index += value.length
      else
        value = @source[index]
        index += 1
      end

      # Lazy or possessive suffix belongs to the same quantifier.
      if ["?", "+"].include?(@source[index])
        value += @source[index]
        index += 1
      end

      @tokens << Token.new(:quantifier, value, @source[start...index])
      index
    end

    def parse_alternation
      branches = [parse_sequence]

      while peek && peek.type == :alternation
        advance
        branches << parse_sequence
      end

      if branches.length == 1
        branches.first
      else
        Node.new(:alternation, nil, branches, branches.map(&:source).join("|"), nil)
      end
    end

    def parse_sequence
      items = []

      while peek && ![:alternation, :group_end].include?(peek.type)
        if peek.type == :quantifier
          raise ParseError
        end

        items << parse_item
      end

      Node.new(:sequence, nil, items, items.map(&:source).join, nil)
    end

    def parse_item
      token = advance
      raise ParseError if token.nil?

      node = case token.type
             when :anchor_start
               Node.new(:anchor, :start, [], token.source, nil)
             when :anchor_end
               Node.new(:anchor, :end, [], token.source, nil)
             when :anchor_end_soft
               Node.new(:anchor, :end_soft, [], token.source, nil)
             when :atom
               Node.new(:atom, token.value, [], token.source, nil)
             when :zero_width
               Node.new(:zero_width, token.value, [], token.source, nil)
             when :reset_start
               Node.new(:reset_start, token.value, [], token.source, nil)
             when :group_start
               inner = parse_alternation
               expect :group_end
               Node.new(:group, token.value, [inner], "#{token.source}#{inner.source})", nil)
             else
               raise ParseError
             end

      if peek && peek.type == :quantifier
        quantifier = advance
        node = Node.new(:quantified, quantifier.value, [node], "#{node.source}#{quantifier.value}", quantifier.value)
      end

      node
    end

    def expect type
      token = advance
      raise ParseError unless token && token.type == type
    end

    def peek
      @tokens[@index]
    end

    def advance
      token = @tokens[@index]
      @index += 1
      token
    end

    def eof?
      @index == @tokens.length
    end

    def left_anchored? node
      case node.type
      when :anchor
        node.value == :start
      when :sequence
        sequence_left_anchored?(node.children)
      when :alternation
        !node.children.empty? && node.children.all? { |branch| left_anchored?(branch) }
      when :group
        group_left_anchored?(node)
      when :quantified
        quantifier_min(node.quantifier) > 0 && left_anchored?(node.children.first)
      else
        false
      end
    end

    def right_anchored? node
      case node.type
      when :anchor
        [:end, :end_soft].include?(node.value)
      when :sequence
        sequence_right_anchored?(node.children)
      when :alternation
        !node.children.empty? && node.children.all? { |branch| right_anchored?(branch) }
      when :group
        group_right_anchored?(node)
      when :quantified
        quantifier_min(node.quantifier) > 0 && right_anchored?(node.children.first)
      else
        false
      end
    end

    def sequence_left_anchored? items
      return false if items.empty?

      items.each do |item|
        return true if left_anchored?(item)
        return false unless maybe_empty?(item)
      end

      false
    end

    def sequence_right_anchored? items
      return false if items.empty?

      items.reverse_each do |item|
        return true if right_anchored?(item)
        return false unless maybe_empty?(item)
      end

      false
    end

    def group_left_anchored? node
      kind = node.value
      return false if assertion?(kind)

      left_anchored?(node.children.first)
    end

    def group_right_anchored? node
      kind = node.value
      return false if assertion?(kind)

      right_anchored?(node.children.first)
    end

    def quantifier_min quantifier
      case quantifier
      when "*", "?"
        0
      when "+"
        1
      when /\A\{(\d*)/
        $1.empty? ? 0 : $1.to_i
      else
        0
      end
    end

    def maybe_empty? node
      case node.type
      when :anchor, :zero_width, :reset_start
        true
      when :atom
        zero_width_atom?(node.value)
      when :sequence
        node.children.all? { |item| maybe_empty?(item) }
      when :alternation
        node.children.any? { |branch| maybe_empty?(branch) }
      when :group
        assertion?(node.value) || maybe_empty?(node.children.first)
      when :quantified
        quantifier_min(node.quantifier) == 0 || maybe_empty?(node.children.first)
      else
        true
      end
    end

    def zero_width_atom? value
      ZERO_WIDTH_ESCAPES.include?(value) || ZERO_WIDTH_ATOMS.include?(value)
    end

    def assertion? kind
      [:lookahead, :negative_lookahead, :lookbehind, :negative_lookbehind].include?(kind)
    end

    def build_problem
      if contains_reset_start?(@tree)
        return "The pattern uses `\\K`, which can reset the reported match start, so anchoring cannot be proven."
      end

      if !right_anchored?(@tree)
        return "The end anchor appears only in an extended-mode comment (`#{@extended_comment_anchor}`), not in the pattern, so an unverified suffix can match." if @extended_comment_anchor
        return "The `\\z` is an escaped backslash followed by a literal `z`, not an end anchor, so an unverified suffix can match." if @escaped_backslash_anchor

        return problem_for(right_leak(@tree), :end)
      end

      problem_for(left_leak(@tree), :start)
    end

    def problem_for leak, side
      return "The pattern is not anchored at the #{side}, so an unverified #{side == :end ? "suffix" : "prefix"} can match." unless leak

      case leak[:kind]
      when :optional
        if side == :end
          "The end anchor `#{leak[:source]}` is optional, so an unverified suffix can match."
        else
          "The start anchor `#{leak[:source]}` is optional, so a value with an unverified prefix can match."
        end
      when :branch
        if side == :end
          "Alternative #{leak[:index]} of #{leak[:total]} (`#{leak[:source]}`) has no end anchor, so it can match a prefix and leave an unverified suffix."
        else
          "Alternative #{leak[:index]} of #{leak[:total]} (`#{leak[:source]}`) has no start anchor, so unverified data can precede the value."
        end
      else
        if side == :end
          "`#{leak[:source]}` is not followed by an end anchor, so an unverified suffix can match."
        else
          "`#{leak[:source]}` is not preceded by a start anchor, so unverified data can precede the value."
        end
      end
    end

    def right_leak node
      case node.type
      when :anchor
        nil
      when :sequence
        sequence_leak(node.children, :end)
      when :alternation
        branch_leak(node, :end)
      when :group
        right_leak(node.children.first)
      when :quantified
        optional_anchor_leak(node, :end) || (right_anchored?(node) ? nil : right_leak(node.children.first))
      else
        { kind: :tail, source: display_source(node.source) }
      end
    end

    def left_leak node
      case node.type
      when :anchor
        nil
      when :sequence
        sequence_leak(node.children, :start)
      when :alternation
        branch_leak(node, :start)
      when :group
        left_leak(node.children.first)
      when :quantified
        optional_anchor_leak(node, :start) || (left_anchored?(node) ? nil : left_leak(node.children.first))
      else
        { kind: :tail, source: display_source(node.source) }
      end
    end

    def sequence_leak items, side
      if side == :end
        anchor_index = items.rindex { |item| right_anchored?(item) }
        tail = anchor_index ? items.drop(anchor_index + 1) : items
        tail = tail.drop_while { |item| maybe_empty?(item) } unless anchor_index
      else
        anchor_index = items.index { |item| left_anchored?(item) }
        tail = anchor_index ? items.take(anchor_index) : items
        tail = tail.reverse.drop_while { |item| maybe_empty?(item) }.reverse unless anchor_index
      end

      tail.each do |item|
        leak = nested_leak(item, side)
        return leak if leak
      end

      return nil if tail.all? { |item| maybe_empty?(item) }

      { kind: :tail, source: tail.map(&:source).join }
    end

    def nested_leak item, side
      case item.type
      when :group
        nested = side == :end ? right_leak(item.children.first) : left_leak(item.children.first)
        return nested if nested && [:branch, :optional].include?(nested[:kind])
      when :alternation
        return branch_leak(item, side)
      when :quantified
        return optional_anchor_leak(item, side)
      end

      nil
    end

    def optional_anchor_leak node, side
      return nil unless quantifier_min(node.quantifier) == 0
      return nil unless contains_anchor?(node.children.first, side)

      { kind: :optional, source: display_source(node.source) }
    end

    def display_source source
      source.to_s.gsub(/\s+/, " ").strip
    end

    def branch_leak node, side
      node.children.each_with_index do |branch, index|
        anchored = side == :end ? right_anchored?(branch) : left_anchored?(branch)
        next if anchored

        return {
          kind: :branch,
          index: index + 1,
          total: node.children.size,
          source: branch.source.empty? ? "(empty alternative)" : display_source(branch.source)
        }
      end

      nil
    end

    def contains_reset_start? node
      case node.type
      when :reset_start
        true
      when :sequence, :alternation
        node.children.any? { |child| contains_reset_start?(child) }
      when :group, :quantified
        contains_reset_start?(node.children.first)
      else
        false
      end
    end

    def contains_anchor? node, kind
      case node.type
      when :anchor
        node.value == kind
      when :sequence, :alternation
        node.children.any? { |child| contains_anchor?(child, kind) }
      when :group, :quantified
        contains_anchor?(node.children.first, kind)
      else
        false
      end
    end
  end
end
