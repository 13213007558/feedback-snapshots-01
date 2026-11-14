# frozen_string_literal: true

module Loofah
  module HTML5 # :nodoc:
    #
    #  Evaluates CSS custom properties for Scrub.scrub_css against a caller-supplied allowlist.
    #
    #  A custom property is retained only when its name is allowlisted and its declaration can be
    #  proven safe from definitions in the same declaration list. A `var()` reference that depends
    #  on anything outside that list is not trusted even when it has a fallback: the element may
    #  inherit a value for the name, so a fallback is not evidence that the fallback will be used.
    #
    #  The rules applied everywhere, including inside fallbacks, are:
    #
    #  * Custom property names are matched ASCII case-sensitively, as CSS custom property names
    #    are. The function name `var` is matched ASCII case-insensitively, as CSS function names
    #    are.
    #  * Every `var()` reference must name an allowlisted custom property that is defined in the
    #    same declaration list, and that definition must itself be provably safe. Fallbacks are
    #    validated but never make an unresolved reference acceptable.
    #  * A definition that participates in a reference cycle is invalid, and so is every declaration
    #    that depends on it.
    #  * Custom property values may contain colors, numbers, dimensions, identifiers, strings,
    #    allowed functions and nested `var()` references. URLs, `attr()` (which can read a URL from
    #    an attribute), unknown functions, at-keywords and unbalanced block delimiters are
    #    rejected.
    #
    module CustomProperties
      # A decoded custom property name. Characters that could terminate the declaration or that
      # would need an escaped spelling are not accepted in the caller's allowlist.
      CUSTOM_PROPERTY_NAME = /\A--[^\x00-\x20\x7f:;(){}\[\]"'\\]+\z/

      # `attr()` is allowed in ordinary declarations by the existing safelist, but not in a custom
      # property: `attr(data-bg url)` can obtain a URL from an otherwise harmless attribute, and a
      # custom property must not be able to launder that into a safe-looking declaration.
      VALUE_FUNCTIONS = (SafeList::ALLOWED_CSS_FUNCTIONS - ["attr"]).freeze

      SAFE_DELIMITERS = ["/", "+", "-", "*", "%", "."].freeze

      # A theme editor's variable graph is small. Bounding the depth keeps a pathological chain
      # from exhausting the Ruby stack; such a chain is simply not proven safe and is dropped.
      MAX_REFERENCE_DEPTH = 256

      # The concrete expansion is only used for validation. Cap it so a fan-out of variables
      # (`--v1: var(--v0) var(--v0)`, repeated) cannot grow exponentially; such input is dropped.
      MAX_EXPANDED_LENGTH = 4096

      # CSS-wide keywords are not ordinary identifiers in a custom property value: `inherit`,
      # `unset` and the `revert` keywords can bring in a value from outside the declaration list
      # (an ancestor element or an earlier cascade layer), so they are exactly the missing context
      # this evaluator must not assume. `initial` is harmless for a custom property, but rejecting
      # all five keeps the rule uniform.
      CONTEXT_DEPENDENT_KEYWORDS = ["inherit", "initial", "unset", "revert", "revert-layer"].freeze

      # Accepted spellings for the caller's allowlist. `allowed_custom_properties` is the
      # documented name; the others are convenience aliases for callers that already use those
      # terms.
      ALLOWLIST_OPTIONS = [:allowed_custom_properties, :custom_properties, :allowed_variables].freeze

      def self.option_value(positional, options)
        key = ALLOWLIST_OPTIONS.find { |candidate| options.key?(candidate) }
        key ? options[key] : positional
      end

      def self.allowed_names(list)
        return Set.new if list.nil?

        entries = list.is_a?(String) ? [list] : list.to_a
        entries.each_with_object(Set.new) do |entry, result|
          unless entry.is_a?(String) && CUSTOM_PROPERTY_NAME.match?(entry)
            raise ArgumentError, "invalid custom property name in allowlist: #{entry.inspect}"
          end

          result << entry
        end.freeze
      end

      def self.custom_property_name?(name)
        name.is_a?(String) && name.start_with?("--")
      end

      # True when these tokens contain a var() function at any depth, including inside an allowed
      # function's arguments.
      def self.contains_var_function?(children)
        children.any? do |child|
          case child[:node]
          when :function
            child[:name]&.downcase(:ascii) == "var" || contains_var_function?(child[:value])
          when :simple_block
            contains_var_function?(child[:value])
          else
            false
          end
        end
      end

      #
      #  Rewrites a declaration list, retaining allowlisted custom properties and applying the
      #  existing rules (plus transitive `var()` checks) to ordinary declarations.
      #
      class Evaluator
        # Internal sentinel for a token or reference that cannot be proven safe.
        class Untrusted < StandardError; end

        def initialize(style, allowed_names)
          @allowed_names = allowed_names
          @properties = Crass.parse_properties(style)
          @definitions = {}
          @trusted = {}
          @untrusted = {}

          @properties.each do |node|
            next unless node[:node] == :property

            name = node[:name]
            next unless CustomProperties.custom_property_name?(name) && @allowed_names.include?(name)

            # Within one declaration list the last declaration wins, as it does in CSS. Earlier
            # declarations are not emitted, so they cannot be mistaken for the value a later
            # reference uses.
            @definitions[name] = node
          end
        end

        def sanitize
          sanitized_tree = []

          @properties.each do |node|
            next unless node[:node] == :property

            propstring = if CustomProperties.custom_property_name?(node[:name])
              custom_property(node)
            else
              ordinary_property(node)
            end
            next unless propstring

            sanitized_node = Crass.parse_properties(propstring).first
            sanitized_tree << sanitized_node << Scrub::CRASS_SEMICOLON
          end

          Crass::Parser.stringify(sanitized_tree)
        end

        private

        def custom_property(node)
          name = node[:name]
          return nil unless @allowed_names.include?(name)
          return nil unless @definitions[name].equal?(node)

          value = strict_value(node[:children], [name])
          return nil if value.empty?
          return nil unless expanded_tokens_trusted?(node[:children], [name], custom_property: true)

          propstring = format("%s:%s", raw_property_name(node, name), value)
          propstring << Scrub::CSS_WHITESPACE << Scrub::CSS_IMPORTANT if node[:important]
          return nil unless round_trips?(propstring, name)
          return nil unless serialized_tokens_trusted?(propstring, name, [name])

          propstring
        rescue Untrusted
          nil
        end

        def ordinary_property(node)
          name = node[:name].downcase
          return nil unless allowed_ordinary_property?(name)
          # Match the existing scrub_css token prefilter: top-level URL-ish tokens reject the whole
          # declaration before any rebuilding can join tokens.
          return nil if node[:children].any? { |child| Scrub::CSS_URLISH_NODES.include?(child[:node]) }

          value = node[:children].filter_map do |child|
            case child[:node]
            when :whitespace
              Scrub::CSS_WHITESPACE
            when :string
              if Scrub::CSS_PROPERTY_STRING_WITHOUT_EMBEDDED_QUOTES.match?(child[:raw])
                Crass::Parser.stringify(child)
              end
            when :function
              function_name = child[:name].downcase(:ascii)
              if function_name == "var" || SafeList::ALLOWED_CSS_FUNCTIONS.include?(child[:name].downcase)
                Crass::Parser.stringify(child)
              end
            when :ident
              keyword = child[:value]
              if !SafeList::SHORTHAND_CSS_PROPERTIES.include?(name.split("-").first) ||
                  SafeList::ALLOWED_CSS_KEYWORDS.include?(keyword) ||
                  (keyword =~ Scrub::CSS_KEYWORDISH)
                child[:raw]
              end
            else
              child[:raw]
            end
          end.join.strip

          return nil if value.empty?

          value << Scrub::CSS_WHITESPACE << Scrub::CSS_IMPORTANT if node[:important]
          propstring = format("%s:%s", name, value)
          # Dropping tokens can join the survivors into new tokens, so keep a property only if its
          # rebuilt string survives a parse and stringify unchanged. The var checks then run on the
          # exact tokens a browser will see.
          return nil unless round_trips?(propstring, name)

          # Only a declaration that actually uses var() needs the transitive check. Without var(),
          # retain the existing scrub_css behavior exactly, including its treatment of nested
          # tokens inside allowed functions.
          sanitized_node = Crass.parse_properties(propstring).first
          if CustomProperties.contains_var_function?(sanitized_node[:children])
            return nil unless ordinary_tokens_trusted?(sanitized_node[:children])
            # The value substituted for each var() can itself join tokens into a new url() or
            # function call, so validate the substituted token stream, too.
            return nil unless expanded_tokens_trusted?(sanitized_node[:children], [], custom_property: false)
            # Serializing removed comments, which can join tokens into a new var() that was not in
            # the input. Check the token stream that will actually be written, too.
            return nil unless serialized_ordinary_tokens_trusted?(propstring, name)
          elsif Scrub.css_property_unsafe?(sanitized_node)
            return nil
          end

          propstring
        end

        def allowed_ordinary_property?(name)
          SafeList::ALLOWED_CSS_PROPERTIES.include?(name) ||
            SafeList::ALLOWED_SVG_PROPERTIES.include?(name) ||
            SafeList::SHORTHAND_CSS_PROPERTIES.include?(name.split("-").first)
        end

        # Custom property values are kept only when every token can be proven safe. Unlike an
        # ordinary declaration, dropping a token here is never attempted: an unknown token rejects
        # the definition rather than risking its neighbours joining into a different token.
        def strict_value(children, stack)
          validate_tokens(children, stack, custom_property: true)

          children.filter_map do |child|
            case child[:node]
            when :whitespace
              Scrub::CSS_WHITESPACE
            when :function, :string, :simple_block
              Crass::Parser.stringify(child)
            else
              child[:raw]
            end
          end.join.strip
        end

        def validate_tokens(children, stack, custom_property:)
          children.each do |child|
            case child[:node]
            when *Scrub::CSS_URLISH_NODES, :at_keyword, :semicolon, :"(", :")", :"{", :"}", :"[", :"]"
              raise Untrusted
            when :string
              raise Untrusted unless Scrub::CSS_PROPERTY_STRING_WITHOUT_EMBEDDED_QUOTES.match?(child[:raw])
            when :function
              validate_function(child, stack, custom_property: custom_property)
            when :simple_block
              validate_tokens(child[:value], stack, custom_property: custom_property)
            when :delim
              raise Untrusted unless SAFE_DELIMITERS.include?(child[:raw])
            when :ident
              if custom_property && CONTEXT_DEPENDENT_KEYWORDS.include?(child[:value].downcase(:ascii))
                raise Untrusted
              end
              # Identifiers are not decoded here; output uses the raw spelling.
            when :number, :percentage, :dimension, :hash, :comma, :whitespace, :unicode_range
              # Safe as a bare token.
            else
              raise Untrusted
            end
          end

          children
        end

        def validate_function(child, stack, custom_property:)
          name = child[:name]&.downcase(:ascii)
          raise Untrusted unless name

          if name == "var"
            validate_var(child, stack, custom_property: custom_property)
          else
            raise Untrusted unless SafeList::ALLOWED_CSS_FUNCTIONS.include?(name)
            raise Untrusted if custom_property && !VALUE_FUNCTIONS.include?(name)

            validate_tokens(child[:value], stack, custom_property: custom_property)
          end
        end

        def validate_var(child, stack, custom_property:)
          tokens = child[:value]
          index = skip_whitespace(tokens, 0)
          name_token = tokens[index]
          name = name_token && name_token[:node] == :ident && name_token[:value]

          unless CustomProperties.custom_property_name?(name) && CUSTOM_PROPERTY_NAME.match?(name)
            raise Untrusted
          end

          index = skip_whitespace(tokens, index + 1)
          if index < tokens.length
            raise Untrusted unless tokens[index][:node] == :comma

            fallback = tokens[(index + 1)..] || []
            # A fallback is always checked, even when the definition exists and the fallback can
            # never be selected here. It must not contain syntax we would refuse to keep.
            validate_tokens(fallback, stack, custom_property: custom_property)
          end

          # A reference is trusted only when the definition is in this declaration list and is
          # itself trusted. A fallback does not stand in for missing context.
          raise Untrusted unless definition_trusted?(name, stack)
        end

        # Ordinary declarations keep the existing token-dropping behavior, so this checks only what
        # the rebuilt output can still contain: nested URLs and `var()` calls. A nested `var()` is
        # checkable even though the surrounding allowed function was stringified wholesale.
        def ordinary_tokens_trusted?(children)
          children.each do |child|
            case child[:node]
            when *Scrub::CSS_URLISH_NODES, :at_keyword, :semicolon, :"(", :")", :"{", :"}", :"[", :"]"
              return false
            when :function
              name = child[:name]&.downcase(:ascii)
              if name == "var"
                return false unless var_shape_valid?(child)
                return false unless definition_trusted?(var_name(child), [])
                # The fallback is part of the retained function text and is validated too. It must
                # pass the same strict rules as a custom property value, because `inherit` and
                # friends could otherwise reintroduce context from outside this declaration list.
                return false unless strict_tokens_trusted?(var_fallback(child))
              elsif SafeList::ALLOWED_CSS_FUNCTIONS.include?(name)
                return false unless ordinary_tokens_trusted?(child[:value])
              else
                return false
              end
            when :simple_block
              return false unless ordinary_tokens_trusted?(child[:value])
            when :string
              return false unless Scrub::CSS_PROPERTY_STRING_WITHOUT_EMBEDDED_QUOTES.match?(child[:raw])
            when :ident
              return false if CONTEXT_DEPENDENT_KEYWORDS.include?(child[:value].downcase(:ascii))
            end
          end

          true
        end

        def serialized_ordinary_tokens_trusted?(propstring, name)
          parsed = Crass.parse_properties(propstring)
          return false unless parsed.length == 1

          node = parsed.first
          return false unless node[:node] == :property && node[:name] == name && node[:children]

          if CustomProperties.contains_var_function?(node[:children])
            ordinary_tokens_trusted?(node[:children])
          else
            !Scrub.css_property_unsafe?(node)
          end
        end

        # Substitute every var() with its trusted definition and validate the resulting concrete
        # token stream. CSS substitution is token-based, but serializing the result and tokenizing
        # it again catches a definition that supplies the pieces of a url() (for example,
        # `--name:url` used as `var(--name)(//evil.example/x)`).
        def expanded_tokens_trusted?(children, stack, custom_property:)
          expanded = Expansion.new(self, stack).to_s(children)
          return true if expanded.empty?

          tokens_safe?(Crass::Parser.new(expanded).parse_component_values, custom_property: custom_property)
        rescue Untrusted
          false
        end

        def tokens_safe?(children, custom_property:)
          children.each do |child|
            case child[:node]
            when *Scrub::CSS_URLISH_NODES, :at_keyword, :semicolon, :"(", :")", :"{", :"}", :"[", :"]"
              raise Untrusted
            when :function
              name = child[:name]&.downcase(:ascii)
              raise Untrusted unless name
              if name == "var"
                raise Untrusted unless CustomProperties.contains_var_function?([child])
              elsif custom_property
                raise Untrusted unless VALUE_FUNCTIONS.include?(name)
                tokens_safe?(child[:value], custom_property: custom_property)
              else
                raise Untrusted unless SafeList::ALLOWED_CSS_FUNCTIONS.include?(name)
                tokens_safe?(child[:value], custom_property: custom_property)
              end
            when :simple_block
              tokens_safe?(child[:value], custom_property: custom_property)
            when :string
              raise Untrusted unless Scrub::CSS_PROPERTY_STRING_WITHOUT_EMBEDDED_QUOTES.match?(child[:raw])
            when :delim
              raise Untrusted unless SAFE_DELIMITERS.include?(child[:raw])
            when :ident
              if custom_property && CONTEXT_DEPENDENT_KEYWORDS.include?(child[:value].downcase(:ascii))
                raise Untrusted
              end
            else
              # Bare numbers, dimensions, hashes, commas and whitespace are fine.
            end
          end

          true
        end

        def strict_tokens_trusted?(children)
          validate_tokens(children, [], custom_property: true)
          true
        rescue Untrusted
          false
        end

        def var_shape_valid?(child)
          tokens = child[:value]
          index = skip_whitespace(tokens, 0)
          name_token = tokens[index]
          name = name_token && name_token[:node] == :ident && name_token[:value]
          return false unless CustomProperties.custom_property_name?(name) && CUSTOM_PROPERTY_NAME.match?(name)

          index = skip_whitespace(tokens, index + 1)
          index >= tokens.length || tokens[index][:node] == :comma
        end

        def var_name(child)
          tokens = child[:value]
          index = skip_whitespace(tokens, 0)
          tokens[index][:value]
        end

        # Iterative substitution of var() references into a concrete token string. The evaluator
        # supplies the trusted definitions; this class only handles the mechanics and the size
        # limit.
        class Expansion
          def initialize(evaluator, stack)
            @evaluator = evaluator
            @stack = stack
          end

          def to_s(children)
            work = [[:children, children, 0]]
            result = String.new

            until work.empty?
              kind, value, index = work.pop
              case kind
              when :literal
                result << value
              when :children
                if index >= value.length
                  next
                end

                work << [:children, value, index + 1]
                child = value[index]
                case child[:node]
                when :whitespace
                  work << [:literal, Scrub::CSS_WHITESPACE]
                when :function
                  if child[:name]&.downcase(:ascii) == "var"
                    name = @evaluator.send(:var_name, child)
                    raise Untrusted unless @evaluator.send(:definition_trusted?, name, @stack)

                    work << [:children, @evaluator.instance_variable_get(:@definitions).fetch(name)[:children], 0]
                  else
                    work << [:literal, child[:tokens].first[:raw]]
                    work << [:children, child[:value], 0]
                    work << [:literal, ")"]
                  end
                when :simple_block
                  work << [:literal, child[:start]]
                  work << [:children, child[:value], 0]
                  work << [:literal, child[:end]]
                else
                  work << [:literal, child[:raw]]
                end
              end

              raise Untrusted if result.length > MAX_EXPANDED_LENGTH
            end

            result
          end
        end

        def var_fallback(child)
          tokens = child[:value]
          index = skip_whitespace(tokens, 0)
          index = skip_whitespace(tokens, index + 1)
          tokens[index] && tokens[index][:node] == :comma ? (tokens[(index + 1)..] || []) : []
        end

        # A definition is trusted only when validation succeeds without encountering a reference
        # back into the current stack. Failures are cached too: a failure while validating under a
        # non-empty stack always means the definition is part of a cycle with an ancestor, so it is
        # invalid in every context, not just this one. Caching keeps a diamond-shaped dependency
        # graph from being re-walked exponentially many times.
        def definition_trusted?(name, stack)
          return false unless @definitions.key?(name)
          return true if @trusted[name]
          return false if @untrusted[name]
          return false if stack.include?(name)

          @untrusted[name] = true
          validate_definition(name, stack)
          @untrusted.delete(name)
          @trusted[name] = true
        rescue Untrusted
          false
        end

        def validate_definition(name, stack)
          raise Untrusted if stack.length >= MAX_REFERENCE_DEPTH

          node = @definitions.fetch(name)
          value = strict_value(node[:children], stack + [name])
          raise Untrusted if value.empty?

          propstring = format("%s:%s", raw_property_name(node, name), value)
          propstring << Scrub::CSS_WHITESPACE << Scrub::CSS_IMPORTANT if node[:important]
          raise Untrusted unless round_trips?(propstring, name)
          raise Untrusted unless serialized_tokens_trusted?(propstring, name, stack + [name])

          true
        end

        def skip_whitespace(tokens, index)
          index += 1 while tokens[index] && tokens[index][:node] == :whitespace
          index
        end

        def raw_property_name(node, decoded_name)
          token = node[:tokens]&.first
          if token && token[:node] == :ident && token[:value] == decoded_name
            token[:raw]
          else
            decoded_name
          end
        end

        # Comments are gone from the Crass tree, so raw tokens that were separated by a comment can
        # join when serialized (`u/**/rl(x)` becomes a live `url(x)`). Validate the exact token
        # stream that will be written, too, not only the tokens that were parsed from the input.
        def serialized_tokens_trusted?(propstring, name, stack)
          parsed = Crass.parse_properties(propstring)
          return false unless parsed.length == 1

          node = parsed.first
          return false unless node[:node] == :property && node[:name] == name

          validate_tokens(node[:children], stack, custom_property: true)
          true
        rescue Untrusted
          false
        end

        def round_trips?(propstring, name)
          parsed = Crass.parse_properties(propstring)
          return false unless parsed.length == 1

          node = parsed.first
          return false unless node[:node] == :property && node[:name] == name
          return false unless Crass::Parser.stringify(node) == propstring

          true
        end
      end
    end
  end
end
