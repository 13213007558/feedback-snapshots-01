# frozen_string_literal: true

require "nokogiri"

require_relative "sanitize/version"
require_relative "sanitize/config"
require_relative "sanitize/config/default"
require_relative "sanitize/config/restricted"
require_relative "sanitize/config/basic"
require_relative "sanitize/config/relaxed"
require_relative "sanitize/css"
require_relative "sanitize/transformers/clean_cdata"
require_relative "sanitize/transformers/clean_comment"
require_relative "sanitize/transformers/clean_css"
require_relative "sanitize/transformers/clean_doctype"
require_relative "sanitize/transformers/clean_element"

class Sanitize
  attr_reader :config

  # Matches one or more control characters that should be removed from HTML
  # before parsing, as defined by the HTML living standard.
  #
  # -   https://html.spec.whatwg.org/multipage/parsing.html#preprocessing-the-input-stream
  # -   https://infra.spec.whatwg.org/#control
  REGEX_HTML_CONTROL_CHARACTERS = /[\u0001-\u0008\u000b\u000e-\u001f\u007f-\u009f]+/u

  # Matches one or more non-characters that should be removed from HTML before
  # parsing, as defined by the HTML living standard.
  #
  # -   https://html.spec.whatwg.org/multipage/parsing.html#preprocessing-the-input-stream
  # -   https://infra.spec.whatwg.org/#noncharacter
  REGEX_HTML_NON_CHARACTERS = /[\ufdd0-\ufdef\ufffe\uffff\u{1fffe}\u{1ffff}\u{2fffe}\u{2ffff}\u{3fffe}\u{3ffff}\u{4fffe}\u{4ffff}\u{5fffe}\u{5ffff}\u{6fffe}\u{6ffff}\u{7fffe}\u{7ffff}\u{8fffe}\u{8ffff}\u{9fffe}\u{9ffff}\u{afffe}\u{affff}\u{bfffe}\u{bffff}\u{cfffe}\u{cffff}\u{dfffe}\u{dffff}\u{efffe}\u{effff}\u{ffffe}\u{fffff}\u{10fffe}\u{10ffff}]+/u

  # Matches an attribute value that could be treated by a browser as a URL with
  # a protocol prefix, such as "http:" or "javascript:". Any string of zero or
  # more characters followed by a colon is considered a match, even if the colon
  # is encoded as an entity and even if it's an incomplete entity (which IE6 and
  # Opera will still parse).
  REGEX_PROTOCOL = /\A\s*([^\/#]*?)(?::|&#0*58|&#x0*3a)/i

  # Matches one or more characters that should be stripped from HTML before
  # parsing. This is a combination of `REGEX_HTML_CONTROL_CHARACTERS` and
  # `REGEX_HTML_NON_CHARACTERS`.
  #
  # https://html.spec.whatwg.org/multipage/parsing.html#preprocessing-the-input-stream
  REGEX_UNSUITABLE_CHARS = /(?:#{REGEX_HTML_CONTROL_CHARACTERS}|#{REGEX_HTML_NON_CHARACTERS})/u

  # Thread variable used to store each thread's map of active transformer
  # contexts, keyed by Sanitize instance.
  CONTEXT_STACKS_KEY = :sanitize_transformer_contexts

  #--
  # Class Methods
  #++

  # Returns a sanitized copy of the given full _html_ document, using the
  # settings in _config_ if specified.
  #
  # When sanitizing a document, the `<html>` element must be allowlisted or an
  # error will be raised. If this is undesirable, you should probably use
  # {#fragment} instead.
  def self.document(html, config = {})
    Sanitize.new(config).document(html)
  end

  # Returns a sanitized copy of the given _html_ fragment, using the settings in
  # _config_ if specified.
  def self.fragment(html, config = {})
    Sanitize.new(config).fragment(html)
  end

  # Sanitizes the given `Nokogiri::XML::Node` instance and all its children.
  def self.node!(node, config = {})
    Sanitize.new(config).node!(node)
  end

  # Aliases for pre-3.0.0 backcompat.
  class << Sanitize
    # @deprecated Use {.document} instead.
    alias_method :clean_document, :document

    # @deprecated Use {.fragment} instead.
    alias_method :clean, :fragment

    # @deprecated Use {.node!} instead.
    alias_method :clean_node!, :node!
  end

  #--
  # Instance Methods
  #++

  # Returns a new Sanitize object initialized with the settings in _config_.
  def initialize(config = {})
    @config = Config.merge(Config::DEFAULT, config)

    @transformers = Array(@config[:transformers]).dup

    # Default transformers always run at the end of the chain, after any custom
    # transformers.
    @transformers << Transformers::CleanElement.new(@config)
    @transformers << Transformers::CleanComment

    if @config[:elements].include?("style")
      scss = Sanitize::CSS.new(config)
      @transformers << Transformers::CSS::CleanElement.new(scss)
    end

    if @config[:attributes].values.any? { |attr| attr.include?("style") }
      scss ||= Sanitize::CSS.new(config)
      @transformers << Transformers::CSS::CleanAttribute.new(scss)
    end

    @transformers << Transformers::CleanDoctype
    @transformers << Transformers::CleanCDATA

    # Compatibility view of the innermost active transformer call, kept for
    # extensions that read it directly. It's saved and restored around every
    # transformer call, so a reentrant call can't leave its node or allowlist
    # visible to the call that invoked it. Prefer #current_env, which is also
    # safe across threads.
    @transformer_config = {config: @config}
  end

  # Returns a sanitized copy of the given _html_ document.
  #
  # When sanitizing a document, the `<html>` element must be allowlisted or an
  # error will be raised. If this is undesirable, you should probably use
  # {#fragment} instead.
  def document(html)
    return "" unless html

    doc = Nokogiri::HTML5.parse(preprocess(html), **@config[:parser_options])
    node!(doc)
    to_html(doc)
  end

  # @deprecated Use {#document} instead.
  alias_method :clean_document, :document

  # Returns a sanitized copy of the given _html_ fragment.
  def fragment(html)
    return "" unless html

    frag = Nokogiri::HTML5.fragment(preprocess(html), **@config[:parser_options])
    node!(frag)
    to_html(frag)
  end

  # @deprecated Use {#fragment} instead.
  alias_method :clean, :fragment

  # Sanitizes the given `Nokogiri::XML::Node` and all its children, modifying it
  # in place.
  #
  # If _node_ is a `Nokogiri::XML::Document`, the `<html>` element must be
  # allowlisted or an error will be raised.
  def node!(node)
    raise ArgumentError unless node.is_a?(Nokogiri::XML::Node)

    if node.is_a?(Nokogiri::XML::Document)
      unless @config[:elements].include?("html")
        raise Error, 'When sanitizing a document, "<html>" must be allowlisted.'
      end
    end

    node_allowlist = Set.new

    traverse(node) do |n|
      transform_node!(n, node_allowlist)
    end

    node
  end

  # @deprecated Use {#node!} instead.
  alias_method :clean_node!, :node!

  # Returns the environment Hash of the innermost transformer call currently
  # being processed by this instance in the current thread, or `nil` if no
  # transformer is running.
  #
  # When transformers are nested (a transformer calls back into this same
  # Sanitize instance), this always refers to the innermost active call. Once
  # the inner call returns or raises, the outer call's environment becomes
  # current again.
  #
  # The returned Hash is a snapshot of the call as it was made. It contains the
  # same keys passed to the transformer (`:node`, `:node_name`,
  # `:is_allowlisted`, `:node_allowlist`, and their deprecated aliases).
  def current_env
    stack = active_context_stack
    stack&.last
  end

  # Returns the `Nokogiri::XML::Node` of the innermost transformer call
  # currently being processed by this instance in the current thread, or
  # `nil` if no transformer is running.
  def current_node
    env = current_env
    env && env[:node]
  end

  # Returns the lowercase name of the node of the innermost transformer call
  # currently being processed by this instance in the current thread, or
  # `nil` if no transformer is running.
  def current_node_name
    env = current_env
    env && env[:node_name]
  end

  private

  # Preprocesses HTML before parsing to remove undesirable Unicode chars.
  def preprocess(html)
    html = html.to_s.dup

    unless html.encoding.name == "UTF-8"
      html.encode!("UTF-8",
        invalid: :replace,
        undef: :replace)
    end

    html.gsub!(REGEX_UNSUITABLE_CHARS, "")
    html
  end

  def to_html(node)
    node.to_html(preserve_newline: true)
  end

  def transform_node!(node, node_allowlist)
    # Resolve the per-thread context stack once per traversal step instead of
    # once per transformer call.
    stack = transformer_context_stack

    @transformers.each do |transformer|
      # Build a fresh environment Hash for each transformer call. Reusing a
      # single mutable Hash would let a reentrant call (a transformer that
      # sanitizes embedded content with this same Sanitize instance) replace
      # the outer call's node, node name, allowlist, and allowlist status
      # while the outer transformer is still running.
      env = transformer_env(node, node_allowlist)

      # Keep a per-thread stack of the environments currently being
      # processed by this instance. This lets extensions query the node of
      # the innermost active transformer call (see #current_env), and it
      # gives reentrant calls a precise context to return to.
      previous_env = @transformer_config
      @transformer_config = env
      stack.push(env)

      begin
        result = transformer.call(**env)

        if result.is_a?(Hash)
          result_allowlist = result[:node_allowlist] || result[:node_whitelist]

          if result_allowlist.respond_to?(:each)
            node_allowlist.merge(result_allowlist)
          end
        end
      ensure
        # Restore even if the transformer raised, so a rescued exception
        # inside a reentrant call can't leave the inner context visible to the
        # call that invoked it.
        stack.pop
        @transformer_config = previous_env
      end
    end

    release_context_stack if stack.empty?

    node
  end

  # Returns a fresh environment Hash describing the current transformer call.
  def transformer_env(node, node_allowlist)
    is_allowlisted = node_allowlist.include?(node)

    {
      config: @config,
      is_allowlisted: is_allowlisted,
      is_whitelisted: is_allowlisted,
      node: node,
      node_name: node.name.downcase,
      node_allowlist: node_allowlist,
      node_whitelist: node_allowlist
    }
  end

  # Returns this instance's per-thread stack of active transformer
  # environments, creating it if necessary.
  #
  # Using a thread variable (rather than an instance variable) keeps
  # concurrently running sanitizations from seeing each other's contexts.
  def transformer_context_stack
    stacks = Thread.current.thread_variable_get(CONTEXT_STACKS_KEY)

    unless stacks
      stacks = {}
      Thread.current.thread_variable_set(CONTEXT_STACKS_KEY, stacks)
    end

    stacks[self] ||= []
  end

  # Returns this instance's per-thread stack of active transformer
  # environments if one exists, without creating a new one.
  def active_context_stack
    stacks = Thread.current.thread_variable_get(CONTEXT_STACKS_KEY)
    stacks && stacks[self]
  end

  # Removes this instance's now-empty stack from the current thread's map so
  # idle instances aren't retained by threads that once used them.
  def release_context_stack
    stacks = Thread.current.thread_variable_get(CONTEXT_STACKS_KEY)
    stacks&.delete(self)
  end

  # Performs top-down traversal of the given node, operating first on the node
  # itself, then traversing each child (if any) in order.
  def traverse(node, &block)
    yield node

    child = node.child

    while child
      prev = child.previous_sibling
      traverse(child, &block)

      child = if child.parent == node
        child.next_sibling
      else
        # The child was unlinked or reparented, so traverse the previous node's
        # next sibling, or the parent's first child if there is no previous
        # node.
        prev ? prev.next_sibling : node.child
      end
    end
  end

  class Error < StandardError; end
end
