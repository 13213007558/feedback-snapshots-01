# frozen_string_literal: true

require_relative "common"

describe "Transformers" do
  make_my_diffs_pretty!
  parallelize_me!

  it "should receive a complete env Hash as input" do
    Sanitize.fragment("<SPAN>foo</SPAN>",
      foo: :bar,
      transformers: lambda { |env|
        return unless env[:node].element?

        _(env[:config][:foo]).must_equal :bar
        _(env[:is_allowlisted]).must_equal false
        _(env[:is_whitelisted]).must_equal env[:is_allowlisted]
        _(env[:node]).must_be_kind_of Nokogiri::XML::Node
        _(env[:node_name]).must_equal "span"
        _(env[:node_allowlist]).must_be_kind_of Set
        _(env[:node_allowlist]).must_be_empty
        _(env[:node_whitelist]).must_equal env[:node_allowlist]
      })
  end

  it "should traverse all node types, including the fragment itself" do
    nodes = []

    Sanitize.fragment("<div>foo</div><!--bar--><script>cdata!</script>",
      transformers: proc { |env| nodes << env[:node_name] })

    _(nodes).must_equal %w[
      #document-fragment div text text text comment script text
    ]
  end

  it "should perform top-down traversal" do
    nodes = []

    Sanitize.fragment("<div><span><strong>foo</strong></span><b></b></div><p>bar</p>",
      transformers: proc { |env| nodes << env[:node_name] if env[:node].element? })

    _(nodes).must_equal %w[div span strong b p]
  end

  it "should allowlist nodes in the node allowlist" do
    _(Sanitize.fragment('<div class="foo">foo</div><span>bar</span>',
      transformers: [
        proc { |env|
          {node_allowlist: [env[:node]]} if env[:node_name] == "div"
        },

        proc { |env|
          _(env[:is_allowlisted]).must_equal false unless env[:node_name] == "div"
          _(env[:is_allowlisted]).must_equal true if env[:node_name] == "div"
          _(env[:node_allowlist]).must_include env[:node] if env[:node_name] == "div"
          _(env[:is_whitelisted]).must_equal env[:is_allowlisted]
          _(env[:node_whitelist]).must_equal env[:node_allowlist]
        }
      ])).must_equal '<div class="foo">foo</div>bar'
  end

  it "should clear the node allowlist after each fragment" do
    called = false

    Sanitize.fragment("<div>foo</div>",
      transformers: proc { |env| {node_allowlist: [env[:node]]} })

    Sanitize.fragment("<div>foo</div>",
      transformers: proc { |env|
        called = true
        _(env[:is_allowlisted]).must_equal false
        _(env[:is_whitelisted]).must_equal env[:is_allowlisted]
        _(env[:node_allowlist]).must_be_empty
        _(env[:node_whitelist]).must_equal env[:node_allowlist]
      })

    _(called).must_equal true
  end

  it "should accept a method transformer" do
    def transformer(env)
    end
    _(Sanitize.fragment("<div>foo</div>", transformers: method(:transformer)))
      .must_equal(" foo ")
  end

  describe "Image allowlist transformer" do
    require "uri"

    image_allowlist_transformer = lambda do |env|
      # Ignore everything except <img> elements.
      return unless env[:node_name] == "img"

      node = env[:node]
      image_uri = URI.parse(node["src"])

      # Only allow relative URLs or URLs with the example.com domain. The
      # image_uri.host.nil? check ensures that protocol-relative URLs like
      # "//evil.com/foo.jpg" are not allowed.
      unless image_uri.host == "example.com"
        unless image_uri.host.nil? && image_uri.relative?
          node.unlink # `Nokogiri::XML::Node#unlink` removes a node from the document
        end
      end
    end

    before do
      @s = Sanitize.new(Sanitize::Config.merge(Sanitize::Config::RELAXED,
        transformers: image_allowlist_transformer))
    end

    it "should allow images with relative URLs" do
      input = '<img src="/foo/bar.jpg">'
      _(@s.fragment(input)).must_equal(input)
    end

    it "should allow images at the example.com domain" do
      input = '<img src="http://example.com/foo/bar.jpg">'
      _(@s.fragment(input)).must_equal(input)

      input = '<img src="https://example.com/foo/bar.jpg">'
      _(@s.fragment(input)).must_equal(input)

      input = '<img src="//example.com/foo/bar.jpg">'
      _(@s.fragment(input)).must_equal(input)
    end

    it "should not allow images at other domains" do
      input = '<img src="http://evil.com/foo/bar.jpg">'
      _(@s.fragment(input)).must_equal("")

      input = '<img src="https://evil.com/foo/bar.jpg">'
      _(@s.fragment(input)).must_equal("")

      input = '<img src="//evil.com/foo/bar.jpg">'
      _(@s.fragment(input)).must_equal("")

      input = '<img src="http://subdomain.example.com/foo/bar.jpg">'
      _(@s.fragment(input)).must_equal("")
    end
  end

  describe "YouTube transformer" do
    youtube_transformer = lambda do |env|
      node = env[:node]
      node_name = env[:node_name]

      # Don't continue if this node is already allowlisted or is not an element.
      return if env[:is_allowlisted] || !node.element?

      # Don't continue unless the node is an iframe.
      return unless node_name == "iframe"

      # Verify that the video URL is actually a valid YouTube video URL.
      return unless %r{\A(?:https?:)?//(?:www\.)?youtube(?:-nocookie)?\.com/}.match?(node["src"])

      # We're now certain that this is a YouTube embed, but we still need to run
      # it through a special Sanitize step to ensure that no unwanted elements or
      # attributes that don't belong in a YouTube embed can sneak in.
      Sanitize.node!(node, {
        elements: %w[iframe],

        attributes: {
          "iframe" => %w[allowfullscreen frameborder height src width]
        }
      })

      # Now that we're sure that this is a valid YouTube embed and that there are
      # no unwanted elements or attributes hidden inside it, we can tell Sanitize
      # to allowlist the current node.
      {node_allowlist: [node]}
    end

    it "should allow HTTP YouTube video embeds" do
      input = '<iframe width="420" height="315" src="http://www.youtube.com/embed/QH2-TGUlwu4" frameborder="0" allowfullscreen bogus="bogus"><script>alert()</script></iframe>'

      _(Sanitize.fragment(input, transformers: youtube_transformer))
        .must_equal '<iframe width="420" height="315" src="http://www.youtube.com/embed/QH2-TGUlwu4" frameborder="0" allowfullscreen=""></iframe>'
    end

    it "should allow HTTPS YouTube video embeds" do
      input = '<iframe width="420" height="315" src="https://www.youtube.com/embed/QH2-TGUlwu4" frameborder="0" allowfullscreen bogus="bogus"><script>alert()</script></iframe>'

      _(Sanitize.fragment(input, transformers: youtube_transformer))
        .must_equal '<iframe width="420" height="315" src="https://www.youtube.com/embed/QH2-TGUlwu4" frameborder="0" allowfullscreen=""></iframe>'
    end

    it "should allow protocol-relative YouTube video embeds" do
      input = '<iframe width="420" height="315" src="//www.youtube.com/embed/QH2-TGUlwu4" frameborder="0" allowfullscreen bogus="bogus"><script>alert()</script></iframe>'

      _(Sanitize.fragment(input, transformers: youtube_transformer))
        .must_equal '<iframe width="420" height="315" src="//www.youtube.com/embed/QH2-TGUlwu4" frameborder="0" allowfullscreen=""></iframe>'
    end

    it "should allow privacy-enhanced YouTube video embeds" do
      input = '<iframe width="420" height="315" src="https://www.youtube-nocookie.com/embed/QH2-TGUlwu4" frameborder="0" allowfullscreen bogus="bogus"><script>alert()</script></iframe>'

      _(Sanitize.fragment(input, transformers: youtube_transformer))
        .must_equal '<iframe width="420" height="315" src="https://www.youtube-nocookie.com/embed/QH2-TGUlwu4" frameborder="0" allowfullscreen=""></iframe>'
    end

    it "should not allow non-YouTube video embeds" do
      input = '<iframe width="420" height="315" src="http://www.fake-youtube.com/embed/QH2-TGUlwu4" frameborder="0" allowfullscreen></iframe>'

      _(Sanitize.fragment(input, transformers: youtube_transformer))
        .must_equal("")
    end
  end

  describe "DOM modification transformer" do
    b_to_strong_tag_transformer = lambda do |env|
      node = env[:node]
      node_name = env[:node_name]

      if node_name == "b"
        node.name = "strong"
      end
    end

    it "should allow the <b> tag to be changed to a <strong> tag" do
      input = "<b>text</b>"

      _(Sanitize.fragment(input, elements: ["strong"], transformers: b_to_strong_tag_transformer))
        .must_equal "<strong>text</strong>"
    end
  end

  describe "reentrant transformers" do
    make_my_diffs_pretty!

    # A transformer that sanitizes embedded content by calling back into the
    # same Sanitize instance it belongs to.
    class ReentrantTestTransformer
      attr_accessor :sanitizer

      def initialize(&block)
        @block = block
      end

      def call(env)
        @block.call(env, sanitizer)
      end
    end

    def reentrant_transformer(&block)
      ReentrantTestTransformer.new(&block)
    end

    # Returns the transformer call the sanitizer currently considers active.
    # `current_env` is the supported API; older Sanitize versions exposed the
    # same information through `@transformer_config`.
    def current_view(sanitizer)
      if sanitizer.respond_to?(:current_env)
        sanitizer.current_env
      else
        sanitizer.instance_variable_get(:@transformer_config)
      end
    end

    it "restores the outer node for transformers that run after a nested call" do
      sanitizer = nil
      inner_depth = 0
      observations = []

      reenter = reentrant_transformer do |env, s|
        next unless env[:node_name] == "div"
        next unless env[:node].element? && !env[:node].key?("data-nested")

        env[:node]["data-nested"] = "1"
        inner_depth += 1
        begin
          s.node!(env[:node])
        ensure
          inner_depth -= 1
        end

        view = current_view(s)
        observations << [:after_nested, env[:node].name, env[:node_name], view[:node].name, view[:node_name], view[:node_allowlist].include?(env[:node])]
      end

      recorder = lambda do |env|
        if inner_depth.zero? && %w[div span].include?(env[:node_name])
          observations << [:later, env[:node].name, env[:node_name], env[:node].parent&.name]
        end
      end

      sanitizer = Sanitize.new(
        elements: %w[div span],
        attributes: {"div" => ["data-nested"]},
        transformers: [reenter, recorder]
      )
      reenter.sanitizer = sanitizer

      sanitizer.fragment("<div><span>x</span></div>")

      after_nested = observations.find { |o| o.first == :after_nested }
      _(after_nested).must_equal [:after_nested, "div", "div", "div", "div", false]

      later = observations.select { |o| o.first == :later }
      _(later).must_include [:later, "div", "div", "#document-fragment"]
      _(later).must_include [:later, "span", "span", "div"]
    end

    it "keeps the inner and outer allowlists separate when the inner call allowlists nodes" do
      sanitizer = nil
      inner_depth = 0
      outer_view = nil

      transformer = reentrant_transformer do |env, s|
        node = env[:node]

        if inner_depth.positive?
          # The inner pass trusts everything it sees.
          {node_allowlist: [node]}
        elsif env[:node_name] == "div" && node.element? && !node.key?("data-nested")
          node["data-nested"] = "1"
          inner_depth += 1
          begin
            s.node!(node)
          ensure
            inner_depth -= 1
          end

          # The current view must describe the outer call, not the last node
          # visited by the nested call.
          view = current_view(s)
          outer_view = [view[:node].name, view[:node_name], view[:node_allowlist].include?(node), view[:node_allowlist].size]

          # Explicitly propagate the outer allowlist (empty) and never the
          # inner one.
          {node_allowlist: view[:node_allowlist]}
        end
      end

      sanitizer = Sanitize.new(
        elements: %w[div],
        remove_contents: true,
        attributes: {"div" => ["data-nested"]},
        transformers: [transformer]
      )
      transformer.sanitizer = sanitizer

      # The inner pass allowlists every node, including <script> and <img>,
      # but the outer config allows only <div>, so they must still be removed.
      _(sanitizer.fragment(%(<div><script>alert(1)</script><img src="x" onerror="alert(2)"></div>)))
        .must_equal %(<div data-nested="1"></div>)

      _(outer_view).must_equal ["div", "div", false, 0]
    end

    it "restores the outer context when a nested call raises" do
      sanitizer = nil
      inner_depth = 0
      reraised = nil
      recovered = nil

      transformer = reentrant_transformer do |env, s|
        if inner_depth.positive?
          raise "inner boom" if env[:node_name] == "span"
        elsif env[:node_name] == "div" && env[:node].element? && !env[:node].key?("data-nested")
          env[:node]["data-nested"] = "1"
          inner_depth += 1
          begin
            s.node!(env[:node])
          rescue => e
            reraised = e
          ensure
            inner_depth -= 1
          end
          view = current_view(s)
          recovered = [view[:node].name, view[:node_name], view[:node_allowlist].include?(view[:node])]
        end
      end

      sanitizer = Sanitize.new(
        elements: %w[div span],
        attributes: {"div" => ["data-nested"]},
        transformers: [transformer]
      )
      transformer.sanitizer = sanitizer

      sanitizer.fragment("<div><span>x</span></div>")

      _(reraised).must_be_kind_of RuntimeError
      _(reraised.message).must_equal "inner boom"
      _(recovered).must_equal ["div", "div", false]
    end

    it "exposes the innermost active transformer context" do
      sanitizer = nil
      seen = []

      transformer = reentrant_transformer do |env, s|
        next unless env[:node_name] == "div"
        next unless env[:node].element? && !env[:node].key?("data-nested")

        env[:node]["data-nested"] = "1"
        seen << [:outer_before, s.current_node_name, s.current_node.name]

        nested = Nokogiri::HTML5.fragment("<span>inner</span>")
        s.node!(nested)
        seen << [:outer_after, s.current_node_name, s.current_node.name]
      end

      sanitizer = Sanitize.new(
        elements: %w[div span],
        attributes: {"div" => ["data-nested"]},
        transformers: [transformer]
      )
      transformer.sanitizer = sanitizer

      sanitizer.fragment("<div>outer</div>")

      _(seen).must_equal [
        [:outer_before, "div", "div"],
        [:outer_after, "div", "div"]
      ]
      _(sanitizer.current_env).must_be_nil
      _(sanitizer.current_node).must_be_nil
      _(sanitizer.current_node_name).must_be_nil
    end

    it "gives each concurrent thread its own transformer context" do
      sanitizer = nil
      mutex = Mutex.new
      mismatches = []

      transformer = reentrant_transformer do |env, _s|
        next unless env[:node].element?
        next unless env[:node_name] == Thread.current[:expected_name]

        mismatches << [Thread.current[:expected_name], env[:node_name]] unless env[:node].name.downcase == env[:node_name]
      end

      sanitizer = Sanitize.new(elements: %w[div span b], transformers: [transformer])
      transformer.sanitizer = sanitizer

      cases = {
        "div" => "<div><b>x</b></div>",
        "span" => "<span>x</span>",
        "b" => "<b>x</b>"
      }

      threads = cases.map do |name, html|
        Thread.new do
          Thread.current[:expected_name] = name
          100.times { sanitizer.fragment(html) }
        end
      end
      threads.each(&:join)

      mutex.synchronize { _(mismatches).must_be_empty }
      _(sanitizer.current_env).must_be_nil
    end
  end
end
