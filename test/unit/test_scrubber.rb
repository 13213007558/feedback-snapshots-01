# frozen_string_literal: true

require "helper"

class UnitTestScrubber < Loofah::TestCase
  FRAGMENT = "<span>hello</span><span>goodbye</span>"
  FRAGMENT_NODE_COUNT = 4 # span, text, span, text
  FRAGMENT_NODE_STOP_TOP_DOWN = 2 # span, span
  DOCUMENT = "<html><head><link></link></head><body><span>hello</span><span>goodbye</span></body></html>"
  DOCUMENT_NODE_COUNT = 8 # html, head, link, body, span, text, span, text
  DOCUMENT_NODE_STOP_TOP_DOWN = 1 # html

  context "receiving a block" do
    before do
      @count = 0
    end

    context "returning CONTINUE" do
      before do
        @scrubber = Loofah::Scrubber.new do |_node|
          @count += 1
          Loofah::Scrubber::CONTINUE
        end
      end

      it "operates properly" do
        Loofah.scrub_html4_fragment(FRAGMENT, @scrubber)

        assert_equal FRAGMENT_NODE_COUNT, @count
      end

      it "operates properly" do
        Loofah.scrub_html4_document(DOCUMENT, @scrubber)

        assert_equal DOCUMENT_NODE_COUNT, @count
      end

      it "operates properly" do
        Loofah.scrub_html5_fragment(FRAGMENT, @scrubber)

        assert_equal FRAGMENT_NODE_COUNT, @count
      end if Loofah.html5_support?

      it "operates properly" do
        Loofah.scrub_html5_document(DOCUMENT, @scrubber)

        assert_equal DOCUMENT_NODE_COUNT, @count
      end if Loofah.html5_support?
    end

    context "returning STOP" do
      before do
        @scrubber = Loofah::Scrubber.new do |_node|
          @count += 1
          Loofah::Scrubber::STOP
        end
      end

      it "operates as top-down" do
        Loofah.scrub_html4_fragment(FRAGMENT, @scrubber)

        assert_equal FRAGMENT_NODE_STOP_TOP_DOWN, @count
      end

      it "operates as top-down" do
        Loofah.scrub_html4_document(DOCUMENT, @scrubber)

        assert_equal DOCUMENT_NODE_STOP_TOP_DOWN, @count
      end

      it "operates as top-down" do
        Loofah.scrub_html5_fragment(FRAGMENT, @scrubber)

        assert_equal FRAGMENT_NODE_STOP_TOP_DOWN, @count
      end if Loofah.html5_support?

      it "operates as top-down" do
        Loofah.scrub_html5_document(DOCUMENT, @scrubber)

        assert_equal DOCUMENT_NODE_STOP_TOP_DOWN, @count
      end if Loofah.html5_support?
    end

    context "returning neither CONTINUE nor STOP" do
      before do
        @scrubber = Loofah::Scrubber.new do |_node|
          @count += 1
        end
      end

      it "acts as if CONTINUE was returned" do
        Loofah.scrub_html4_fragment(FRAGMENT, @scrubber)

        assert_equal FRAGMENT_NODE_COUNT, @count
      end

      it "acts as if CONTINUE was returned" do
        Loofah.scrub_html4_document(DOCUMENT, @scrubber)

        assert_equal DOCUMENT_NODE_COUNT, @count
      end

      it "acts as if CONTINUE was returned" do
        Loofah.scrub_html5_fragment(FRAGMENT, @scrubber)

        assert_equal FRAGMENT_NODE_COUNT, @count
      end if Loofah.html5_support?

      it "acts as if CONTINUE was returned" do
        Loofah.scrub_html5_document(DOCUMENT, @scrubber)

        assert_equal DOCUMENT_NODE_COUNT, @count
      end if Loofah.html5_support?
    end

    context "not specifying direction" do
      before do
        @scrubber = Loofah::Scrubber.new do |_node|
          @count += 1
          Loofah::Scrubber::STOP
        end
      end

      it "operates as top-down" do
        Loofah.scrub_html4_fragment(FRAGMENT, @scrubber)

        assert_equal FRAGMENT_NODE_STOP_TOP_DOWN, @count
      end

      it "operates as top-down" do
        Loofah.scrub_html4_document(DOCUMENT, @scrubber)

        assert_equal DOCUMENT_NODE_STOP_TOP_DOWN, @count
      end

      it "operates as top-down" do
        Loofah.scrub_html5_fragment(FRAGMENT, @scrubber)

        assert_equal FRAGMENT_NODE_STOP_TOP_DOWN, @count
      end if Loofah.html5_support?

      it "operates as top-down" do
        Loofah.scrub_html5_document(DOCUMENT, @scrubber)

        assert_equal DOCUMENT_NODE_STOP_TOP_DOWN, @count
      end if Loofah.html5_support?
    end

    context "specifying top-down direction" do
      before do
        @scrubber = Loofah::Scrubber.new(direction: :top_down) do |_node|
          @count += 1
          Loofah::Scrubber::STOP
        end
      end

      it "operates as top-down" do
        Loofah.scrub_html4_fragment(FRAGMENT, @scrubber)

        assert_equal FRAGMENT_NODE_STOP_TOP_DOWN, @count
      end

      it "operates as top-down" do
        Loofah.scrub_html4_document(DOCUMENT, @scrubber)

        assert_equal DOCUMENT_NODE_STOP_TOP_DOWN, @count
      end

      it "operates as top-down" do
        Loofah.scrub_html5_fragment(FRAGMENT, @scrubber)

        assert_equal FRAGMENT_NODE_STOP_TOP_DOWN, @count
      end if Loofah.html5_support?

      it "operates as top-down" do
        Loofah.scrub_html5_document(DOCUMENT, @scrubber)

        assert_equal DOCUMENT_NODE_STOP_TOP_DOWN, @count
      end if Loofah.html5_support?
    end

    context "specifying bottom-up direction" do
      before do
        @scrubber = Loofah::Scrubber.new(direction: :bottom_up) do |_node|
          @count += 1
        end
      end

      it "operates as bottom-up" do
        Loofah.scrub_html4_fragment(FRAGMENT, @scrubber)

        assert_equal FRAGMENT_NODE_COUNT, @count
      end

      it "operates as bottom-up" do
        Loofah.scrub_html4_document(DOCUMENT, @scrubber)

        assert_equal DOCUMENT_NODE_COUNT, @count
      end

      it "operates as bottom-up" do
        Loofah.scrub_html5_fragment(FRAGMENT, @scrubber)

        assert_equal FRAGMENT_NODE_COUNT, @count
      end if Loofah.html5_support?

      it "operates as bottom-up" do
        Loofah.scrub_html5_document(DOCUMENT, @scrubber)

        assert_equal DOCUMENT_NODE_COUNT, @count
      end if Loofah.html5_support?
    end

    context "invalid direction" do
      it "raise an exception" do
        assert_raises(ArgumentError) do
          Loofah::Scrubber.new(direction: :quux) {}
        end
      end
    end

    context "given a block taking zero arguments" do
      before do
        @scrubber = Loofah::Scrubber.new do
          @count += 1
        end
      end

      it "works anyway, shrug" do
        Loofah.scrub_html4_fragment(FRAGMENT, @scrubber)

        assert_equal FRAGMENT_NODE_COUNT, @count
      end

      it "works anyway, shrug" do
        Loofah.scrub_html4_document(DOCUMENT, @scrubber)

        assert_equal DOCUMENT_NODE_COUNT, @count
      end

      it "works anyway, shrug" do
        Loofah.scrub_html5_fragment(FRAGMENT, @scrubber)

        assert_equal FRAGMENT_NODE_COUNT, @count
      end if Loofah.html5_support?

      it "works anyway, shrug" do
        Loofah.scrub_html5_document(DOCUMENT, @scrubber)

        assert_equal DOCUMENT_NODE_COUNT, @count
      end if Loofah.html5_support?
    end
  end

  context "defining a new Scrubber class" do
    before do
      @klass = Class.new(Loofah::Scrubber) do
        attr_accessor :count

        def initialize(direction = nil) # rubocop:disable Lint/MissingSuper
          @direction = direction
          @count = 0
        end

        def scrub(node)
          @count += 1
          Loofah::Scrubber::STOP
        end
      end
    end

    context "when not specifying direction" do
      before do
        @scrubber = @klass.new

        assert_nil @scrubber.direction
      end

      it "operates as top-down" do
        Loofah.scrub_html4_fragment(FRAGMENT, @scrubber)

        assert_equal FRAGMENT_NODE_STOP_TOP_DOWN, @scrubber.count
      end

      it "operates as top-down" do
        Loofah.scrub_html4_document(DOCUMENT, @scrubber)

        assert_equal DOCUMENT_NODE_STOP_TOP_DOWN, @scrubber.count
      end

      it "operates as top-down" do
        Loofah.scrub_html5_fragment(FRAGMENT, @scrubber)

        assert_equal FRAGMENT_NODE_STOP_TOP_DOWN, @scrubber.count
      end if Loofah.html5_support?

      it "operates as top-down" do
        Loofah.scrub_html5_document(DOCUMENT, @scrubber)

        assert_equal DOCUMENT_NODE_STOP_TOP_DOWN, @scrubber.count
      end if Loofah.html5_support?
    end

    context "when direction is specified as top_down" do
      before do
        @scrubber = @klass.new(:top_down)

        assert_equal :top_down, @scrubber.direction
      end

      it "operates as top-down" do
        Loofah.scrub_html4_fragment(FRAGMENT, @scrubber)

        assert_equal FRAGMENT_NODE_STOP_TOP_DOWN, @scrubber.count
      end

      it "operates as top-down" do
        Loofah.scrub_html4_document(DOCUMENT, @scrubber)

        assert_equal DOCUMENT_NODE_STOP_TOP_DOWN, @scrubber.count
      end

      it "operates as top-down" do
        Loofah.scrub_html5_fragment(FRAGMENT, @scrubber)

        assert_equal FRAGMENT_NODE_STOP_TOP_DOWN, @scrubber.count
      end if Loofah.html5_support?

      it "operates as top-down" do
        Loofah.scrub_html5_document(DOCUMENT, @scrubber)

        assert_equal DOCUMENT_NODE_STOP_TOP_DOWN, @scrubber.count
      end if Loofah.html5_support?
    end

    context "when direction is specified as bottom_up" do
      before do
        @scrubber = @klass.new(:bottom_up)

        assert_equal :bottom_up, @scrubber.direction
      end

      it "operates as bottom-up" do
        Loofah.scrub_html4_fragment(FRAGMENT, @scrubber)

        assert_equal FRAGMENT_NODE_COUNT, @scrubber.count
      end

      it "operates as bottom-up" do
        Loofah.scrub_html4_document(DOCUMENT, @scrubber)

        assert_equal DOCUMENT_NODE_COUNT, @scrubber.count
      end

      it "operates as bottom-up" do
        Loofah.scrub_html5_fragment(FRAGMENT, @scrubber)

        assert_equal FRAGMENT_NODE_COUNT, @scrubber.count
      end if Loofah.html5_support?

      it "operates as bottom-up" do
        Loofah.scrub_html5_document(DOCUMENT, @scrubber)

        assert_equal DOCUMENT_NODE_COUNT, @scrubber.count
      end if Loofah.html5_support?
    end
  end

  context "creating a new Scrubber class with no scrub method" do
    before do
      @klass = Class.new(Loofah::Scrubber) do
        def initialize; end # rubocop:disable Lint/MissingSuper
      end
      @scrubber = @klass.new
    end

    it "raises an exception" do
      assert_raises(Loofah::ScrubberNotFound) do
        Loofah.scrub_html4_fragment(FRAGMENT, @scrubber)
      end

      assert_raises(Loofah::ScrubberNotFound) do
        Loofah.scrub_html4_document(DOCUMENT, @scrubber)
      end

      assert_raises(Loofah::ScrubberNotFound) do
        Loofah.scrub_html5_fragment(FRAGMENT, @scrubber)
      end if Loofah.html5_support?

      assert_raises(Loofah::ScrubberNotFound) do
        Loofah.scrub_html5_document(DOCUMENT, @scrubber)
      end if Loofah.html5_support?
    end
  end

  context "traversal without recursion" do
    def build_deep_xml(depth, inner = "x")
      doc = Loofah.xml_document("<r/>")
      cursor = doc.root
      (depth - 1).times do |i|
        child = Nokogiri::XML::Node.new("n", doc)
        child["depth"] = (i + 1).to_s
        cursor.add_child(child)
        cursor = child
      end
      cursor.add_child(Nokogiri::XML::Text.new(inner, doc))
      doc
    end

    it "visits a tree much deeper than the Ruby call stack in top-down order" do
      doc = build_deep_xml(20_000)
      count = 0
      doc.root.scrub!(Loofah::Scrubber.new { |_node| count += 1 })

      assert_equal(20_001, count)
    end

    it "visits a tree much deeper than the Ruby call stack in bottom-up order" do
      doc = build_deep_xml(20_000)
      count = 0
      last_name = nil
      doc.root.scrub!(Loofah::Scrubber.new(direction: :bottom_up) do |node|
        count += 1
        last_name = node.name
      end)

      assert_equal(20_001, count)
      assert_equal("r", last_name)
    end

    it "scrubs every node of a deep tree rather than skipping subtrees" do
      doc = build_deep_xml(20_000)
      doc.root.scrub!(Loofah::Scrubber.new do |node|
        node["seen"] = "1" if node.element?
      end)

      elements = doc.root.xpath(".//*")
      assert_equal(19_999, elements.size)
      assert(elements.all? { |element| element["seen"] == "1" })
    end

    it "runs a built-in scrubber on a deep tree without exhausting the stack" do
      doc = build_deep_xml(20_000)
      script = Nokogiri::XML::Node.new("script", doc)
      script.add_child(Nokogiri::XML::Text.new("alert(1)", doc))
      leaf = doc.root.xpath(".//*[not(*)]").first
      leaf.add_child(script)

      doc.scrub!(Loofah::Scrubbers::Prune.new)

      assert_empty(doc.xpath(".//script"))
    end

    it "scrubs a deep HTML5 tree without exhausting the stack" do
      skip("HTML5 is not supported") unless Loofah.html5_support?

      depth = 4_000
      doc = Loofah.html5_document("<html><body><div></div></body></html>")
      cursor = doc.at_xpath("//div")
      (depth - 1).times do
        child = Nokogiri::XML::Node.new("div", doc)
        cursor.add_child(child)
        cursor = child
      end
      script = Nokogiri::XML::Node.new("script", doc)
      script.add_child(Nokogiri::XML::Text.new("alert(1)", doc))
      cursor.add_child(script)

      doc.scrub!(Loofah::Scrubbers::Prune.new)

      assert_empty(doc.xpath("//script"))
      assert_equal(depth, doc.xpath("//div").length)
    end
  end

  context "work budget" do
    it "visits exactly max_nodes nodes and then raises" do
      seen = 0
      scrubber = Loofah::Scrubber.new(max_nodes: 2) do |_node|
        seen += 1
        Loofah::Scrubber::CONTINUE
      end
      Loofah.html5_fragment("<span>hi</span>").scrub!(scrubber)

      assert_equal(2, seen)
    end

    it "raises BudgetExceeded instead of returning a partially scrubbed result" do
      fragment = Loofah.html5_fragment("<span>hi</span>")

      error = assert_raises(Loofah::Scrubber::BudgetExceeded) do
        fragment.scrub!(Loofah::Scrubber.new(max_nodes: 1) { |_node| Loofah::Scrubber::CONTINUE })
      end

      assert_equal(:max_nodes, error.limit_name)
      assert_equal(1, error.limit)
      assert_equal(2, error.nodes)
    end

    it "enforces max_depth and reports the offending depth" do
      doc = Loofah.xml_document("<a><b><c/></b></a>")

      error = assert_raises(Loofah::Scrubber::BudgetExceeded) do
        doc.root.scrub!(Loofah::Scrubber.new(max_depth: 1) { |_node| Loofah::Scrubber::CONTINUE })
      end

      assert_equal(:max_depth, error.limit_name)
      assert_equal(1, error.limit)
      assert_equal(2, error.depth)
    end

    it "counts nodes across the whole fragment, not once per root" do
      seen = 0
      fragment = Loofah.html5_fragment("<i>a</i><i>b</i>")

      assert_raises(Loofah::Scrubber::BudgetExceeded) do
        fragment.scrub!(Loofah::Scrubber.new(max_nodes: 2) do |_node|
          seen += 1
          Loofah::Scrubber::CONTINUE
        end)
      end
      assert_equal(2, seen)
    end

    it "limits a scrubber that dynamically adds new nodes" do
      doc = Loofah.xml_document("<a/>")

      error = assert_raises(Loofah::Scrubber::BudgetExceeded) do
        doc.root.scrub!(Loofah::Scrubber.new(max_nodes: 100) do |node|
          node.add_child("<b/>")
          Loofah::Scrubber::CONTINUE
        end)
      end

      assert_equal(:max_nodes, error.limit_name)
    end

    it "accepts limits on built-in scrubbers" do
      scrubber = Loofah::Scrubbers::Prune.new(max_nodes: 5)

      assert_equal(5, scrubber.max_nodes)
    end

    it "supports an unlimited budget explicitly" do
      scrubber = Loofah::Scrubber.new(max_nodes: nil)

      assert_nil(scrubber.max_nodes)
    end

    it "rejects invalid limits" do
      assert_raises(ArgumentError) { Loofah::Scrubber.new(max_nodes: -1) }
      assert_raises(ArgumentError) { Loofah::Scrubber.new(max_nodes: 1.5) }
      assert_raises(ArgumentError) { Loofah::Scrubber.new(max_depth: -1) }
    end

    it "defaults to a finite node budget" do
      assert_equal(Loofah::Scrubber::DEFAULT_MAX_NODES, Loofah::Scrubber.new.max_nodes)
      assert_nil(Loofah::Scrubber.new.max_depth)
    end

    it "propagates the budget through the scrub shortcuts" do
      assert_raises(Loofah::Scrubber::BudgetExceeded) do
        Loofah.scrub_html5_fragment("<span>hi</span>", Loofah::Scrubber.new(max_nodes: 1) { |_node| })
      end
    end

    it "raises a distinct error class that cannot be mistaken for success" do
      assert(Loofah::Scrubber::BudgetExceeded < RuntimeError)
      refute(Loofah::Scrubber::BudgetExceeded < Loofah::ScrubberNotFound)
    end
  end

  context "traversal over a mutating tree" do
    def record(html, direction, &action)
      fragment = Loofah.html5_fragment(html)
      events = []
      scrubber = Loofah::Scrubber.new(direction: direction) do |node|
        events << [node.name, node.parent&.name]
        action.call(node)
        Loofah::Scrubber::CONTINUE
      end
      fragment.scrub!(scrubber)
      [events, fragment.to_html]
    end

    it "still visits a node removed by an earlier sibling because it was pending" do
      events, = record("<a><b></b><c></c><d></d></a>", :top_down) do |node|
        node.next_sibling&.remove if node.name == "b"
      end

      assert_equal([["a", "#document-fragment"], ["b", "a"], ["c", nil], ["d", "a"]], events)
    end

    it "still visits a detached node in bottom-up order" do
      events, = record("<a><b></b><c></c><d></d></a>", :bottom_up) do |node|
        node.next_sibling&.remove if node.name == "b"
      end

      assert_equal([["b", "a"], ["c", nil], ["d", "a"], ["a", "#document-fragment"]], events)
    end

    it "does not visit nodes added after the parent's children were snapshotted" do
      events, = record("<a><b></b><c></c></a>", :top_down) do |node|
        node.parent.add_child("<new></new>") if node.name == "b"
      end

      assert_equal([["a", "#document-fragment"], ["b", "a"], ["c", "a"]], events)
    end

    it "descends into children created or moved during a node's own callback" do
      events, = record("<a><b><x></x></b><c><y></y></c></a>", :top_down) do |node|
        node.add_child("<m></m>") if node.name == "b"
      end

      assert_equal([["a", "#document-fragment"], ["b", "a"], ["x", "b"], ["m", "b"], ["c", "a"], ["y", "c"]], events)
    end

    it "skips a subtree after STOP and continues with snapshotted siblings" do
      fragment = Loofah.html5_fragment("<a><b><x></x></b><c><y></y></c></a>")
      events = []
      fragment.scrub!(Loofah::Scrubber.new(direction: :top_down) do |node|
        events << [node.name, node.parent&.name]
        node.name == "b" ? Loofah::Scrubber::STOP : Loofah::Scrubber::CONTINUE
      end)

      assert_equal([["a", "#document-fragment"], ["b", "a"], ["c", "a"], ["y", "c"]], events)
    end

    it "visits unwrapped children in the same order as the recursive walk" do
      events, = record("<a><b><x></x><y></y></b><c></c></a>", :bottom_up) do |node|
        if node.name == "b"
          node.before(node.children)
          node.remove
        end
      end

      assert_equal([["x", "b"], ["y", "b"], ["b", "a"], ["c", "a"], ["a", "#document-fragment"]], events)
    end

    it "visits a sibling that was removed from the tree by the previous sibling" do
      events, = record("<a><b></b><c></c><d></d></a>", :top_down) do |node|
        node.next_sibling&.remove if node.name == "b"
      end

      assert_equal([["a", "#document-fragment"], ["b", "a"], ["c", nil], ["d", "a"]], events)
    end

    it "does not flatten the whole tree before traversing it" do
      fragment = Loofah.html5_fragment("<a><b></b><c></c></a>")
      events = []
      fragment.scrub!(Loofah::Scrubber.new(direction: :top_down) do |node|
        events << node.name
        fragment.children.first.add_child("<inserted/>") if node.name == "a"
        Loofah::Scrubber::CONTINUE
      end)

      assert_equal(["a", "b", "c", "inserted"], events)
    end
  end

end
