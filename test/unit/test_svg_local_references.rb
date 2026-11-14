# frozen_string_literal: true

require "helper"

#
#  Acceptance for strict local references in inline SVG.
#
#  Assertions are made against the reference graph of the *re-parsed* sanitized output (which
#  elements point at which ids, and whether the target resolves), never against whether a string
#  merely starts with "#". A dangling "#missing" would pass a prefix check yet must fail here.
#
class UnitTestSvgLocalReferences < Loofah::TestCase
  # Re-runs the full pipeline and parses the serialized output again, then extracts every local
  # reference edge together with the element its id resolves to in the re-parsed tree.
  def reference_graph_after_sanitization(input)
    fragment = @klass.parse(input)
    fragment.scrub!(:strip).scrub!(:svg_local_references)

    reparsed = @klass.parse(fragment.to_s)
    Loofah::HTML5::SvgLocalReferences.reference_graph(reparsed).map do |edge|
      {
        from: edge[:node].name,
        attribute: edge[:attribute],
        id: edge[:id],
        resolves: !edge[:target].nil?,
        target: edge[:target]&.name,
      }
    end
  end

  def sanitize(input)
    @klass.parse(input).scrub!(:strip).scrub!(:svg_local_references).to_s
  end

  LOOFAH_HTML_DOCUMENT_FRAGMENT_CLASSES.each do |klass|
    describe "strict svg local references with #{klass}" do
      before do
        @klass = klass
      end

      # ----------------------------------------------------------------- surviving, valid icons

      it "keeps a complete gradient and clipping icon referenced from attributes and styles" do
        icon = <<~SVG
          <svg viewBox="0 0 10 10">
            <defs>
              <linearGradient id="grad"><stop offset="0" stop-color="red"></stop></linearGradient>
              <clipPath id="clip"><rect width="5" height="5"></rect></clipPath>
              <symbol id="icon"><circle r="3"></circle></symbol>
            </defs>
            <rect fill="url(#grad)" clip-path="url(#clip)"
                  style="fill:url(#grad);clip-path:url(#clip);stroke:red"></rect>
            <use href="#icon"></use>
          </svg>
        SVG

        graph = reference_graph_after_sanitization(icon)

        assert_equal(5, graph.size)
        assert(graph.all? { |edge| edge[:resolves] }, "every surviving edge must resolve: #{graph.inspect}")
        assert(graph.any? { |edge| edge[:from] == "rect" && edge[:attribute] == "fill" &&
                                   edge[:target]&.downcase == "lineargradient" })
        assert(graph.any? { |edge| edge[:attribute] == "style:fill" && edge[:target]&.downcase == "lineargradient" })
        assert(graph.any? { |edge| edge[:attribute] == "clip-path" && edge[:target]&.downcase == "clippath" })
        assert(graph.any? { |edge| edge[:from] == "use" && edge[:attribute] == "href" &&
                                   edge[:target]&.downcase == "symbol" })
      end

      it "keeps a paint reference with a terminal gradient on both parsers" do
        output = sanitize(%(<svg><linearGradient id="g"><stop stop-color="red"></stop></linearGradient>
                           <rect fill="url(#g)"></rect></svg>))

        assert_match(/lineargradient/i, output)
        assert_includes(output, "url(#g)")
      end

      # --------------------------------------------------------------- rejected reference shapes

      it "removes references whose target is absent from the fragment" do
        graph = reference_graph_after_sanitization(
          %(<svg><rect fill="url(#missing)"></rect><use href="#gone"></use></svg>),
        )

        assert_empty(graph.select { |edge| edge[:attribute] == "fill" })
        assert_empty(graph.select { |edge| edge[:from] == "use" })
      end

      it "treats a duplicate id as ambiguous and rejects every reference to it" do
        input = <<~SVG
          <svg>
            <linearGradient id="dup"><stop stop-color="red"></stop></linearGradient>
            <linearGradient id="dup"><stop stop-color="blue"></stop></linearGradient>
            <rect fill="url(#dup)"></rect>
          </svg>
        SVG

        graph = reference_graph_after_sanitization(input)

        assert_empty(graph.select { |edge| edge[:id] == "dup" && edge[:resolves] })
      end

      it "rejects a reference whose target type does not match the attribute" do
        graph = reference_graph_after_sanitization(
          %(<svg><rect id="r" width="5"></rect><circle clip-path="url(#r)"></circle></svg>),
        )

        assert_empty(graph.select { |edge| edge[:attribute] == "clip-path" })
      end

      it "rejects a reference chain rather than following it" do
        input = <<~SVG
          <svg>
            <linearGradient id="indirect" xlink:href="#direct"></linearGradient>
            <linearGradient id="direct"><stop stop-color="red"></stop></linearGradient>
            <rect fill="url(#indirect)"></rect>
          </svg>
        SVG

        graph = reference_graph_after_sanitization(input)

        assert_empty(graph.select { |edge| edge[:resolves] && edge[:attribute] == "fill" })
      end

      it "rejects every edge of a reference cycle" do
        input = <<~SVG
          <svg>
            <linearGradient id="a" xlink:href="#b"></linearGradient>
            <linearGradient id="b" xlink:href="#a"></linearGradient>
            <rect fill="url(#a)"></rect>
          </svg>
        SVG

        graph = reference_graph_after_sanitization(input)

        assert_empty(graph.select { |edge| edge[:resolves] })
      end

      it "does not let a removed node leave a dangling interpretation behind" do
        # the script subtree is pruned by :strip, taking its id with it; the fill reference must go too
        input = %(<svg><script id="evil"></script><rect fill="url(#evil)"></rect></svg>)

        graph = reference_graph_after_sanitization(input)

        assert_empty(graph)
      end

      # --------------------------------------------------------------- reference-bearing surfaces

      it "validates url() tokens inside style attributes, not just presentation attributes" do
        valid = sanitize(%(<svg><linearGradient id="g"><stop stop-color="red"></stop></linearGradient>
                          <rect style="fill:url(#g)"></rect></svg>))
        invalid = sanitize(%(<svg><rect style="fill:url(#ghost)"></rect></svg>))

        assert_includes(valid, "url(#g)")
        refute_match(/url\(#ghost\)/, invalid)
      end

      it "keeps an unrelated style declaration while dropping only the bad reference" do
        output = sanitize(%(<svg><rect style="fill:url(#ghost);stroke:red"></rect></svg>))

        assert_includes(output, "stroke:red")
        refute_match(/url\(#ghost\)/, output)
      end

      it "keeps a paint fallback color when the referenced paint server is rejected" do
        output = sanitize(%(<svg><rect fill="url(#ghost) red"></rect></svg>))

        assert_includes(output, 'fill="red"')
      end

      it "leaves html anchor href values outside svg untouched" do
        output = sanitize(%(<p><a href="#section">jump</a></p>))

        assert_includes(output, 'href="#section"')
      end

      it "removes a non-local svg href even when the earlier scrubber would have left it" do
        fragment = @klass.parse(%(<svg><use href="http://bad.example/x"></use></svg>))

        Loofah::HTML5::SvgLocalReferences.scrub(fragment)

        assert_empty(Loofah::HTML5::SvgLocalReferences.reference_graph(fragment)
          .select { |edge| edge[:id].to_s.start_with?("http") })
        refute_includes(fragment.to_s, "http://bad.example")
      end

      it "re-resolves references after re-parsing, so the graph is internally consistent" do
        icon = %(<svg><mask id="m"><rect width="1" height="1"></rect></mask>
                 <rect mask="url(#m)"></rect></svg>)

        graph = reference_graph_after_sanitization(icon)

        assert_equal(1, graph.size)
        assert(graph.first[:resolves])
        assert_equal("mask", graph.first[:target]&.downcase)
      end

      it "prunes an unreferenced paint server and the empty defs wrapper that held it" do
        output = sanitize(%(<svg><defs><linearGradient id="lonely"><stop stop-color="red"></stop>
                          </linearGradient></defs><rect width="5"></rect></svg>))

        refute_match(/lineargradient/i, output)
        refute_includes(output, "<defs")
        refute_includes(output, "lonely")
      end

      it "cascades pruning through a multi-level reference chain" do
        input = <<~SVG
          <svg>
            <linearGradient id="g3" xlink:href="#g2"></linearGradient>
            <linearGradient id="g2" xlink:href="#g1"></linearGradient>
            <linearGradient id="g1"><stop stop-color="red"></stop></linearGradient>
            <rect fill="url(#g3)"></rect>
          </svg>
        SVG

        output = sanitize(input)
        graph = reference_graph_after_sanitization(input)

        assert_empty(graph.select(&:resolves))
        refute_match(/lineargradient/i, output)
        refute_includes(output, "url(#g3)")
      end

      it "keeps a defs wrapper while it still holds a referenced element" do
        output = sanitize(%(<svg><defs><linearGradient id="g"><stop stop-color="red"></stop>
                          </linearGradient></defs><rect fill="url(#g)"></rect></svg>))

        assert_match(/defs/i, output)
        assert_includes(output, "url(#g)")
      end

      it "does not accept an html element id as an svg paint target" do
        input = %(<div id="g"></div><svg><rect fill="url(#g)"></rect></svg>)

        graph = reference_graph_after_sanitization(input)

        assert_empty(graph.select { |edge| edge[:resolves] })
      end

      it "rejects a local reference that hides a query or a second fragment" do
        output = sanitize(%(<svg><linearGradient id="g"><stop stop-color="red"></stop>
                      </linearGradient><rect fill="url(#g?x)"></rect></svg>))

        refute_includes(output, "url(#g?x)")
      end

      it "is safe to run on its own, removing external or malformed url() without a prior scrub" do
        external = @klass.parse(%(<svg><rect fill="url(http://bad.example/x)"></rect></svg>))
        malformed = @klass.parse(%(<svg><rect fill="url(# )"></rect></svg>))
        mixed = @klass.parse(
          %(<svg><linearGradient id="g"><stop stop-color="red"></stop></linearGradient>
             <rect fill="url(#g) url(# )"></rect></svg>),
        )

        Loofah::HTML5::SvgLocalReferences.scrub(external)
        Loofah::HTML5::SvgLocalReferences.scrub(malformed)
        Loofah::HTML5::SvgLocalReferences.scrub(mixed)

        refute_includes(external.to_s, "http://bad.example")
        refute_includes(malformed.to_s, "url(#")
        assert_includes(mixed.to_s, "url(#g)")
        refute_includes(mixed.to_s, "url(# )")
      end

      it "validates a local url in any css property, not only the svg paint properties" do
        valid = sanitize(%(<svg><mask id="m"><rect></rect></mask>
                      <rect style="background:url(#m)"></rect></svg>))
        dangling = sanitize(%(<svg><rect style="background:url(#missing)"></rect></svg>))

        assert_includes(valid, "url(#m)")
        refute_includes(dangling, "style")
      end

      it "drops an emptied style attribute rather than leaving a dangling semicolon" do
        output = sanitize(%(<svg><rect style="fill:url(#missing)"></rect></svg>))

        refute_match(/style\s*=/, output)
      end
    end
  end
end
