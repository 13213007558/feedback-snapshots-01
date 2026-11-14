# frozen_string_literal: true

require "helper"

class UnitTestEvidence < Loofah::TestCase
  def fragment(input, recorder: nil, klass: Loofah::HTML5::DocumentFragment)
    klass.parse(input, evidence: recorder)
  end

  def html4_fragment(input, recorder: nil)
    Loofah::HTML4::DocumentFragment.parse(input, evidence: recorder)
  end

  def html5?
    Loofah.html5_support?
  end

  context "recorder opt-in" do
    it "leaves the output identical when evidence is not requested" do
      input = %q(<div><script>alert(1)</script><p style="color:red;background:url(http://e/x)">ok</p></div>)
      plain = Loofah.html5_fragment(input).scrub!(:prune)
      recorded = Loofah::Evidence::Recorder.new
      with_evidence = Loofah.html5_fragment(input).scrub!(:prune, evidence: recorded)

      assert_equal plain.to_s, with_evidence.to_s
    end if Loofah.html5_support?

    it "keeps the output identical for a custom scrubber" do
      input = "<span>hello</span><p>world</p>"
      scrubber = Loofah::Scrubber.new { |node| node.name = "div" if node.name == "span" }
      plain = Loofah.html4_fragment(input).scrub!(scrubber)
      recorded = Loofah::Evidence::Recorder.new
      with_evidence = Loofah.html4_fragment(input).scrub!(scrubber, evidence: recorded)

      assert_equal plain.to_s, with_evidence.to_s
    end

    it "rejects an object that is not a recorder" do
      assert_raises(ArgumentError) do
        Loofah.html4_fragment("<p>x</p>").scrub!(:prune, evidence: Object.new)
      end
      assert_raises(ArgumentError) do
        Loofah.html4_fragment("<p>x</p>", evidence: Object.new)
      end
    end
  end

  context "reasons" do
    it "reports an element removed by prune as not allowed" do
      recorder = Loofah::Evidence::Recorder.new
      doc = fragment("<div><script>alert(1)</script><p>ok</p></div>", recorder: recorder)
      doc.scrub!(:prune, evidence: recorder)

      entry = recorder.entries.fetch(0)
      assert_equal(:removed, entry.action)
      assert_equal(:element_not_allowed, entry.reason)
      assert_equal(:element, entry.target)
      assert_match(/script/, entry.path)
      assert_match(/Loofah::Scrubbers::Prune/, entry.scrubber)
    end if Loofah.html5_support?

    it "reports strip as an unwrap and correlates the retained children" do
      recorder = Loofah::Evidence::Recorder.new
      doc = html4_fragment("<div><foo>a<b>b</b></foo></div>", recorder: recorder)
      doc.scrub!(:strip, evidence: recorder)

      entry = recorder.entries.find { |item| item.action == :unwrapped && item.path.end_with?("foo[1]") }
      refute_nil(entry)
      refute_empty(entry.retained_nodes)
      entry.retained_nodes.each do |id|
        node = recorder.node(id)
        refute_nil(node)
        assert(node.parent)
      end
    end

    it "reports an unsafe URI attribute removal without the URI" do
      recorder = Loofah::Evidence::Recorder.new
      doc = fragment(%q(<a href="javascript:alert('secret')" title="hello">click</a>), recorder: recorder)
      doc.scrub!(:prune, evidence: recorder)

      entry = recorder.entries.find { |item| item.action == :attribute_removed }
      refute_nil(entry)
      assert_equal(:unsafe_uri, entry.reason)
      assert_equal("href", entry.attribute)
      refute_match(/javascript|secret/, entry.summary)
      refute_match(/javascript|secret/, entry.to_h.to_s)
    end

    it "reports a CSS rewrite with declaration-level reasons but no values" do
      recorder = Loofah::Evidence::Recorder.new
      doc = fragment(%q(<p style="color:red;background:url(http://e/x?token=abc);evil:1">x</p>), recorder: recorder)
      doc.scrub!(:prune, evidence: recorder)

      entry = recorder.entries.find { |item| item.reason == :css_rewritten }
      refute_nil(entry)
      assert_equal(:style, entry.target)
      declarations = entry.details[:dropped_declarations]
      assert_equal(["background", "evil"], declarations.map { |declaration| declaration[:property] })
      assert_equal([:css_url, :css_property_not_allowed], declarations.map { |declaration| declaration[:reason] })
      refute_match(/token=abc/, entry.to_h.to_s)
      refute_match(/url\(/, entry.to_h.to_s)
    end

    it "reports a whitewash attribute removal by name only" do
      recorder = Loofah::Evidence::Recorder.new
      doc = fragment(%q(<div id="keep" class="drop">x</div>), recorder: recorder)
      doc.scrub!(:whitewash, evidence: recorder)

      attributes = recorder.entries.select { |item| item.action == :attribute_removed }
      assert_equal(["id", "class"], attributes.map(&:attribute))
      attributes.each { |entry| refute_match(/keep|drop/, entry.to_h.to_s) }
    end
  end

  context "parser and scrubber attribution" do
    it "never presents parser diagnostics as scrubber actions" do
      recorder = Loofah::Evidence::Recorder.new
      doc = fragment("<table><td>x</td></table>", recorder: recorder)
      doc.scrub!(:prune, evidence: recorder)

      assert_empty(recorder.entries)
      refute_empty(recorder.parser_notices)
      recorder.parser_notices.each do |notice|
        assert_equal(:parser, notice.actor)
        assert_equal(:diagnostic, notice.action)
        assert_equal(:parser, notice.target)
        refute_match(/<td>|<table>/, notice.summary)
      end
      assert_equal(:collected, recorder.parser_diagnostics_status)
    end if Loofah.html5_support?

    it "does not claim parser repairs when the document was parsed without evidence" do
      recorder = Loofah::Evidence::Recorder.new
      doc = Loofah.html5_fragment("<p>a<div>b</div>")
      doc.scrub!(:prune, evidence: recorder)

      assert_empty(recorder.entries)
      assert_empty(recorder.parser_notices)
      assert_equal(:not_collected, recorder.parser_diagnostics_status)
    end if Loofah.html5_support?

    it "attributes a custom scrubber's change to its own step with a generic reason" do
      recorder = Loofah::Evidence::Recorder.new
      doc = fragment("<div><script>alert(1)</script><span>hi</span></div>", recorder: recorder)
      scrubber = Loofah::Scrubber.new { |node| node.remove if node.name == "script" }
      doc.scrub!(scrubber, evidence: recorder)

      entry = recorder.entries.fetch(0)
      assert_equal(:scrubber, entry.actor)
      assert_equal(:custom_scrubber, entry.reason)
      assert_equal(1, entry.step)
      assert_equal("custom block", entry.scrubber)
      assert_match(/script/, entry.path)
    end if Loofah.html5_support?

    it "reports a re-parented node as a move, correlating the old and new paths" do
      recorder = Loofah::Evidence::Recorder.new
      doc = fragment("<div><section><p>x</p></section></div>", recorder: recorder)
      scrubber = Loofah::Scrubber.new { |node| node.parent = node.parent.parent if node.name == "p" }
      doc.scrub!(scrubber, evidence: recorder)

      entry = recorder.entries.fetch(0)
      assert_equal(:moved, entry.action)
      assert_equal("/div[1]/section[1]/p[1]", entry.path)
      node = recorder.final_nodes.find { |item| item[:id] == entry.node }
      assert_equal("/div[1]/p[1]", node[:path])
      assert_equal("/div[1]/section[1]/p[1]", node[:first_path])
    end if Loofah.html5_support?

    it "does not report nodes that were merely detached by an earlier step" do
      recorder = Loofah::Evidence::Recorder.new
      doc = fragment("<div><script>alert(1)</script></div>", recorder: recorder)
      first = Loofah::Scrubber.new { |node| node.remove if node.name == "script" }
      second = Loofah::Scrubber.new { |_node| nil }
      doc.scrub!(first, evidence: recorder)
      doc.scrub!(second, evidence: recorder)

      assert_equal(1, recorder.entries.length)
      assert_equal(2, recorder.steps.length)
    end if Loofah.html5_support?
  end

  context "replay and correlation" do
    def record_run(input)
      recorder = Loofah::Evidence::Recorder.new
      doc = Loofah.html5_fragment(input, evidence: recorder)
      doc.scrub!(:prune, evidence: recorder)
      doc.scrub!(Loofah::Scrubber.new { |node| node.name = "div" if node.name == "span" }, evidence: recorder)
      doc.scrub!(:nofollow, evidence: recorder)
      [doc.to_s, recorder]
    end

    it "produces the same fingerprint for the same input and scrubbers" do
      input = %q(<div><script>alert(1)</script><span>hello</span><a href="http://e/">x</a></div>)
      2.times.map { record_run(input) }.then do |runs|
        assert_equal(runs[0][0], runs[1][0])
        assert_equal(runs[0][1].fingerprint, runs[1][1].fingerprint)
      end
    end if Loofah.html5_support?

    it "correlates every surviving node id with a path in the final tree" do
      input = %q(<div><script>alert(1)</script><span>hello</span><a href="http://e/">x</a></div>)
      recorder = Loofah::Evidence::Recorder.new
      doc = Loofah.html5_fragment(input, evidence: recorder)
      doc.scrub!(:prune, evidence: recorder)
      doc.scrub!(Loofah::Scrubber.new { |node| node.name = "div" if node.name == "span" }, evidence: recorder)
      doc.scrub!(:nofollow, evidence: recorder)

      recorder.final_nodes.each do |node|
        refute_nil(doc.at_xpath(node[:path].sub(/\A\//, "./")))
      end

      entries = recorder.entries
      assert_equal(["n-0001", "n-0002", "n-0004"], entries.map(&:node))
      assert_equal([1, 2, 3], entries.map(&:step))
    end if Loofah.html5_support?

    it "includes the source digest and never the source text" do
      input = "<div><script>secret()</script></div>"
      recorder = Loofah::Evidence::Recorder.new
      Loofah.html5_fragment(input, evidence: recorder).scrub!(:prune, evidence: recorder)

      assert_equal(input.bytesize, recorder.input_metadata[:bytesize])
      assert_match(/\Asha256:[0-9a-f]{64}\z/, recorder.input_metadata[:digest])
      refute_match(/secret/, recorder.to_json)
    end if Loofah.html5_support?
  end

  context "opt-in values" do
    it "redacts credentials and query strings in URL attributes" do
      recorder = Loofah::Evidence::Recorder.new(include_values: true)
      doc = fragment(%q(<a href="https://user:pass@example.com/path?q=secret#frag">x</a>), recorder: recorder)
      doc.scrub!(:whitewash, evidence: recorder)

      entry = recorder.entries.fetch(0)
      assert_equal("https://[REDACTED]@example.com/path?[REDACTED]#[REDACTED]", entry.details[:before])
    end

    it "redacts credential-like attribute names" do
      recorder = Loofah::Evidence::Recorder.new(include_values: true)
      doc = html4_fragment(%q(<input type="text" value="hunter2">), recorder: recorder)
      doc.scrub!(:whitewash, evidence: recorder)

      attribute = recorder.entries.find { |item| item.attribute == "value" }
      assert_equal("[REDACTED]", attribute.details[:before])
    end
  end

  context "JSON output" do
    it "serializes with a schema and separate channels" do
      recorder = Loofah::Evidence::Recorder.new
      doc = fragment("<div><script>x</script></div>", recorder: recorder)
      doc.scrub!(:prune, evidence: recorder)

      payload = JSON.parse(recorder.to_json)
      assert_equal(Loofah::Evidence::SCHEMA, payload["schema"])
      assert_equal("summary", payload["redaction"])
      assert_equal("collected", payload["parser_diagnostics"])
      assert_equal(1, payload["steps"].length)
      refute_empty(payload["entries"])
      assert(payload["entries"].all? { |entry| entry["actor"] == "scrubber" })
      assert(payload["parser_notices"].all? { |entry| entry["actor"] == "parser" })
    end
  end
end
