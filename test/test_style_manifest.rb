# frozen_string_literal: true

require_relative "common"

describe "Sanitize::StyleManifest" do
  make_my_diffs_pretty!
  parallelize_me!

  before do
    @sanitizer = Sanitize.new(Sanitize::Config::RELAXED)
  end

  describe "Sanitize#fragment_with_manifest" do
    it "should return the same HTML as #fragment" do
      input = %[<style>p { color: red; }</style><p style="color: blue">hi</p>]

      html, manifest = @sanitizer.fragment_with_manifest(input)

      _(html).must_equal @sanitizer.fragment(input)
      _(manifest).must_be_kind_of Sanitize::StyleManifest
    end

    it "should return an empty manifest for nil input" do
      html, manifest = @sanitizer.fragment_with_manifest(nil)

      _(html).must_equal ""
      _(manifest.entries).must_equal []
    end
  end

  describe "digest binding" do
    it "should hash the final sanitized text, not the input fragment" do
      input = %[<p style="color: red; position: fixed; behavior: url(x.htc)">hi</p>]

      html, manifest = @sanitizer.fragment_with_manifest(input)

      _(html).must_equal %[<p style="color: red; position: fixed; ">hi</p>]
      _(manifest.entries.size).must_equal 1

      entry = manifest.entries.first
      _(entry.kind).must_equal :attribute
      _(entry.content).must_equal "color: red; position: fixed; "
      _(entry.digest).must_equal Sanitize::StyleManifest.digest("color: red; position: fixed; ")
      # The digest must not match any prefix or fragment of the unsanitized
      # input, including the input with removed declarations still present.
      _(entry.digest).wont_equal Sanitize::StyleManifest.digest("color: red; position: fixed; behavior: url(x.htc)")
      _(entry.digest).wont_equal Sanitize::StyleManifest.digest("color: red; ")
    end

    it "should be immune to character references and newlines in the source" do
      # Character references are decoded by the HTML parser before the browser
      # computes CSP hashes, so the manifest must hash the decoded value.
      input = %[<p style="color:&#32;&#x72;ed\n;\tfont-weight: bold">hi</p>]

      html, manifest = @sanitizer.fragment_with_manifest(input)
      entry = manifest.entries.first

      _(entry.content).must_equal Nokogiri::HTML5.fragment(html).at_css("p")["style"]
      _(entry.digest).must_equal Sanitize::StyleManifest.digest(entry.content)
      _(manifest.verify(html).approved?).must_equal true
    end

    it "should hash style element text content exactly as serialized" do
      input = "<style>p {\n  color: red;\n  behavior: url(x.htc);\n}</style>"

      html, manifest = @sanitizer.fragment_with_manifest(input)
      entry = manifest.entries.first

      _(entry.kind).must_equal :element
      _(entry.content).must_equal Nokogiri::HTML5.fragment(html).at_css("style").content
      _(entry.content).wont_include "behavior"
      _(manifest.verify(html).approved?).must_equal true
    end
  end

  describe "kind separation" do
    it "should distinguish style elements from style attributes" do
      input = %[<style>p { color: red; }</style><p style="color: blue">hi</p>]

      _html, manifest = @sanitizer.fragment_with_manifest(input)

      kinds = manifest.entries.map(&:kind)
      _(kinds).must_include :element
      _(kinds).must_include :attribute

      directives = manifest.csp_directives
      _(directives["style-src-elem"].size).must_equal 1
      _(directives["style-src-attr"].size).must_equal 1
      _(directives["style-src-elem"]).wont_include directives["style-src-attr"].first
    end

    it "should generate a CSP header with quoted hash sources" do
      input = %[<style>p { color: red; }</style><p style="color: blue">hi</p>]

      _html, manifest = @sanitizer.fragment_with_manifest(input)
      header = manifest.csp_header

      _(header).must_match(/\Astyle-src-elem 'sha256-[A-Za-z0-9+\/=]+'; style-src-attr 'sha256-[A-Za-z0-9+\/=]+'\z/)
    end
  end

  describe "deduplication" do
    it "should deduplicate identical styles while keeping positions traceable" do
      input = %[<p style="color: red">a</p><p style="color: red">b</p><p style="color: blue">c</p>]

      _html, manifest = @sanitizer.fragment_with_manifest(input)

      _(manifest.entries.size).must_equal 2

      deduped = manifest.entries.find { |entry| entry.content == "color: red" }
      _(deduped.positions.size).must_equal 2
      _(deduped.positions.first).wont_equal deduped.positions.last
      _(deduped.positions.first).must_include "/@style"
    end
  end

  describe "#verify" do
    before do
      @input = %[
        <style>p { color: red; }</style>
        <p style="color: blue">a</p>
        <p style="color: blue">b</p>
      ]
      @html, @manifest = @sanitizer.fragment_with_manifest(@input)
    end

    it "should approve the unmodified output" do
      result = @manifest.verify(@html)

      _(result.approved?).must_equal true
      _(result.unauthorized).must_equal []
      _(result.missing).must_equal []
    end

    it "should approve the output when reparsed from serialized HTML" do
      _(@manifest.verify(@html.dup).approved?).must_equal true
    end

    it "should reject output where an authorized style was modified" do
      tampered = @html.sub("color: blue", "color: green")
      result = @manifest.verify(tampered)

      _(result.approved?).must_equal false
      _(result.unauthorized.size).must_equal 1
      _(result.unauthorized.first.kind).must_equal :attribute
      _(result.unauthorized.first.content).must_equal "color: green"
      # One of the two approved "color: blue" occurrences is now missing.
      _(result.missing.size).must_equal 1
      _(result.missing.first.count).must_equal 1
    end

    it "should reject output where an authorized style element was modified" do
      tampered = @html.sub("color: red", "color: orange")
      result = @manifest.verify(tampered)

      _(result.approved?).must_equal false
      _(result.unauthorized.first.kind).must_equal :element
    end

    it "should reject output with an added unauthorized style" do
      # Simulate an attacker injecting a style attribute into the sanitized
      # output after sanitization (e.g. via a template flaw). The injected
      # style was never approved, so its digest is not in the manifest.
      tampered = @html + %[<span style="color: purple">y</span>]
      result = @manifest.verify(tampered)

      _(result.approved?).must_equal false
      _(result.unauthorized.map(&:content)).must_include "color: purple"
    end

    it "should reject output where an authorized style was removed" do
      tampered = @html.sub(%[<p style="color: blue">a</p>], "")
      result = @manifest.verify(tampered)

      _(result.approved?).must_equal false
      _(result.missing.size).must_equal 1
    end

    it "should reject output where an approved style was duplicated" do
      tampered = @html + @html
      result = @manifest.verify(tampered)

      _(result.approved?).must_equal false
      _(result.unauthorized.size).must_equal 3
    end
  end

  describe "Sanitize.document_with_manifest" do
    it "should verify a full sanitized document" do
      input = "<html><head><style>body { color: black }</style></head>" +
        %[<body><p style="color: blue">hi</p></body></html>]

      html, manifest = Sanitize.document_with_manifest(input, Sanitize::Config::RELAXED)

      _(manifest.entries.size).must_equal 2
      _(manifest.verify(html).approved?).must_equal true

      tampered = html.sub("color: blue", "color: green")
      _(manifest.verify(tampered).approved?).must_equal false
    end
  end

  describe "#to_h" do
    it "should serialize kinds, digests, content, and positions" do
      input = %[<style>p { color: red; }</style><p style="color: blue">hi</p>]

      _html, manifest = @sanitizer.fragment_with_manifest(input)
      hash = manifest.to_h

      _(hash["algorithm"]).must_equal "sha256"
      _(hash["entries"].size).must_equal 2

      element_entry = hash["entries"].find { |entry| entry["kind"] == "element" }
      _(element_entry["digest"]).must_match(/\Asha256-/)
      _(element_entry["content"]).must_equal "p { color: red; }"
      _(element_entry["positions"].size).must_equal 1
    end
  end
end
