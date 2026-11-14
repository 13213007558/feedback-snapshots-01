# frozen_string_literal: true

require "helper"

class IntegrationTestHelpers < Loofah::TestCase
  context ".strip_tags" do
    context "on safe markup" do
      it "strip out tags" do
        assert_equal("omgwtfbbq!!1!", Loofah::Helpers.strip_tags("<div>omgwtfbbq</div><span>!!1!</span>"))
      end
    end

    context "on hack attack" do
      it "strip escape html entities" do
        bad_shit = "&lt;script&gt;alert('evil')&lt;/script&gt;"

        assert_equal(bad_shit, Loofah::Helpers.strip_tags(bad_shit))
      end
    end
  end

  context ".sanitize" do
    context "on safe markup" do
      it "render the safe html" do
        html = "<div>omgwtfbbq</div><span>!!1!</span>"

        assert_equal(html, Loofah::Helpers.sanitize(html))
      end
    end

    context "on hack attack" do
      it "strip the unsafe tags" do
        assert_equal(
          "alert('evil')<span>w00t</span>",
          Loofah::Helpers.sanitize("<script>alert('evil')</script><span>w00t</span>"),
        )
      end

      it "strips form tags" do
        assert_equal(
          "alert('evil')<span>w00t</span>",
          Loofah::Helpers.sanitize("<script>alert('evil')</script><form action=\"/foo/bar\" method=\"post\"><input></form><span>w00t</span>"),
        )
      end
    end
  end

  context ".sanitize_css" do
    it "removes unsafe css properties" do
      assert_match(
        /display:\s*block;\s*background-color:\s*blue;/,
        Loofah::Helpers.sanitize_css("display:block;background-image:url(http://www.ragingplatypus.com/i/cam-full.jpg);background-color:blue"),
      )
    end

    it "retains allowlisted custom properties and their multi-level references" do
      assert_equal(
        "--brand:#369;--tone:var(--brand);color:var(--tone);",
        Loofah::Helpers.sanitize_css(
          "--brand:#369; --tone:var(--brand); color:var(--tone)",
          allowed_custom_properties: ["--brand", "--tone"],
        ),
      )
    end

    it "does not retain a resource reference passed indirectly through a variable" do
      style = "--leak:url(https://evil.example/x.png); --tone:var(--leak); color:var(--tone)"

      assert_empty(Loofah::Helpers.sanitize_css(style, allowed_custom_properties: ["--leak", "--tone"]))
    end
  end
end
