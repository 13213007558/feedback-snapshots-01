# frozen_string_literal: true

module Loofah
  module Helpers
    class << self
      #
      #  A replacement for Rails's built-in +strip_tags+ helper.
      #
      #    Loofah::Helpers.strip_tags("<div>Hello <b>there</b></div>") # => "Hello there"
      #
      def strip_tags(string_or_io)
        Loofah.html4_fragment(string_or_io).text
      end

      #
      #  A replacement for Rails's built-in +sanitize+ helper.
      #
      #    Loofah::Helpers.sanitize("<script src=http://ha.ckers.org/xss.js></script>")
      #    # => "&lt;script src=\"http://ha.ckers.org/xss.js\"&gt;&lt;/script&gt;"
      #
      def sanitize(string_or_io)
        loofah_fragment = Loofah.html4_fragment(string_or_io)
        loofah_fragment.scrub!(:strip)
        loofah_fragment.xpath("./form").each(&:remove)
        loofah_fragment.to_s
      end

      #
      #  A replacement for Rails's built-in +sanitize_css+ helper.
      #
      #    Loofah::Helpers.sanitize_css("display:block;background-image:url(http://example.com/foo.jpg)")
      #    # => "display: block;"
      #
      #  A theme editor can retain a small set of CSS custom properties by passing their decoded
      #  names. References are only accepted when they resolve, transitively, to a provably safe
      #  definition in the same declaration list:
      #
      #    Loofah::Helpers.sanitize_css(
      #      "--brand:#369; --accent:var(--brand); color:var(--accent)",
      #      allowed_custom_properties: ["--brand", "--accent"],
      #    )
      #    # => "--brand:#369;--accent:var(--brand);color:var(--accent);"
      #
      def sanitize_css(style_string, allowed_custom_properties = nil, **options)
        if allowed_custom_properties.nil? && options.empty?
          ::Loofah::HTML5::Scrub.scrub_css(style_string)
        else
          ::Loofah::HTML5::Scrub.scrub_css(style_string, allowed_custom_properties, **options)
        end
      end

      #
      #  A helper to remove extraneous whitespace from text-ified HTML.
      #
      #  TODO: remove this in a future major-point-release.
      #
      def remove_extraneous_whitespace(string)
        Loofah.remove_extraneous_whitespace(string)
      end
    end

    module ActionView
      module ClassMethods # :nodoc:
        def full_sanitizer
          @full_sanitizer ||= ::Loofah::Helpers::ActionView::FullSanitizer.new
        end

        def safe_list_sanitizer
          @safe_list_sanitizer ||= ::Loofah::Helpers::ActionView::SafeListSanitizer.new
        end

        def white_list_sanitizer
          warn("warning: white_list_sanitizer is deprecated, please use safe_list_sanitizer instead.")
          safe_list_sanitizer
        end
      end

      #
      #  Replacement class for Rails's HTML::FullSanitizer.
      #
      #  To use by default, call this in an application initializer:
      #
      #    ActionView::Helpers::SanitizeHelper.full_sanitizer = \
      #      Loofah::Helpers::ActionView::FullSanitizer.new
      #
      #  Or, to generally opt-in to Loofah's view sanitizers:
      #
      #    Loofah::Helpers::ActionView.set_as_default_sanitizer
      #
      class FullSanitizer
        def sanitize(html, *args)
          Loofah::Helpers.strip_tags(html)
        end
      end

      #
      #  Replacement class for Rails's HTML::WhiteListSanitizer.
      #
      #  To use by default, call this in an application initializer:
      #
      #    ActionView::Helpers::SanitizeHelper.safe_list_sanitizer = \
      #      Loofah::Helpers::ActionView::SafeListSanitizer.new
      #
      #  Or, to generally opt-in to Loofah's view sanitizers:
      #
      #    Loofah::Helpers::ActionView.set_as_default_sanitizer
      #
      class SafeListSanitizer
        def sanitize(html, *args)
          Loofah::Helpers.sanitize(html)
        end

        def sanitize_css(style_string, *args, **options)
          if args.empty? && options.empty?
            Loofah::Helpers.sanitize_css(style_string)
          else
            Loofah::Helpers.sanitize_css(style_string, *args, **options)
          end
        end
      end

      WhiteListSanitizer = SafeListSanitizer
      if Object.respond_to?(:deprecate_constant)
        deprecate_constant :WhiteListSanitizer
      end
    end
  end
end
