class RenderInlineController < ApplicationController
  # Final options: text=params[:bio], content_type="text/plain"
  # params[:bio] is a plain-text response body. Safe exception: no warning.
  def plain_text
    render text: params[:bio], content_type: "text/plain"
  end

  # Final options: text=params[:bio], content_type="text/html"
  # params[:bio] is served as HTML. Must warn.
  def html_text
    render text: params[:bio], content_type: "text/html"
  end

  # Final options: text=params[:bio], content_type="Text/Plain"
  # MIME types are case-insensitive, so this is still a plain-text
  # response. Safe exception: no warning.
  def plain_text_case
    render text: params[:bio], content_type: "Text/Plain"
  end

  # Final options: text=params[:bio], content_type="Text/HTML"
  # Case-insensitive match on text/html: params[:bio] is served as HTML.
  # Must warn.
  def html_text_case
    render text: params[:bio], content_type: "Text/HTML"
  end

  # Final options: text=params[:bio], content_type="text/html; charset=utf-8"
  # MIME parameters do not change the media type: params[:bio] is served
  # as HTML. Must warn.
  def html_text_with_params
    render text: params[:bio], content_type: "text/html; charset=utf-8"
  end

  # Final options: text=params[:bio], content_type="text/html"
  # Ruby keeps the LAST duplicate key, so the response is HTML even though
  # "text/plain" appears first. Must warn.
  def duplicate_content_type_html_last
    render text: params[:bio], content_type: "text/plain", content_type: "text/html"
  end

  # Final options: text=params[:bio], content_type="text/plain"
  # Last duplicate key wins, so the response is plain text even though
  # "text/html" appears first. Safe exception: no warning.
  def duplicate_content_type_plain_last
    render text: params[:bio], content_type: "text/html", content_type: "text/plain"
  end

  # Final options: text=params[:bio], content_type="text/#{params[:mime]}"
  # Interpolated MIME is not statically known; the response type cannot be
  # proven safe. Must warn (safe direction).
  def dynamic_content_type
    render text: params[:bio], content_type: "text/#{params[:mime]}"
  end

  # Final options: text=params[:bio], content_type="text/plain" (via **opts)
  # Merged keyword hash hides content_type from static analysis, so the
  # response type cannot be proven safe. Must warn (safe direction).
  def merged_options
    opts = { content_type: "text/plain" }
    render text: params[:bio], **opts
  end

  # Final options: text=params[:bio] (default content_type is text/html)
  # params[:bio] is served as HTML. Must warn.
  def default_content_type
    render text: params[:bio]
  end

  # Final options: inline=params[:template], content_type="text/plain"
  # params[:template] is executed as an ERB template. A non-HTML MIME only
  # changes the response type; it cannot remove template execution. Must warn.
  def inline_with_plain_content_type
    render inline: params[:template], content_type: "text/plain"
  end

  # Final options: inline=params[:template], content_type="text/html"
  # params[:template] is executed as an ERB template and served as HTML.
  # Must warn.
  def inline_with_html_content_type
    render inline: params[:template], content_type: "text/html"
  end
end
