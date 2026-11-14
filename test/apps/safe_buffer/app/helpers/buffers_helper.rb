module BuffersHelper
  # safe_concat does not escape its argument, so the returned buffer is unsafe.
  def build_safe_concat_buffer
    buffer = "".html_safe
    buffer.safe_concat(params[:unsafe])
    buffer
  end

  # SafeBuffer#<< escapes non-SafeBuffer arguments.
  def build_plain_concat_buffer
    buffer = "".html_safe
    buffer << params[:escaped]
    buffer
  end

  # Fixed markup is not user-controlled.
  def build_static_markup_buffer
    buffer = "".html_safe
    buffer.safe_concat("<b>static</b>")
    buffer
  end

  # Both names refer to the same mutable buffer.
  def build_alias_buffer
    buffer = "".html_safe
    alias_buffer = buffer
    alias_buffer.safe_concat(params[:aliased])
    buffer
  end

  # Replacing the contents with static markup drops the unsafe state.
  def build_replaced_buffer
    buffer = "".html_safe
    buffer.safe_concat(params[:stale])
    buffer.replace("<b>replaced</b>")
    buffer
  end
end
