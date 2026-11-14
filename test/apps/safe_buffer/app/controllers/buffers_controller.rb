class BuffersController < ApplicationController
  include BuffersHelper

  def helper_safe_concat
    @buffer = build_safe_concat_buffer
  end

  def helper_plain_concat
    @buffer = build_plain_concat_buffer
  end

  def helper_static_markup
    @buffer = build_static_markup_buffer
  end

  def helper_alias
    @buffer = build_alias_buffer
  end

  def helper_replace_static
    @buffer = build_replaced_buffer
  end

  def direct_safe_concat
  end

  def direct_plain_concat
  end

  def direct_static_markup
  end

  def direct_alias
  end

  def direct_reassign
  end

  def direct_reassign_raw
  end

  def plain_escaped
  end

  def direct_buffer_argument
  end
end
