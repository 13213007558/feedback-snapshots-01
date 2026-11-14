class Brakeman::CheckRenderInline < Brakeman::CheckCrossSiteScripting
  Brakeman::Checks.add self

  @description = "Checks for cross-site scripting in render calls"

  def run_check
    setup

    tracker.find_call(:target => nil, :method => :render).each do |result|
      check_render result
    end
  end

  def check_render result
    return unless original? result

    call = result[:call]

    if node_type? call, :render and
      (call.render_type == :text or call.render_type == :inline)

      unless call.render_type == :text and content_type_set? call[3]
        render_value = call[2]

        if input = has_immediate_user_input?(render_value)
          warn :result => result,
            :warning_type => "Cross-Site Scripting",
            :warning_code => :cross_site_scripting_inline,
            :message => msg("Unescaped ", msg_input(input), " rendered inline"),
            :user_input => input,
            :confidence => :high,
            :cwe_id => [79]
        elsif input = has_immediate_model?(render_value)
          warn :result => result,
            :warning_type => "Cross-Site Scripting",
            :warning_code => :cross_site_scripting_inline,
            :message => "Unescaped model attribute rendered inline",
            :user_input => input,
            :confidence => :medium,
            :cwe_id => [79]
        end
      end
    end
  end

  CONTENT_TYPES = ["text/html", "text/javascript", "application/javascript"]

  def content_type_set? opts
    if hash? opts
      content_type = last_hash_access(opts, :content_type)

      string? content_type and not html_content_type?(content_type.value)
    end
  end

  # Duplicate keys are allowed in Ruby hashes and the last one wins,
  # so the final value determines the actual response content type
  def last_hash_access hash, key
    value = nil

    hash_iterate hash do |k, v|
      if symbol? k and k.value == key
        value = v
      end
    end

    value
  end

  # Media types are case-insensitive and may include parameters,
  # e.g. "Text/HTML; charset=utf-8" is still an HTML response
  def html_content_type? content_type
    media_type = content_type.split(";".freeze, 2).first.to_s.strip.downcase

    CONTENT_TYPES.include? media_type
  end
end
