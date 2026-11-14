module CleanHelper
  # Brakeman never executes these helpers. Their security effect comes
  # from the sanitizer descriptions in config/brakeman.yml.

  def clean_text value, unused = nil
    value.to_s.gsub("<", "&lt;").gsub(">", "&gt;")
  end

  def clean_sql value, unused = nil
    value.to_s.gsub("'", "''")
  end

  def clean_filename value
    File.basename(value.to_s)
  end
end
