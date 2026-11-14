class CleanController < ApplicationController
  def show
    # clean_text is only an HTML sanitizer: SQL warning expected
    User.where("name = '#{clean_text(params[:sql_name])}'")

    # clean_text is only an HTML sanitizer: file access warning expected
    File.read(clean_text(params[:file_name]))

    # clean_sql is a SQL sanitizer: no warning expected
    User.where("name = '#{clean_sql(params[:safe_name])}'")

    # clean_filename is a path sanitizer: no warning expected
    File.read(clean_filename(params[:safe_path]))

    # clean_sql is not a path sanitizer: file access warning expected
    File.read(clean_sql(params[:sql_path]))

    # Sanitized return value mixed back into unprocessed input:
    # warning expected
    User.where("name = '#{clean_sql(params[:name])}' AND id = #{params[:id]}")

    # clean_sql only cleans its first argument: warning expected
    User.where("name = '#{clean_sql("x", params[:other])}'")
  end
end
