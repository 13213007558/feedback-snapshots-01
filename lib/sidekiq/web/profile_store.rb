# frozen_string_literal: true

module Sidekiq
  class Web
    ##
    # Uploads profile data to a Firefox Profiler compatible store and returns
    # the token used to view it.
    #
    # The endpoint is only contacted when a record has been explicitly
    # approved for transfer. Tests inject their own object with the same
    # `#upload(data) => sid` interface.
    class ProfileStore
      def initialize(url)
        @uri = URI(url)
      end

      def upload(data)
        require "net/http"

        http = Net::HTTP.new(@uri.host, @uri.port)
        http.use_ssl = @uri.scheme == "https"
        request = Net::HTTP::Post.new(@uri.request_uri)
        request.body = data
        request["Accept"] = "application/vnd.firefox-profiler+json;version=1.0"
        request["User-Agent"] = "Sidekiq #{Sidekiq::VERSION} job profiler"

        resp = http.request(request)
        # https://raw.githubusercontent.com/firefox-devtools/profiler-server/master/tools/decode_jwt_payload.py
        rawjson = resp.body.split(".")[1].unpack1("m")
        Sidekiq.load_json(rawjson)["profileToken"]
      end
    end
  end
end
