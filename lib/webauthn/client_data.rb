# frozen_string_literal: true

require "json"
require "openssl"
require "webauthn/encoder"
require "webauthn/error"

module WebAuthn
  class ClientDataMissingError < FormatError; end
  class ClientDataFormatError < FormatError; end

  class ClientData
    def initialize(client_data_json)
      @client_data_json = client_data_json
    end

    def type
      data["type"]
    end

    def challenge
      WebAuthn.standard_encoder.decode(data["challenge"])
    end

    def origin
      data["origin"]
    end

    def cross_origin
      data["crossOrigin"]
    end

    def top_origin
      data["topOrigin"]
    end

    def hash
      OpenSSL::Digest::SHA256.digest(client_data_json)
    end

    private

    attr_reader :client_data_json

    def data
      @data ||=
        if client_data_json
          parse(client_data_json)
        else
          raise ClientDataMissingError, "Client Data JSON is missing"
        end
    end

    def parse(client_data_json)
      parsed = JSON.parse(client_data_json)

      if parsed.is_a?(Hash)
        parsed
      else
        raise ClientDataFormatError, "Client Data JSON could not be parsed"
      end
    rescue JSON::ParserError
      raise ClientDataFormatError, "Client Data JSON could not be parsed"
    end
  end
end
