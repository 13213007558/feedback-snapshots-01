module ROTP
  # Small indirection around OpenSSL::HMAC so applications can audit or
  # record every HMAC performed during OTP generation.
  #
  # A replacement must respond to +digest(digest_name, key, data)+ and
  # return the raw binary HMAC. A callable with the same three arguments is
  # also accepted by OTP.
  class HMAC
    def digest(digest_name, key, data)
      OpenSSL::HMAC.digest(OpenSSL::Digest.new(digest_name.to_s), key, data)
    end
  end
end
