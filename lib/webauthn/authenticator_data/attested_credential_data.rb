# frozen_string_literal: true

require "bindata"
require "cbor"
require "cose/key"
require "webauthn/error"

module WebAuthn
  class AttestedCredentialDataFormatError < WebAuthn::Error; end

  class AuthenticatorData < BinData::Record
    class AttestedCredentialData < BinData::Record
      AAGUID_LENGTH = 16
      ZEROED_AAGUID = 0.chr * AAGUID_LENGTH

      ID_LENGTH_LENGTH = 2

      endian :big

      string :raw_aaguid, length: AAGUID_LENGTH
      bit16 :id_length
      string :id, read_length: :id_length
      count_bytes_remaining :trailing_bytes_length
      string :trailing_bytes, length: :trailing_bytes_length

      Credential =
        Struct.new(:id, :public_key, :algorithm, keyword_init: true) do
          def public_key_object
            COSE::Key.deserialize(public_key).to_pkey
          end
        end

      def self.deserialize(data)
        read(data)
      rescue EOFError, IOError
        raise AttestedCredentialDataFormatError
      end

      def valid?
        valid_credential_public_key?
      end

      def aaguid
        raw_aaguid.unpack("H8H4H4H4H12").join("-")
      end

      def credential
        @credential ||=
          if valid?
            Credential.new(id: id, public_key: public_key, algorithm: algorithm)
          end
      end

      def length
        if valid?
          AAGUID_LENGTH + ID_LENGTH_LENGTH + id_length + public_key_length
        end
      end

      private

      def algorithm
        COSE::Algorithm.find(cose_key.alg).name
      end

      def valid_credential_public_key?
        !!cose_key.alg
      end

      def cose_key
        @cose_key ||= COSE::Key.deserialize(public_key)
      end

      def public_key
        @public_key ||= trailing_bytes.snapshot.byteslice(0, public_key_length)
      end

      # Returns the number of bytes the first CBOR object in +data+ occupies.
      #
      # The length must come from the raw input, not from re-encoding the decoded
      # object: legal CBOR may use non-shortest integer encodings or a different
      # map ordering, and re-encoding would produce a shorter, canonical byte
      # string. Using that canonical length would truncate the public key and
      # make the remaining key bytes look like extension data.
      def public_key_length
        @public_key_length ||= begin
          data = trailing_bytes.snapshot

          unpacker = CBOR::Unpacker.new
          unpacker.feed(data)
          unpacker.read

          data.bytesize - unpacker.buffer.size
        rescue CBOR::UnpackError, CBOR::TypeError, EOFError
          raise AttestedCredentialDataFormatError
        end
      end
    end
  end
end
