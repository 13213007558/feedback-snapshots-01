# frozen_string_literal: true

require "spec_helper"
require "cbor"
require "support/seeds"
require "webauthn/public_key/format"

RSpec.describe WebAuthn::PublicKey::Format do
  let(:ec_key) { OpenSSL::PKey::EC.generate("prime256v1") }
  let(:legacy_point) { ec_key.public_key.to_octet_string(:uncompressed) }
  let(:cose_blob) do
    key = COSE::Key::EC2.from_pkey(ec_key.public_key)
    key.alg = -7
    key.serialize
  end

  describe ".detect" do
    context "with a legacy P-256 uncompressed point" do
      it "classifies it as :legacy_p256_point" do
        expect(described_class.detect(legacy_point)).to eq(:legacy_p256_point)
      end

      it "accepts the seed U2F public key" do
        seed_key = WebAuthn::Encoders::Base64Encoder.decode(
          seeds[:u2f_migration][:stored_credential][:public_key]
        )
        expect(described_class.detect(seed_key)).to eq(:legacy_p256_point)
      end
    end

    context "with a COSE_Key" do
      it "classifies it as :cose_key" do
        expect(described_class.detect(cose_blob)).to eq(:cose_key)
      end

      it "accepts a COSE key without an explicit alg" do
        key = COSE::Key::EC2.from_pkey(ec_key.public_key)
        expect(key.alg).to be_nil
        expect(described_class.detect(key.serialize)).to eq(:cose_key)
      end
    end

    context "with an off-curve point" do
      let(:off_curve) do
        bytes = legacy_point.dup
        bytes[-1] = (bytes[-1].ord ^ 0xFF).chr
        bytes
      end

      it "does not rely only on the 0x04 indicator and rejects it" do
        expect(off_curve[0]).to eq("\x04".b)
        expect(off_curve.bytesize).to eq(65)
        expect { described_class.detect(off_curve) }
          .to raise_error(WebAuthn::PublicKey::UnrecognizedPublicKey) do |error|
            expect(error.reason).to eq(:point_not_on_curve)
          end
      end
    end

    context "with a point-shaped record of wrong length" do
      it "reports bad_point_length" do
        short = "\x04".b + legacy_point[1, 32]
        expect { described_class.detect(short) }
          .to raise_error(WebAuthn::PublicKey::UnrecognizedPublicKey) do |error|
            expect(error.reason).to eq(:bad_point_length)
          end
      end
    end

    context "with malformed COSE bytes" do
      it "reports malformed_cose" do
        expect { described_class.detect("\xA5\x01\x02garbage".b) }
          .to raise_error(WebAuthn::PublicKey::UnrecognizedPublicKey) do |error|
            expect(error.reason).to eq(:malformed_cose)
          end
      end
    end

    context "with a COSE key using another algorithm" do
      it "reports unsupported_algorithm instead of guessing" do
        key = COSE::Key::EC2.new(alg: -35, crv: 1, x: legacy_point[1, 32], y: legacy_point[33, 32])
        expect { described_class.detect(key.serialize) }
          .to raise_error(WebAuthn::PublicKey::UnrecognizedPublicKey) do |error|
            expect(error.reason).to eq(:unsupported_algorithm)
          end
      end
    end

    context "with a COSE key using another curve" do
      it "reports unsupported_curve" do
        key = COSE::Key::EC2.new(alg: -7, crv: 2, x: "\x00".b * 32, y: "\x00".b * 32)
        expect { described_class.detect(key.serialize) }
          .to raise_error(WebAuthn::PublicKey::UnrecognizedPublicKey) do |error|
            expect(error.reason).to eq(:unsupported_curve)
          end
      end
    end

    context "with an RSA COSE key" do
      it "reports unsupported_key_type" do
        rsa_key = OpenSSL::PKey::RSA.new(1024)
        cose_rsa = COSE::Key::RSA.from_pkey(rsa_key)
        expect { described_class.detect(cose_rsa.serialize) }
          .to raise_error(WebAuthn::PublicKey::UnrecognizedPublicKey) do |error|
            expect(error.reason).to eq(:unsupported_key_type)
          end
      end
    end

    context "with bad coordinate lengths" do
      it "rejects a COSE EC2 key whose coordinates are not 32 bytes" do
        map = {
          COSE::Key::Base::LABEL_KTY => COSE::Key::EC2::KTY_EC2,
          COSE::Key::CurveKey::LABEL_CRV => 1,
          COSE::Key::Base::LABEL_ALG => -7,
          COSE::Key::CurveKey::LABEL_X => legacy_point[1, 16],
          COSE::Key::EC2::LABEL_Y => legacy_point[33, 16]
        }
        expect { described_class.detect(CBOR.encode(map)) }
          .to raise_error(WebAuthn::PublicKey::UnrecognizedPublicKey) do |error|
            expect(error.reason).to eq(:bad_coordinate_length)
          end
      end
    end

    context "with empty or non-binary input" do
      it "reports :empty for nil" do
        expect { described_class.detect(nil) }
          .to raise_error(WebAuthn::PublicKey::UnrecognizedPublicKey) do |error|
            expect(error.reason).to eq(:empty)
          end
      end

      it "reports :empty for an empty string" do
        expect { described_class.detect("") }
          .to raise_error(WebAuthn::PublicKey::UnrecognizedPublicKey) do |error|
            expect(error.reason).to eq(:empty)
          end
      end

      it "reports :not_binary for non-string input" do
        expect { described_class.detect(123) }
          .to raise_error(WebAuthn::PublicKey::UnrecognizedPublicKey) do |error|
            expect(error.reason).to eq(:not_binary)
          end
      end
    end
  end

  describe ".to_cose_key" do
    it "converts a legacy point to an ES256 P-256 COSE key" do
      cose_key = described_class.to_cose_key(legacy_point)
      expect(cose_key).to be_a(COSE::Key::EC2)
      expect(cose_key.alg).to eq(-7)
      expect(cose_key.crv).to eq(1)
      expect("\x04".b + cose_key.x + cose_key.y).to eq(legacy_point)
    end

    it "normalizes an alg-less COSE key to ES256" do
      key = COSE::Key::EC2.from_pkey(ec_key.public_key)
      cose_key = described_class.to_cose_key(key.serialize)
      expect(cose_key.alg).to eq(-7)
    end

    it "preserves the underlying public key across both forms" do
      from_point = described_class.to_cose_key(legacy_point)
      from_cose = described_class.to_cose_key(cose_blob)
      expect(from_point.serialize).to eq(from_cose.serialize)
    end
  end
end
