# frozen_string_literal: true

require "rails_helper"

describe Doorkeeper::OpenidConnect::SubjectIdentifier do
  let(:user) { create :user }
  let(:client_a) { create :application, owner_id: 1, owner_type: "Partner" }
  let(:client_b) { create :application, owner_id: 2, owner_type: "Partner" }

  def configure_pairwise(salt: "pairwise-salt", sector: nil, fingerprint: nil)
    Doorkeeper::OpenidConnect.configure do
      issuer "dummy"
      signing_key <<~KEY
        #{OpenSSL::PKey::RSA.new(2048).to_pem}
      KEY
      subject_types_supported %i[public pairwise]
      subject_type :pairwise
      pairwise_subject_salt salt
      pairwise_sector_identifier sector if sector
      subject_client_fingerprint fingerprint if fingerprint

      resource_owner_from_access_token do |access_token|
        User.find_by(id: access_token.resource_owner_id)
      end

      subject { |resource_owner, _| resource_owner.id }
    end
  end

  def configure_public
    Doorkeeper::OpenidConnect.configure do
      issuer "dummy"
      signing_key <<~KEY
        #{OpenSSL::PKey::RSA.new(2048).to_pem}
      KEY
      subject_types_supported [:public]
      subject_type :public

      resource_owner_from_access_token do |access_token|
        User.find_by(id: access_token.resource_owner_id)
      end

      subject { |resource_owner, _| resource_owner.id }
    end
  end

  describe ".binding_for" do
    context "with a public subject type" do
      before { configure_public }

      it "returns the local subject unchanged" do
        binding = described_class.binding_for(client_a, user)

        expect(binding.public?).to be(true)
        expect(binding.subject).to eq user.id.to_s
      end

      it "gives every client the same identifier for one person" do
        expect(described_class.binding_for(client_a, user).subject)
          .to eq(described_class.binding_for(client_b, user).subject)
      end
    end

    context "with a pairwise subject type" do
      before { configure_pairwise }

      it "returns an HMAC-derived identifier distinct from the local subject" do
        binding = described_class.binding_for(client_a, user)

        expect(binding.pairwise?).to be(true)
        expect(binding.subject).not_to eq user.id.to_s
        expect(binding.subject).to match(/\A[0-9a-f]{64}\z/)
      end

      it "is deterministic for the same client and user" do
        first = described_class.binding_for(client_a, user).subject
        second = described_class.binding_for(client_a, user).subject

        expect(first).to eq second
      end

      it "isolates two partners: the same person gets unrelated identifiers" do
        sub_a = described_class.binding_for(client_a, user).subject
        sub_b = described_class.binding_for(client_b, user).subject

        expect(sub_a).not_to eq sub_b
      end

      it "defaults the sector to the client registration identity" do
        binding = described_class.binding_for(client_a, user)

        expect(binding.sector).to eq "#{client_a.uid}:Partner:1"
      end

      it "groups registrations sharing a configured sector under one identifier" do
        configure_pairwise(sector: ->(application) { application.owner_id.to_s })
        app_one = create :application, owner_id: 7, owner_type: "Partner"
        app_two = create :application, owner_id: 7, owner_type: "Partner"

        expect(described_class.binding_for(app_one, user).subject)
          .to eq(described_class.binding_for(app_two, user).subject)
      end

      it "keeps different sectors isolated even with a custom sector" do
        configure_pairwise(sector: ->(application) { application.owner_id.to_s })

        expect(described_class.binding_for(client_a, user).subject)
          .not_to eq(described_class.binding_for(client_b, user).subject)
      end
    end

    context "with configuration errors" do
      it "rejects an unknown subject type" do
        Doorkeeper::OpenidConnect.configure do
          issuer "dummy"
          subject_types_supported %i[public pairwise]
          subject_type :banana
          resource_owner_from_access_token { |_| nil }
          subject { |owner, _| owner.id }
        end

        expect { described_class.binding_for(client_a, user) }
          .to raise_error(Doorkeeper::OpenidConnect::Errors::InvalidConfiguration)
      end

      it "rejects a type that is not advertised in subject_types_supported" do
        Doorkeeper::OpenidConnect.configure do
          issuer "dummy"
          subject_types_supported [:public]
          subject_type :pairwise
          pairwise_subject_salt "salt"
          resource_owner_from_access_token { |_| nil }
          subject { |owner, _| owner.id }
        end

        expect { described_class.binding_for(client_a, user) }
          .to raise_error(Doorkeeper::OpenidConnect::Errors::InvalidConfiguration)
      end

      it "requires a salt for pairwise subjects" do
        Doorkeeper::OpenidConnect.configure do
          issuer "dummy"
          subject_types_supported %i[public pairwise]
          subject_type :pairwise
          pairwise_subject_salt nil
          resource_owner_from_access_token { |_| nil }
          subject { |owner, _| owner.id }
        end

        expect { described_class.binding_for(client_a, user) }
          .to raise_error(Doorkeeper::OpenidConnect::Errors::InvalidConfiguration)
      end
    end
  end

  describe "stamping and reading a binding" do
    before { configure_pairwise }

    it "pins the policy onto a persisted record and reads it back" do
      grant = create :access_grant, application: client_a, resource_owner_id: user.id
      binding = described_class.binding_for(client_a, user)

      described_class.stamp(grant, binding)
      grant.reload

      stored = described_class.read(grant)
      expect(stored.subject).to eq binding.subject
      expect(stored.subject_type).to eq "pairwise"
      expect(stored.sector).to eq binding.sector
      expect(stored.fingerprint).to eq binding.fingerprint
    end

    it "copies a binding from a source record onto a new record" do
      grant = create :access_grant, application: client_a, resource_owner_id: user.id
      described_class.stamp(grant, described_class.binding_for(client_a, user))
      token = create :access_token, application: client_a, resource_owner_id: user.id

      described_class.inherit(token, grant)
      token.reload

      expect(described_class.read(token).subject).to eq described_class.read(grant).subject
    end
  end

  describe ".problem_for / .enforce!" do
    before { configure_pairwise }

    it "accepts a record whose stored fingerprint matches the client policy" do
      grant = create :access_grant, application: client_a, resource_owner_id: user.id
      described_class.stamp(grant, described_class.binding_for(client_a, user))

      expect(described_class.problem_for(grant, client_a, user)).to be_nil
      expect(described_class.enforce!(grant, client_a, user)).to be(true)
    end

    it "requires reauthorization after the client registration changes owner" do
      grant = create :access_grant, application: client_a, resource_owner_id: user.id
      described_class.stamp(grant, described_class.binding_for(client_a, user))
      client_a.update!(owner_id: 99)

      expect(described_class.problem_for(grant, client_a, user))
        .to eq :reauthorization_required
      expect { described_class.enforce!(grant, client_a, user) }
        .to raise_error(Doorkeeper::OpenidConnect::Errors::ReauthorizationRequired) do |error|
          expect(error.type).to eq :invalid_grant
          expect(error.response.status).to eq :bad_request
          expect(error.response.body[:error]).to eq :invalid_grant
          expect(error.response.body[:error_description]).to be_present
        end
    end

    it "requires reauthorization after the pairwise salt rotates" do
      grant = create :access_grant, application: client_a, resource_owner_id: user.id
      described_class.stamp(grant, described_class.binding_for(client_a, user))

      configure_pairwise(salt: "rotated-salt")

      expect(described_class.problem_for(grant, client_a, user))
        .to eq :reauthorization_required
    end

    context "with a record that predates the binding columns" do
      let(:legacy_grant) { create :access_grant, application: client_a, resource_owner_id: user.id }

      before do
        # Simulate a row written before the migration ran.
        legacy_grant.update_columns(
          described_class::SUBJECT_COLUMN => nil,
          described_class::FINGERPRINT_COLUMN => nil,
        )
      end

      it "is accepted while the client stays public" do
        configure_public

        expect(described_class.read(legacy_grant)).to be_nil
        expect(described_class.problem_for(legacy_grant, client_a, user)).to be_nil
      end

      it "is rejected for a pairwise client" do
        expect(described_class.problem_for(legacy_grant, client_a, user))
          .to eq :reauthorization_required
      end
    end
  end
end
