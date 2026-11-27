# frozen_string_literal: true

require "rails_helper"

# Covers the pairwise identifier as it surfaces through the signed ID Token and
# the UserInfo response, including stability across refresh (the binding is
# copied onto the new token) and the migration fallback for legacy rows.
describe "Pairwise subject in ID Token and UserInfo" do
  let(:user) { create :user }
  let(:client_a) { create :application, owner_id: 1, owner_type: "Partner" }
  let(:client_b) { create :application, owner_id: 2, owner_type: "Partner" }
  let(:salt) { "pairwise-spec-salt" }

  before do
    Doorkeeper::OpenidConnect.configure do
      issuer "dummy"
      signing_key <<~KEY
        #{OpenSSL::PKey::RSA.new(2048).to_pem}
      KEY
      subject_types_supported %i[public pairwise]
      subject_type :pairwise
      pairwise_subject_salt salt

      resource_owner_from_access_token do |access_token|
        User.find_by(id: access_token.resource_owner_id)
      end

      auth_time_from_resource_owner { |resource_owner| resource_owner.current_sign_in_at }
      subject { |resource_owner, _| resource_owner.id }
    end
  end

  let(:token_a) do
    grant = create :access_grant, application: client_a, resource_owner_id: user.id, scopes: "openid"
    Doorkeeper::OpenidConnect::SubjectIdentifier.stamp(
      grant,
      Doorkeeper::OpenidConnect::SubjectIdentifier.binding_for(client_a, user),
    )
    token = create :access_token, application: client_a, resource_owner_id: user.id, scopes: "openid"
    Doorkeeper::OpenidConnect::SubjectIdentifier.inherit(token, grant)
    token
  end

  let(:token_b) do
    grant = create :access_grant, application: client_b, resource_owner_id: user.id, scopes: "openid"
    Doorkeeper::OpenidConnect::SubjectIdentifier.stamp(
      grant,
      Doorkeeper::OpenidConnect::SubjectIdentifier.binding_for(client_b, user),
    )
    token = create :access_token, application: client_b, resource_owner_id: user.id, scopes: "openid"
    Doorkeeper::OpenidConnect::SubjectIdentifier.inherit(token, grant)
    token
  end

  it "puts the pinned pairwise subject in the signed ID Token" do
    id_token = Doorkeeper::OpenidConnect::IdToken.new(token_a, "nonce")
    decoded, = JWT.decode(
      id_token.as_jws_token,
      Doorkeeper::OpenidConnect.signing_key.keypair,
      true,
      algorithms: [Doorkeeper::OpenidConnect.signing_algorithm.to_s],
    )

    expect(decoded["sub"]).not_to eq user.id.to_s
    expect(decoded["sub"]).to eq id_token.claims[:sub]
  end

  it "makes ID Token and UserInfo agree for one partner" do
    id_sub = Doorkeeper::OpenidConnect::IdToken.new(token_a, "nonce").claims[:sub]
    ui_sub = Doorkeeper::OpenidConnect::UserInfo.new(token_a).claims[:sub]

    expect(ui_sub).to eq id_sub
  end

  it "isolates the two partners" do
    sub_a = Doorkeeper::OpenidConnect::IdToken.new(token_a, "n").claims[:sub]
    sub_b = Doorkeeper::OpenidConnect::IdToken.new(token_b, "n").claims[:sub]

    expect(sub_a).not_to eq sub_b
  end

  it "keeps the same subject when the binding is copied through a refresh" do
    original_sub = Doorkeeper::OpenidConnect::IdToken.new(token_a, "n").claims[:sub]
    refreshed = create :access_token, application: client_a, resource_owner_id: user.id, scopes: "openid"
    Doorkeeper::OpenidConnect::SubjectIdentifier.inherit(refreshed, token_a)

    expect(Doorkeeper::OpenidConnect::UserInfo.new(refreshed).claims[:sub]).to eq original_sub
  end

  context "with a token that predates the binding columns" do
    let(:legacy_token) do
      create(:access_token, application: client_a, resource_owner_id: user.id, scopes: "openid").tap do |token|
        Doorkeeper::OpenidConnect::SubjectIdentifier::BINDING_COLUMNS.each do |column|
          token.update_columns(column => nil)
        end
      end
    end

    it "derives the subject from the current policy instead of failing" do
      expect { Doorkeeper::OpenidConnect::IdToken.new(legacy_token, "n").claims }.not_to raise_error
      derived = Doorkeeper::OpenidConnect::IdToken.new(legacy_token, "n").claims[:sub]
      expected = Doorkeeper::OpenidConnect::SubjectIdentifier
                 .binding_for(client_a, user).subject

      expect(derived).to eq expected
    end
  end
end
