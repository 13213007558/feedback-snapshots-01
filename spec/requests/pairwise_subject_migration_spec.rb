# frozen_string_literal: true

require "rails_helper"

# End-to-end coverage of the pairwise subject identifier migration:
#
#   * two local clients (partners) that must see mutually isolated subjects;
#   * one authorization issued *before* the deployment migrates to pairwise;
#   * a first authorization under the new policy interleaved with a refresh of
#     the old authorization;
#   * a UserInfo request that must agree with the signed ID token;
#   * the explicit re-authorization path when a stored policy no longer matches
#     the client (client registration/ownership change or salt rotation).
#
# Every subject assertion is made on the actually signed ID token (decoded with
# the configured JWK) and on the UserInfo JSON body, not on the model directly.
describe "Pairwise subject identifier migration", type: :request do
  let(:user) { create :user }
  let(:client_a) { create :application, owner_id: 1, owner_type: "Partner" }
  let(:client_b) { create :application, owner_id: 2, owner_type: "Partner" }
  let(:salt) { "pairwise-migration-salt" }

  def configure_oidc(subject_type:, pairwise_salt: salt)
    Doorkeeper.configure do
      optional_scopes :openid
      grant_flows %w[authorization_code client_credentials implicit_oidc refresh_token]
      use_refresh_token
    end

    Doorkeeper::OpenidConnect.configure do
      issuer "dummy"
      signing_key <<~KEY
        #{OpenSSL::PKey::RSA.new(2048).to_pem}
      KEY
      subject_types_supported %i[public pairwise]
      subject_type subject_type
      pairwise_subject_salt pairwise_salt

      resource_owner_from_access_token do |access_token|
        User.find_by(id: access_token.resource_owner_id)
      end

      auth_time_from_resource_owner { |resource_owner| resource_owner.current_sign_in_at }

      subject { |resource_owner, _| resource_owner.id }
    end
  end

  def decode_id_token(jwt)
    JWT.decode(
      jwt,
      Doorkeeper::OpenidConnect.signing_key.keypair,
      true,
      algorithms: [Doorkeeper::OpenidConnect.signing_algorithm.to_s],
    ).first
  end

  # Builds an authorization grant the way the authorization endpoint would,
  # then exchanges it at the real token endpoint.
  def authorize_and_exchange(client, nonce: SecureRandom.hex)
    grant = create :access_grant,
                   application: client,
                   resource_owner_id: user.id,
                   scopes: "openid"
    create :openid_request, access_grant: grant, nonce: nonce

    post "/oauth/token", params: {
      grant_type: "authorization_code",
      code: grant.plaintext_token,
      redirect_uri: grant.redirect_uri,
      client_id: client.uid,
      client_secret: client.plaintext_secret,
    }

    expect(response).to have_http_status(:ok), response.body
    JSON.parse(response.body)
  end

  def refresh(client, refresh_token)
    post "/oauth/token", params: {
      grant_type: "refresh_token",
      refresh_token: refresh_token,
      client_id: client.uid,
      client_secret: client.plaintext_secret,
    }
  end

  def userinfo(access_token)
    get "/oauth/userinfo", params: { access_token: access_token }
    expect(response).to have_http_status(:ok), response.body
    JSON.parse(response.body)
  end

  describe "two clients under pairwise policy" do
    before { configure_oidc(subject_type: :pairwise) }

    it "issues isolated but internally consistent subjects" do
      token_a = authorize_and_exchange(client_a)
      token_b = authorize_and_exchange(client_b)

      id_a = decode_id_token(token_a["id_token"])
      id_b = decode_id_token(token_b["id_token"])

      # Mutual isolation: one person, two unrelated identifiers.
      expect(id_a["sub"]).not_to eq user.id.to_s
      expect(id_a["sub"]).not_to eq id_b["sub"]

      # ID token and UserInfo identify the same person for each partner.
      ui_a = userinfo(token_a["access_token"])
      ui_b = userinfo(token_b["access_token"])
      expect(ui_a["sub"]).to eq id_a["sub"]
      expect(ui_b["sub"]).to eq id_b["sub"]
      expect(ui_a["sub"]).not_to eq ui_b["sub"]
    end

    it "keeps the subject stable across the refresh chain" do
      original = authorize_and_exchange(client_a)
      first_id_sub = decode_id_token(original["id_token"])["sub"]

      refreshed = refresh(client_a, original["refresh_token"])
      expect(refreshed.status).to eq 200
      refreshed_body = JSON.parse(refreshed.body)
      expect(decode_id_token(refreshed_body["id_token"])["sub"]).to eq first_id_sub
      expect(userinfo(refreshed_body["access_token"])["sub"]).to eq first_id_sub

      # A second refresh still presents the identifier the grant was issued for.
      again = refresh(client_a, refreshed_body["refresh_token"])
      again_body = JSON.parse(again.body)
      expect(decode_id_token(again_body["id_token"])["sub"]).to eq first_id_sub
    end
  end

  describe "interleaving a new pairwise authorization with a pre-migration grant" do
    # Issue the authorization while the client is still public, then clear the
    # binding columns — exactly the state rows are in after the gem is upgraded
    # but before the binding migration is back-filled.
    let!(:legacy_grant) do
      configure_oidc(subject_type: :public)
      create :access_grant,
             application: client_a,
             resource_owner_id: user.id,
             scopes: "openid"
    end

    before do
      Doorkeeper::OpenidConnect::SubjectIdentifier::BINDING_COLUMNS.each do |column|
        legacy_grant.update_columns(column => nil)
      end
      configure_oidc(subject_type: :pairwise)
    end

    it "refreshes the old authorization only after re-authorization, while a fresh client works" do
      # 1. A brand-new pairwise authorization for client B succeeds.
      fresh_b = authorize_and_exchange(client_b)
      fresh_sub = decode_id_token(fresh_b["id_token"])["sub"]
      expect(fresh_sub).not_to eq user.id.to_s

      # 2. Exchanging the pre-migration authorization code is explicitly
      #    rejected: its public identifier must never be handed to a client
      #    that is now pairwise. This is the re-authorization path.
      post "/oauth/token", params: {
        grant_type: "authorization_code",
        code: legacy_grant.plaintext_token,
        redirect_uri: legacy_grant.redirect_uri,
        client_id: client_a.uid,
        client_secret: client_a.plaintext_secret,
      }
      code_body = JSON.parse(response.body)
      expect(response.status).to eq 400
      expect(code_body["error"]).to eq "invalid_grant"

      # 3. After the end user re-authorizes, the new grant is pairwise and its
      #    ID token and UserInfo agree.
      reauthorized = authorize_and_exchange(client_a)
      reauth_sub = decode_id_token(reauthorized["id_token"])["sub"]
      expect(reauth_sub).not_to eq user.id.to_s
      expect(userinfo(reauthorized["access_token"])["sub"]).to eq reauth_sub

      # The two partners still see different identifiers.
      expect(reauth_sub).not_to eq fresh_sub

      # 4. A refresh of the re-issued authorization keeps the pairwise subject.
      refreshed = refresh(client_a, reauthorized["refresh_token"])
      expect(refreshed.status).to eq 200
      refreshed_body = JSON.parse(refreshed.body)
      expect(decode_id_token(refreshed_body["id_token"])["sub"]).to eq reauth_sub
      expect(userinfo(refreshed_body["access_token"])["sub"]).to eq reauth_sub
    end

    it "keeps a legacy authorization working while the client remains public" do
      configure_oidc(subject_type: :public)

      post "/oauth/token", params: {
        grant_type: "authorization_code",
        code: legacy_grant.reload.plaintext_token,
        redirect_uri: legacy_grant.redirect_uri,
        client_id: client_a.uid,
        client_secret: client_a.plaintext_secret,
      }
      body = JSON.parse(response.body)
      expect(response).to have_http_status(:ok)
      # The historical public identifier is the resource owner id.
      expect(decode_id_token(body["id_token"])["sub"]).to eq user.id.to_s
      expect(userinfo(body["access_token"])["sub"]).to eq user.id.to_s
    end
  end

  describe "policy change after issuance" do
    before { configure_oidc(subject_type: :pairwise) }

    it "requires reauthorization when the client registration changes owner" do
      token_response = authorize_and_exchange(client_a)
      original_sub = decode_id_token(token_response["id_token"])["sub"]
      grant = Doorkeeper::AccessGrant.last
      client_a.update!(owner_id: 99)

      rejected = refresh(client_a, token_response["refresh_token"])
      expect(JSON.parse(rejected.body)["error"]).to eq "invalid_grant"

      # A fresh authorization under the new ownership yields a working token.
      new_grant = create :access_grant, application: client_a, resource_owner_id: user.id, scopes: "openid"
      create :openid_request, access_grant: new_grant, nonce: SecureRandom.hex
      post "/oauth/token", params: {
        grant_type: "authorization_code",
        code: new_grant.plaintext_token,
        redirect_uri: new_grant.redirect_uri,
        client_id: client_a.uid,
        client_secret: client_a.plaintext_secret,
      }
      new_body = JSON.parse(response.body)
      expect(response).to have_http_status(:ok)
      expect(decode_id_token(new_body["id_token"])["sub"]).not_to eq original_sub
      expect(grant).to be_present
    end

    it "requires reauthorization when the pairwise salt rotates" do
      token_response = authorize_and_exchange(client_a)

      configure_oidc(subject_type: :pairwise, pairwise_salt: "rotated-salt")

      rejected = refresh(client_a, token_response["refresh_token"])
      expect(rejected.status).to eq 400
      expect(JSON.parse(rejected.body)["error"]).to eq "invalid_grant"
    end
  end
end
