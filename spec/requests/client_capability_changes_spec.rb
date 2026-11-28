# frozen_string_literal: true

require "rails_helper"

# Covers the two operational properties the capability policy has to preserve:
# registrations in different spaces never change each other, even when they
# share a display name and default settings, and narrowing a space after a
# client registered is explainable as "these capabilities need re-approval"
# rather than silently changing what the stored client may do.
describe "Client capability changes after registration", type: :request do
  let(:redirect_uris) { ["https://test.host/callback"] }

  def configure_policy(scopes)
    Doorkeeper::OpenidConnect.configure do
      issuer "dummy"
      signing_key OpenSSL::PKey::RSA.new(2048).to_pem
      dynamic_client_registration true
      resource_owner_from_access_token { |token| User.find_by(id: token.resource_owner_id) }
      subject { |owner| owner.id }
      client_capabilities do
        space :admins do
          scopes(*scopes)
          grant_types :authorization_code
          response_types :code
          token_endpoint_auth_methods :client_secret_basic
        end
      end
    end

    Rails.application.reload_routes!
  end

  before do
    Doorkeeper.configure do
      orm :active_record
      grant_flows %w[authorization_code]
      default_scopes :openid
      optional_scopes :profile, :admin
      skip_authorization { true }
      resource_owner_authenticator { User.find_by(id: params[:current_user]) }
    end

    configure_policy(%i[openid profile])
  end

  it "keeps same-named registrations in separate spaces independent" do
    post "/admins/oauth/registration", params: {
      client_name: "Shared Name",
      redirect_uris: redirect_uris,
      scope: "openid profile",
    }
    expect(response).to have_http_status(:created)
    admin = Doorkeeper::Application.find_by(uid: JSON.parse(response.body)["client_id"])

    post "/oauth/registration", params: {
      client_name: "Shared Name",
      redirect_uris: redirect_uris,
      scope: "openid",
    }
    expect(response).to have_http_status(:created)
    default = Doorkeeper::Application.find_by(uid: JSON.parse(response.body)["client_id"])

    expect(admin.id).not_to eq(default.id)
    expect(admin.registered_space).to eq("admins")
    expect(default.registered_space).to be_nil
    expect(admin.scopes.to_s).to eq("openid profile")
    expect(default.scopes.to_s).to eq("openid")

    # Changing one approval cannot widen the other.
    admin.update!(scopes: "openid")
    expect(default.reload.scopes.to_s).to eq("openid")
    expect(admin.reload.registered_space).to eq("admins")
  end

  it "explains which capabilities a narrowed policy requires re-approval for" do
    user = create(:user)
    post "/admins/oauth/registration", params: {
      client_name: "admins-client",
      redirect_uris: redirect_uris,
      scope: "openid profile",
    }
    expect(response).to have_http_status(:created)
    client = Doorkeeper::Application.find_by(uid: JSON.parse(response.body)["client_id"])
    expect(client.registered_grant_types).to eq(%w[authorization_code])
    expect(client.registered_response_types).to eq(%w[code])

    # The administrator later narrows the space after the client registered.
    configure_policy(%i[openid])

    review = Doorkeeper::OpenidConnect.capability_review(client)
    expect(review[:space]).to eq("admins")
    expect(review[:approved][:scopes]).to eq(%w[openid profile])
    expect(review[:revoked]).to eq([:scopes])

    # The stored client did not change by itself: it still carries the scopes
    # it was approved for, so the change is explainable rather than silent.
    expect(client.reload.scopes.to_s).to eq("openid profile")

    # A request using the withdrawn capability is refused at authorization.
    get "/admins/oauth/authorize", params: {
      response_type: "code",
      client_id: client.uid,
      redirect_uri: redirect_uris.first,
      scope: "openid profile",
      current_user: user.id,
    }
    expect(response).to have_http_status(:bad_request)
    expect(response.body).to include("The requested scope is invalid")

    # The still-approved part of the capability set continues to work.
    get "/admins/oauth/authorize", params: {
      response_type: "code",
      client_id: client.uid,
      redirect_uri: redirect_uris.first,
      scope: "openid",
      current_user: user.id,
    }
    expect(response).to have_http_status(:found)
  end

  it "leaves a registration created before capability policies usable" do
    legacy = Doorkeeper::Application.create!(
      name: "legacy-client",
      redirect_uri: redirect_uris.first,
      scopes: "openid profile",
    )

    expect(legacy.registered_space).to be_nil
    # The default space declares no capability policy, so a pre-policy client
    # remains approved exactly as it was.
    expect(Doorkeeper::OpenidConnect.capability_review(legacy)[:revoked]).to be_empty
    expect(legacy.scopes.to_s).to eq("openid profile")
  end
end
