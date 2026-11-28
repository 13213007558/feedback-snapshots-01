# frozen_string_literal: true

require "rails_helper"

# Acceptance coverage for per-space client capabilities: two real mounts of the
# engine share one database, but each approves a different capability set. The
# spec registers a client through each mount, reads each mount's discovery
# document, and completes a real authorization with the client whose space
# approved the requested scope.
describe "Per-space client capabilities", type: :request do
  let(:redirect_uris) { ["https://test.host/registration_success"] }

  def register(path, params = {})
    post path, params: {
      client_name: "space-client",
      redirect_uris: redirect_uris,
      scope: "openid",
    }.merge(params)
  end

  before do
    Doorkeeper.configure do
      orm :active_record
      grant_flows %w[authorization_code client_credentials implicit_oidc]
      default_scopes :openid
      optional_scopes :profile, :admin, :write
      skip_authorization { true }
      resource_owner_authenticator do
        User.find_by(id: params[:current_user])
      end
    end

    Doorkeeper::OpenidConnect.configure do
      issuer "dummy"
      signing_key OpenSSL::PKey::RSA.new(2048).to_pem
      dynamic_client_registration true
      resource_owner_from_access_token { |token| User.find_by(id: token.resource_owner_id) }
      subject { |resource_owner| resource_owner.id }
      client_capabilities do
        space :admins do
          scopes :openid, :profile
          grant_types :authorization_code
          response_types :code
          token_endpoint_auth_methods :client_secret_basic
        end
        space :staff do
          scopes :openid
          grant_types :authorization_code
          response_types :code
          token_endpoint_auth_methods :client_secret_basic
        end
      end
    end

    Rails.application.reload_routes!
  end

  it "registers in each space and persists the approved capability set" do
    post "/admins/oauth/registration", params: {
      client_name: "admins-client",
      redirect_uris: redirect_uris,
      scope: "openid profile",
    }
    expect(response).to have_http_status(:created)
    admins_body = JSON.parse(response.body)

    post "/staff/oauth/registration", params: {
      client_name: "staff-client",
      redirect_uris: redirect_uris,
      scope: "openid profile",
    }
    expect(response).to have_http_status(:created)
    staff_body = JSON.parse(response.body)

    admins = Doorkeeper::Application.find_by(uid: admins_body["client_id"])
    staff = Doorkeeper::Application.find_by(uid: staff_body["client_id"])
    expect(admins).to be_present
    expect(staff).to be_present

    expect(admins.scopes.to_s).to eq("openid profile")
    expect(staff.scopes.to_s).to eq("openid")
    expect(staff_body["scope"]).to eq("openid")

    expect(admins.registered_space).to eq("admins")
    expect(staff.registered_space).to eq("staff")
  end

  it "advertises each space's own capabilities in its discovery document" do
    get "/admins/.well-known/openid-configuration"
    admins = JSON.parse(response.body)
    expect(admins["scopes_supported"]).to contain_exactly("openid", "profile")
    expect(admins["registration_endpoint"]).to end_with("/admins/oauth/registration")

    get "/staff/.well-known/openid-configuration"
    staff = JSON.parse(response.body)
    expect(staff["scopes_supported"]).to contain_exactly("openid")
    expect(staff["registration_endpoint"]).to end_with("/staff/oauth/registration")
  end

  it "refuses an authorization request for a capability the space did not approve" do
    user = create(:user)
    post "/staff/oauth/registration", params: {
      client_name: "staff-client",
      redirect_uris: redirect_uris,
      scope: "openid",
    }
    client = Doorkeeper::Application.find_by(uid: JSON.parse(response.body)["client_id"])

    get "/staff/oauth/authorize", params: {
      response_type: "code",
      client_id: client.uid,
      redirect_uri: redirect_uris.first,
      scope: "openid profile",
      current_user: user.id,
    }

    # The narrow space never approved `profile`, so the request is refused with
    # the standard OAuth scope error instead of silently narrowing the token.
    expect(response).to have_http_status(:bad_request)
    expect(response.body).to include("The requested scope is invalid")

    # The same client can complete an authorization in a space that did
    # approve only what it asks for.
    get "/admins/oauth/authorize", params: {
      response_type: "code",
      client_id: client.uid,
      redirect_uri: redirect_uris.first,
      scope: "openid",
      current_user: user.id,
    }
    expect(response).to have_http_status(:found)
    expect(response.location).to start_with(redirect_uris.first)

    code = Rack::Utils.parse_query(URI.parse(response.location).query)["code"]
    post "/admins/oauth/token", params: {
      grant_type: "authorization_code",
      code: code,
      redirect_uri: redirect_uris.first,
      client_id: client.uid,
      client_secret: client.secret,
    }

    expect(response).to have_http_status(:ok)
    body = JSON.parse(response.body)
    token = Doorkeeper::AccessToken.by_token(body["access_token"])
    expect(token.scopes.to_s).to eq("openid")
  end
end

describe "Per-space token endpoint enforcement", type: :request do
  before do
    Doorkeeper.configure do
      orm :active_record
      grant_flows %w[authorization_code client_credentials]
      default_scopes :openid
      optional_scopes :profile
      resource_owner_from_credentials { |_login, _password| create(:user) }
    end

    Doorkeeper::OpenidConnect.configure do
      issuer "dummy"
      signing_key OpenSSL::PKey::RSA.new(2048).to_pem
      client_capabilities do
        space :staff do
          grant_types :authorization_code
          scopes :openid
        end
      end
    end

    Rails.application.reload_routes!
  end

  it "refuses a grant type the receiving space did not approve" do
    client = Doorkeeper::Application.create!(
      name: "staff-client",
      redirect_uri: "https://test.host/cb",
      scopes: "openid",
    )

    post "/staff/oauth/token", params: {
      grant_type: "client_credentials",
      client_id: client.uid,
      client_secret: client.secret,
      scope: "openid",
    }

    expect(response).to have_http_status(:unauthorized)
    expect(JSON.parse(response.body)["error"]).to eq("unauthorized_client")
  end

  it "keeps the same grant available to the default space" do
    client = Doorkeeper::Application.create!(
      name: "default-client",
      redirect_uri: "https://test.host/cb",
      scopes: "openid",
    )

    post "/oauth/token", params: {
      grant_type: "client_credentials",
      client_id: client.uid,
      client_secret: client.secret,
      scope: "openid",
    }

    expect(response).to have_http_status(:ok)
  end
end
