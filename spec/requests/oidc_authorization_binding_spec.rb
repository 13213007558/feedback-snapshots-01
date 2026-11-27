# frozen_string_literal: true

require "rails_helper"

# Reproduces the concurrent-authorization scenario behind per-request
# authorization bindings: one browser (a single cookie jar) opens two
# authorizations for the SAME client — an interactive one that asks the user to
# choose an account (`prompt=select_account`) and a silent one
# (`prompt=none`). The selected account and the allowed interaction scope must
# stay bound to the request that started them, so the silent request can never
# reuse the interactive one's selection or surface an extra page.
describe "OIDC per-request authorization binding", type: :request do
  let(:redirect_uri) { "https://app.example.com/callback" }
  let!(:application) do
    create :application, redirect_uri: redirect_uri, scopes: "openid profile"
  end
  let!(:alice) { create :user }
  let!(:bob) { create :user }

  # The dummy resource_owner_authenticator establishes the session from
  # params[:current_user], so every request names the user it acts as.
  def authorize_params(prompt:, state:, current_user: alice.id)
    {
      response_type: "code",
      client_id: application.uid,
      redirect_uri: redirect_uri,
      scope: "openid profile",
      prompt: prompt,
      state: state,
      nonce: "nonce-#{state}",
      current_user: current_user,
    }
  end

  def query(location)
    Rack::Utils.parse_query(URI.parse(location).query)
  end

  # Path + query for a URL that may be relative (the chooser's return URL is a
  # relative `/oauth/authorize?...`), where URI::Generic has no #request_uri.
  def path_of(location)
    uri = URI.parse(location)
    [uri.path, uri.query && "?#{uri.query}"].compact.join
  end

  def start_select_account(state:, current_user: alice.id)
    get "/oauth/authorize",
        params: authorize_params(prompt: "select_account", state: state,
                                 current_user: current_user)
    expect(response).to redirect_to(%r{\A/select_account})
    query(response.location)["return_to"]
  end

  def choose_account(return_to, user)
    post "/select_account", params: { resource_owner_id: user.id, return_to: return_to }
    # The chooser sends the user-agent back to the authorize endpoint; the
    # actual code redirect happens when that URL is followed in #resume.
    expect(response).to redirect_to(return_to)
    path_of(return_to)
  end

  def resume(path)
    get path
    expect(response).to redirect_to(%r{\A#{Regexp.quote(redirect_uri)}})
    query(response.location)
  end

  def exchange(code)
    post "/oauth/token", params: {
      grant_type: "authorization_code",
      code: code,
      client_id: application.uid,
      client_secret: application.plaintext_secret,
      redirect_uri: redirect_uri,
    }
    expect(response).to have_http_status(:ok)
    JSON.parse(response.body)
  end

  describe "interactive select_account request" do
    it "binds the chosen account to the request and resumes without another page" do
      return_to = start_select_account("interactive")
      resume_path = choose_account(return_to, bob)

      result = resume(resume_path)
      expect(result).not_to have_key "error"
      expect(result["code"]).to be_present

      grant = Doorkeeper::AccessGrant.find_by(token: result["code"])
      expect(grant.resource_owner_id).to eq bob.id
    end

    it "keeps the exchanged token subject equal to the selected account" do
      return_to = start_select_account("subject-check")
      resume_path = choose_account(return_to, bob)
      code = resume(resume_path)["code"]

      token_response = exchange(code)
      payload, = JWT.decode(token_response["id_token"], nil, false)
      expect(payload["sub"]).to eq bob.id.to_s
      expect(payload["nonce"]).to eq "nonce-subject-check"
    end

    it "clears the binding once the authorization completes so it cannot replay" do
      return_to = start_select_account("one-shot")
      resume_path = choose_account(return_to, bob)
      resume(resume_path)

      # A later request carrying the same correlation key starts fresh and has
      # to show the chooser again instead of silently reusing the old account.
      get "/oauth/authorize",
          params: authorize_params(prompt: "select_account", state: "one-shot")
      expect(response).to redirect_to(%r{\A/select_account})
    end
  end

  describe "silent prompt=none request alongside an interactive one" do
    it "never reuses the interactive request's selected account or shows a page" do
      # Interactive request chooses Bob and stores a per-request binding.
      return_to = start_select_account("interactive-2")
      choose_account(return_to, bob)

      # The silent request shares the cookie jar but has its own correlation
      # key. With no matching token it fails closed and renders nothing.
      get "/oauth/authorize",
          params: authorize_params(prompt: "none", state: "silent-2")

      expect(response).to redirect_to(%r{\A#{Regexp.quote(redirect_uri)}})
      error = query(response.location)
      expect(error["error"]).to eq "consent_required"
      expect(error["state"]).to eq "silent-2"
      expect(Doorkeeper::AccessToken.count).to eq 0
      expect(Doorkeeper::AccessGrant.count).to eq 0
    end

    it "succeeds silently for its own account once a matching token exists" do
      create :access_token,
             application: application,
             resource_owner_id: bob.id,
             scopes: "openid profile"

      get "/oauth/authorize",
          params: authorize_params(prompt: "none", state: "silent-ok",
                                   current_user: bob.id)

      expect(response).to redirect_to(%r{\A#{Regexp.quote(redirect_uri)}})
      result = query(response.location)
      expect(result).not_to have_key "error"
      expect(result["code"]).to be_present
    end

    it "answers login_required when the silent preconditions are missing" do
      get "/oauth/authorize",
          params: authorize_params(prompt: "none", state: "silent-anon",
                                   current_user: nil)

      expect(response).to redirect_to(%r{\A#{Regexp.quote(redirect_uri)}})
      error = query(response.location)
      expect(error["error"]).to eq "login_required"
      expect(error["state"]).to eq "silent-anon"
    end

    it "rejects prompt=none combined with another prompt as invalid_request" do
      get "/oauth/authorize",
          params: authorize_params(prompt: "none login", state: "silent-mixed")

      expect(response).to redirect_to(%r{\A#{Regexp.quote(redirect_uri)}})
      expect(query(response.location)["error"]).to eq "invalid_request"
    end
  end

  describe "two requests with different interaction permits" do
    it "isolates the two slots regardless of completion order" do
      # Open the interactive request and choose Bob, but do not resume yet.
      interactive_return = start_select_account("pair-interactive")
      choose_account(interactive_return, bob)

      # A silent request for the same client runs in between and must fail on
      # its own merits without consuming the interactive binding.
      get "/oauth/authorize",
          params: authorize_params(prompt: "none", state: "pair-silent")
      expect(query(response.location)["error"]).to eq "consent_required"

      # Resuming the interactive request now still authenticates Bob.
      result = resume(path_of(interactive_return))
      expect(result["code"]).to be_present
      expect(Doorkeeper::AccessGrant.find_by(token: result["code"]).resource_owner_id)
        .to eq bob.id
    end
  end
end
