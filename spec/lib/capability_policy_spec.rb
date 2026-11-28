# frozen_string_literal: true

require "rails_helper"

describe Doorkeeper::OpenidConnect::CapabilityPolicy do
  subject(:policy) { described_class.new(name: "admins", scopes: %w[openid], grant_types: %w[authorization_code]) }

  it "normalizes a mount name into its route helper prefix" do
    expect(policy.prefix).to eq("admins_")
    expect(policy.space_name).to eq("admins")
  end

  it "treats the empty prefix as the default space" do
    default = described_class.new(name: "")
    expect(default).to be_default
    expect(default.space_name).to eq("default")
  end

  it "declares only the capabilities it was given" do
    expect(policy).to be_declares_scopes
    expect(policy).to be_declares_grant_types
    expect(policy).not_to be_declares_response_types
    expect(policy).not_to be_declares_token_endpoint_auth_methods
  end

  it "intersects declared capabilities with the server's global set" do
    allow(Doorkeeper.configuration).to receive(:scopes).and_return(
      Doorkeeper::OAuth::Scopes.from_array(%w[openid profile admin]),
    )
    allow(Doorkeeper.configuration).to receive(:grant_flows).and_return(%w[authorization_code password])

    expect(policy.effective_scopes(Doorkeeper.configuration).all).to eq(%w[openid])
    expect(policy.effective_grant_types(Doorkeeper.configuration)).to eq(%w[authorization_code])
    expect(policy).not_to be_permits_grant_type("password", Doorkeeper.configuration)
    expect(policy).to be_permits_grant_type("authorization_code", Doorkeeper.configuration)
  end

  it "maps internal flow names to their RFC 7591 name" do
    allow(Doorkeeper.configuration).to receive(:grant_flows).and_return(%w[implicit_oidc])

    implicit = described_class.new(name: "admins", grant_types: %w[implicit])
    expect(implicit.effective_grant_types(Doorkeeper.configuration)).to eq(%w[implicit])
  end

  it "does not restrict undeclared capabilities" do
    unrestricted = described_class.new(name: "admins")

    expect(unrestricted).to be_permits_scopes("anything")
    expect(unrestricted).to be_permits_grant_type("password")
    expect(unrestricted).to be_permits_response_type("id_token")
  end

  it "reports which approved capabilities need re-approval" do
    registration = {
      scopes: %w[openid profile],
      grant_types: %w[authorization_code],
      response_types: %w[code],
      token_endpoint_auth_method: "client_secret_post",
    }

    revoked = policy.capability_review(registration)
    expect(revoked).to include(:scopes)
    expect(revoked).not_to include(:grant_types)
  end
end
