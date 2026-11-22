require_relative 'spec_helper'

describe 'Rodauth onboarding access with verify account grace period' do
  # New employee flow on top of the verify_account_grace_period feature:
  #
  # * GET /onboarding is read-only and available to any logged in user,
  #   including accounts still inside the unverified grace period.
  # * POST /approvals is a modification endpoint that requires a verified
  #   account. The application declares this policy itself, on top of the
  #   grace period Rodauth grants to unverified accounts.
  #
  # The same route policy is exercised once through a browser (Capybara,
  # HTML flash + redirect) and once through JSON requests.
  APPROVAL_ERROR_FLASH = "Please verify your email before submitting approvals"

  def configure_onboarding_rodauth
    rodauth do
      enable :login, :logout, :create_account, :verify_account_grace_period
      verify_account_grace_period 86400
      verify_account_email_last_sent_column nil
    end
  end

  # Shared route policy. json_mode switches the unverified write denial between
  # the HTML (flash + redirect) and JSON (403 body) representations.
  ONBOARDING_ROUTES = proc do |r, json_mode|
    r.rodauth

    r.is "onboarding" do
      r.get do
        rodauth.require_login
        if json_mode
          response["Content-Type"] = "application/json"
          response.write({"status" => rodauth.verified_account? ? "verified" : "unverified"}.to_json)
          request.halt
        end
        view :content => rodauth.verified_account? ? "Onboarding (verified)" : "Onboarding (unverified)"
      end
    end

    r.is "approvals" do
      r.post do
        rodauth.require_login
        unless rodauth.verified_account?
          if json_mode
            response.status = rodauth.unopen_account_error_status
            response["Content-Type"] = "application/json"
            response.write({"reason" => "unverified_approval", "error" => APPROVAL_ERROR_FLASH}.to_json)
            request.halt
          end
          rodauth.set_redirect_error_flash(APPROVAL_ERROR_FLASH)
          r.redirect "/"
        end
        if json_mode
          response["Content-Type"] = "application/json"
          response.write({"success" => "Approval submitted"}.to_json)
          request.halt
        end
        "Approval submitted"
      end
    end

    r.is "expire-grace-period" do
      if json_mode
        r.post do
          session[rodauth.unverified_account_session_key] -= 100000
          response["Content-Type"] = "application/json"
          response.write({"success" => "grace period expired"}.to_json)
          request.halt
        end
      else
        r.get do
          session[rodauth.unverified_account_session_key] -= 100000
          r.redirect "/"
        end
      end
    end

    r.root do
      view :content => rodauth.logged_in? ? "Home" : "Not Logged"
    end
  end

  def create_onboarding_account
    visit "/create-account"
    fill_in "Login", :with => "newhire@example.com"
    fill_in "Password", :with => "0123456789"
    fill_in "Confirm Password", :with => "0123456789"
    click_button "Create Account"
    page.find("#notice_flash").text.must_equal "An email has been sent to you with a link to verify your account"
    email_link(/(\/verify-account\?key=.+)$/, "newhire@example.com")
  end

  it "allows read-only onboarding during the grace period but blocks modification requests in the browser" do
    configure_onboarding_rodauth
    roda do |r|
      instance_exec(r, false, &ONBOARDING_ROUTES)
    end

    link = create_onboarding_account

    # The new account is autologged in but not yet verified.
    page.body.must_include "Home"
    get_cookie("rack.session").must_be_kind_of String

    # Read-only onboarding instructions are available inside the grace period.
    visit "/onboarding"
    page.current_path.must_equal "/onboarding"
    page.body.must_include "Onboarding (unverified)"

    # The modification endpoint is refused while the email is unconfirmed.
    page.driver.post "/approvals"
    page.driver.response.status.must_equal 302
    page.driver.response.headers["Location"].must_equal "/"
    visit "/"
    page.find("#error_flash").text.must_equal APPROVAL_ERROR_FLASH

    # Read access still works after the refused write.
    visit "/onboarding"
    page.body.must_include "Onboarding (unverified)"

    # Once the grace period is over, the established session is no longer a
    # login, so read-only access is revoked as well.
    DB[:account_verification_keys].update(:requested_at => Time.now - 100000)
    visit "/expire-grace-period"
    visit "/onboarding"
    page.current_path.must_equal "/login"
    page.find("#error_flash").text.must_equal "Please login to continue"
    visit "/"
    page.body.must_include "Not Logged"

    # Verifying the email upgrades the session to ordinary permissions.
    visit link
    click_button "Verify Account"
    page.find("#notice_flash").text.must_equal "Your account has been verified"
    page.body.must_include "Home"

    visit "/onboarding"
    page.body.must_include "Onboarding (verified)"

    page.driver.post "/approvals"
    page.driver.response.status.must_equal 200
    page.driver.response.body.must_include "Approval submitted"
  end

  it "enforces the same policy for JSON requests across grace period, expiry, and verification" do
    configure_onboarding_rodauth
    roda(:json) do |r|
      instance_exec(r, true, &ONBOARDING_ROUTES)
    end

    # Create the unverified account; the response sets the session cookie used
    # by subsequent JSON requests.
    res = json_request("/create-account",
      :login => "newhire@example.com",
      :password => "0123456789",
      "password-confirm" => "0123456789")
    res.must_equal [200, {"success" => "An email has been sent to you with a link to verify your account"}]
    link = email_link(/key=.+$/, "newhire@example.com")

    # Read-only onboarding access is allowed while inside the grace period.
    json_request("/onboarding", :method => "GET").must_equal [200, {"status" => "unverified"}]

    # Modification requests are rejected until the email is confirmed.
    res = json_request("/approvals")
    res.must_equal [403, {"reason" => "unverified_approval", "error" => APPROVAL_ERROR_FLASH}]

    # The read-only endpoint keeps working after the rejected write.
    json_request("/onboarding", :method => "GET").must_equal [200, {"status" => "unverified"}]

    # After the grace period ends the session stops being authenticated.
    DB[:account_verification_keys].update(:requested_at => Time.now - 100000)
    json_request("/expire-grace-period").must_equal [200, {"success" => "grace period expired"}]
    json_request("/onboarding", :method => "GET").must_equal [401, {"reason" => "login_required", "error" => "Please login to continue"}]
    json_request("/approvals").must_equal [401, {"reason" => "login_required", "error" => "Please login to continue"}]

    # Confirming the email upgrades the existing session to ordinary
    # permissions. No new login is performed: the next request on the same
    # cookie jar is immediately authenticated with the verified privilege.
    res = json_request("/verify-account", :key => link[/key=\K.+$/])
    res.must_equal [200, {"success" => "Your account has been verified"}]

    json_request("/onboarding", :method => "GET").must_equal [200, {"status" => "verified"}]
    json_request("/approvals").must_equal [200, {"success" => "Approval submitted"}]
  end
end
