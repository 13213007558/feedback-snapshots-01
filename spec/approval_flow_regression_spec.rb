# frozen_string_literal: true

require "spec_helper"

# Regression coverage for the approval page flow described in the security
# report: the page render only decides whether to *show* the button, while the
# actual state change happens on the following submit request. These examples
# observe, in order, the policy scope, the rendered view, the submit-time
# authorization and the resulting data, including after the current user loses
# its qualification between the two requests.
RSpec.describe "approval flow regression" do
  let(:legal_user) { double("legal user") }
  let(:intruder) { double("intruder user") }

  let(:allowed_request) { ApprovalRequest.new(approver: legal_user) }
  let(:protected_request) { ApprovalRequest.new(approver: legal_user) }

  def index_controller(user, requests)
    ApprovalController.new(user, "index", requests: requests)
  end

  def approval_controller(klass, user, request)
    klass.new(user, "approve", approval_request: request)
  end

  describe "list scope, view preview and submit authorization" do
    it "resolves the same object through different namespaced strategies" do
      controller = ApprovalController.new(legal_user, "index", {})

      expect(controller.policy_scope(ApprovalRequest)).to eq(:pending_requests)
      expect(controller.policy_scope([:workflow, ApprovalRequest])).to eq(:routed_requests)
    end

    it "shows the approve button only while the rendered policy grants it" do
      preview = index_controller(legal_user, [allowed_request, protected_request]).index

      expect(preview).to eq("pending:true,pending:true")
    end

    it "re-renders the preview without the button after the qualification changes" do
      preview = index_controller(intruder, [protected_request]).index

      expect(preview).to eq("pending:false")
    end

    it "approves the request when the same legal user continues to submit" do
      index_controller(legal_user, [allowed_request]).index
      controller = approval_controller(ApprovalController, legal_user, allowed_request)

      expect { controller.approve }.to change(allowed_request, :state).from("pending").to("approved")
      expect(controller.approved_request).to be(allowed_request)
      expect(controller).to be_pundit_policy_authorized
    end

    it "rejects the second request after the qualification is switched away" do
      index_controller(legal_user, [allowed_request, protected_request]).index
      controller = approval_controller(ApprovalController, intruder, protected_request)

      expect { controller.approve }.to raise_error(Pundit::NotAuthorizedError) do |error|
        expect(error.query).to eq(:approve?)
        expect(error.record).to be(protected_request)
        expect(error.policy).to be_a(ApprovalRequestPolicy)
        expect(error.policy.user).to be(intruder)
      end
      expect(controller.authorization_error.policy.user).to be(intruder)
      expect(protected_request.state).to eq("pending")
      expect(controller.approved_request).to be_nil
    end
  end

  describe "user switching" do
    it "rebuilds the policy with the current principal after pundit_reset!" do
      controller = approval_controller(ApprovalController, legal_user, protected_request)
      rendered_policy = controller.policy(protected_request)

      expect(rendered_policy.user).to be(legal_user)
      expect(rendered_policy.approve?).to be(true)

      controller.current_user = intruder
      expect(controller.policy(protected_request).user).to be(legal_user)

      controller.pundit_reset!

      fresh_policy = controller.policy(protected_request)
      expect(fresh_policy).not_to be(rendered_policy)
      expect(fresh_policy.user).to be(intruder)
      expect(fresh_policy.approve?).to be(false)
      expect(controller.pundit.user).to be(intruder)
    end

    it "keeps each request's policy bound to the principal that submits it" do
      first_controller = approval_controller(ApprovalController, legal_user, allowed_request)
      second_controller = approval_controller(ApprovalController, intruder, protected_request)

      expect(first_controller.pundit_user).to be(legal_user)
      expect(second_controller.pundit_user).to be(intruder)
      expect(first_controller.policy(allowed_request).user).to be(legal_user)
      expect(second_controller.policy(protected_request).user).to be(intruder)
    end
  end

  describe "interleaved approvals" do
    it "lets the legal approval through and refuses the disqualified one without a write" do
      index_controller(legal_user, [allowed_request, protected_request]).index
      legal_controller = approval_controller(ApprovalController, legal_user, allowed_request)
      intruder_controller = approval_controller(ApprovalController, intruder, protected_request)

      legal_controller.approve

      expect(allowed_request.state).to eq("approved")
      expect { intruder_controller.approve }.to raise_error(Pundit::NotAuthorizedError)
      expect(protected_request.state).to eq("pending")
      expect(intruder_controller.approved_request).to be_nil
      expect(intruder_controller.authorization_error).to have_attributes(
        query: :approve?,
        record: protected_request
      )
    end
  end

  describe "guards against the two known failure modes" do
    def assert_submit_is_refused(klass)
      index_controller(legal_user, [protected_request]).index
      controller = approval_controller(klass, intruder, protected_request)

      expect { controller.approve }.to raise_error(Pundit::NotAuthorizedError)
      expect(protected_request.state).to eq("pending")
      expect(controller.approved_request).to be_nil
    end

    it "passes the refusal contract with the real authorize call" do
      assert_submit_is_refused(ApprovalController)
    end

    it "catches a submit that reuses the stale render-time policy after a user switch" do
      controller = StalePolicyApprovalController.new(
        legal_user,
        "index",
        requests: [protected_request],
        approval_request: protected_request
      )
      controller.index
      controller.current_user = intruder

      stale_policy = controller.policy(protected_request)
      expect(stale_policy.user).to be(legal_user)
      expect(stale_policy.approve?).to be(true)

      expect do
        expect { controller.approve }.to raise_error(Pundit::NotAuthorizedError)
      end.to fail_with(/Pundit::NotAuthorizedError.*nothing was raised/)
      expect(protected_request.state).to eq("approved")
    end

    it "catches a submit that never runs controller authorization" do
      expect do
        assert_submit_is_refused(UnauthorizedApprovalController)
      end.to fail_with(/expected Pundit::NotAuthorizedError/)
      expect(protected_request.state).to eq("approved")
    end
  end

  RSpec::Matchers.define :fail_with do |message_matcher|
    supports_block_expectations

    match do |block|
      block.call
      false
    rescue RSpec::Expectations::ExpectationNotMetError => error
      values_match?(message_matcher, error.message)
    end

    failure_message do
      "expected the inner regression assertion to fail, but it did not"
    end
  end
end
