# frozen_string_literal: true

require "spec_helper"

RSpec.describe "Pundit combined authorization" do
  let(:user) { double("user") }
  let(:other_user) { double("other user") }

  # A ticket plus the organization resource it borrows, authorized through two
  # policies in different namespaces.
  let(:ticket) { Approvable.new(user) }
  let(:resource) { Resource.new(user) }
  let(:records) { [ticket, [:organization, resource]] }

  def process(ticket, resource)
    ticket.approve!(resource)
  end

  def rescue_error
    yield
  rescue => error
    error
  end

  describe ".authorize_all" do
    it "returns a successful result when every policy passes" do
      result = Pundit.authorize_all(user, records, :approve?)

      expect(result).to be_success
      expect(result).not_to be_denied
      expect(result.index).to be_nil
      expect(result.denied_indexes).to eq([])
    end

    it "reports one check per record with namespace aware policy names" do
      result = Pundit.authorize_all(user, records, :approve?)

      expect(result.checks.map(&:policy_class)).to eq(
        ["ApprovablePolicy", "Organization::ResourcePolicy"]
      )
      expect(result.checks.map(&:record_class)).to eq(
        ["Approvable", "Resource"]
      )
      expect(result.checks.map(&:query)).to eq(%i[approve? approve?])
      expect(result.checks.map(&:index)).to eq([0, 1])
      expect(result).to all(be_allowed)
    end

    it "is enumerable over the checks" do
      result = Pundit.authorize_all(user, records, :approve?)

      expect(result.map(&:policy_class)).to eq(
        ["ApprovablePolicy", "Organization::ResourcePolicy"]
      )
    end

    it "continues to processing only when all resources pass" do
      result = Pundit.authorize_all(user, records, :approve?)
      process(ticket, resource) if result.success?

      expect(ticket).to be_approved
      expect(ticket.approved_with).to eq(resource)
    end

    context "when the second check is denied" do
      let(:resource) { Resource.new(other_user) }

      it "returns a failed result pointing at the second business object" do
        result = Pundit.authorize_all(user, records, :approve?)

        expect(result).to be_failure
        expect(result.any_denied?).to be(true)
        expect(result.index).to eq(1)
        expect(result.denied_indexes).to eq([1])
        expect(result.first_denied).to have_attributes(
          index: 1,
          query: :approve?,
          record_class: "Resource",
          policy_class: "Organization::ResourcePolicy",
          allowed: false
        )
      end

      it "does not put record details into the result metadata" do
        result = Pundit.authorize_all(user, records, :approve?)

        payload = result.checks.map(&:to_h)
        expect(payload).not_to include(ticket)
        expect(payload).not_to include(resource)
        expect(payload.inspect).not_to include(resource.to_s)
        expect(result.checks.first).to be_allowed
      end

      it "does not perform the mutation when processing is guarded by success?" do
        result = Pundit.authorize_all(user, records, :approve?)
        process(ticket, resource) if result.success?

        expect(ticket).not_to be_approved
        expect(ticket.approved_with).to be_nil
      end
    end

    context "when a policy is missing" do
      let(:records) { [ticket, [:organization, Article.new]] }

      it "raises NotDefinedError and leaves the business objects untouched" do
        expect { Pundit.authorize_all(user, records, :approve?) }
          .to raise_error(Pundit::NotDefinedError,
            /unable to find policy `Organization::ArticlePolicy`/)

        expect(ticket).not_to be_approved
      end
    end

    it "forces a single policy class for every record when given one" do
      result = Pundit.authorize_all(user, [ticket, resource], :create?,
        policy_class: PublicationPolicy)

      expect(result).to be_success
      expect(result.checks.map(&:policy_class)).to eq(
        %w[PublicationPolicy PublicationPolicy]
      )
    end

    it "names headless symbol records without exposing object state" do
      result = Pundit.authorize_all(user, [:publication], :create?)

      expect(result.first_denied).to be_nil
      expect(result.checks.first.record_class).to eq("publication")
    end

    it "falls back to the runtime class name for anonymous record classes" do
      anonymous_record = Class.new do
        def self.policy_class
          ArticleTagOtherNamePolicy
        end
      end.new

      result = Pundit.authorize_all(user, [anonymous_record], :show?)

      expect(result).to be_success
      expect(result.checks.first.record_class).to match(/\A#<Class:0x[0-9a-f]+>\z/)
      expect(result.checks.first.policy_class).to eq("ArticleTagOtherNamePolicy")
    end

    it "reuses cached policies through the controller context" do
      controller = Controller.new(user, "approve", {})
      controller.authorize_all(records)

      expect { controller.authorize_all(records) }.not_to change { ApprovablePolicy.instances }
    end

    it "supports the explicit cache like Pundit.authorize" do
      cache = {}

      Pundit.authorize_all(user, records, :approve?, cache: cache)

      expect(cache).to include(ticket => kind_of(ApprovablePolicy))
      expect(cache).to include([:organization, resource] => kind_of(Organization::ResourcePolicy))
    end

    it "returns a successful empty result when no records are given" do
      result = Pundit.authorize_all(user, [], :approve?)

      expect(result).to be_success
      expect(result.checks).to eq([])
    end
  end

  describe ".authorize_all!" do
    it "returns the successful result when every policy passes" do
      result = Pundit.authorize_all!(user, records, :approve?)

      expect(result).to be_success
    end

    it "raises AuthorizationFailedError identifying the denied object by index" do
      resource = Resource.new(other_user)

      expect { Pundit.authorize_all!(user, [ticket, [:organization, resource]], :approve?) }
        .to raise_error(Pundit::AuthorizationFailedError) do |error|
          expect(error.index).to eq(1)
          expect(error.result).to be_failure
          expect(error.message).to include("index 1")
          expect(error.message).to include("Organization::ResourcePolicy")
        end
    end

    it "keeps records out of the raised error" do
      resource = Resource.new(other_user)

      error = rescue_error do
        Pundit.authorize_all!(user, [ticket, [:organization, resource]], :approve?)
      end

      expect(error.message).not_to include(resource.to_s)
      expect(error.instance_variables).to contain_exactly(:@result)
    end
  end

  describe Pundit::Authorization do
    let(:controller) { Controller.new(user, "approve", {}) }

    describe "#authorize_all" do
      it "defaults the query to the controller action name" do
        result = controller.authorize_all(records)

        expect(result).to be_success
        expect(result.checks.map(&:query)).to eq(%i[approve? approve?])
      end

      it "marks authorization as performed" do
        controller.authorize_all(records)

        expect(controller.pundit_policy_authorized?).to be(true)
      end

      it "denies the second record and prevents processing" do
        denied_resource = Resource.new(other_user)

        result = controller.authorize_all([ticket, [:organization, denied_resource]])

        expect(result.index).to eq(1)
        expect(ticket).not_to be_approved
      end

      it "raises when a policy is missing" do
        expect { controller.authorize_all([ticket, Article.new]) }
          .to raise_error(Pundit::NotDefinedError)
      end
    end

    describe "#authorize_all!" do
      it "lets processing continue only when all records pass" do
        controller.authorize_all!(records)
        process(ticket, resource)

        expect(ticket).to be_approved
      end

      it "raises before processing when a check is denied" do
        denied_resource = Resource.new(other_user)

        expect do
          controller.authorize_all!([ticket, [:organization, denied_resource]])
        end.to raise_error(Pundit::AuthorizationFailedError)
        expect(ticket).not_to be_approved
      end

      it "marks authorization as performed even when denied" do
        denied_resource = Resource.new(other_user)

        expect do
          controller.authorize_all!([ticket, [:organization, denied_resource]])
        end.to raise_error(Pundit::AuthorizationFailedError)
        expect(controller.pundit_policy_authorized?).to be(true)
      end
    end
  end
end
