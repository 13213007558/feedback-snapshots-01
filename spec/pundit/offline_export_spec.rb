# frozen_string_literal: true

require "spec_helper"

# Offline data export, without a controller: the application hands each
# export task an authorization fact (requester + approved scope + budget),
# and Pundit::Context carries that fact to both policies and scopes.
class ExportGrant
  attr_reader :requester, :approved_owner_ids, :budget

  def initialize(requester:, approved_owner_ids:, budget:)
    @requester = requester
    @approved_owner_ids = approved_owner_ids
    @budget = budget
  end

  def approves?(row)
    !requester.nil? &&
      approved_owner_ids.include?(row.owner_id) &&
      row.cost <= budget
  end
end

class ExportRow
  attr_reader :id, :owner_id, :cost

  def initialize(id:, owner_id:, cost:)
    @id = id
    @owner_id = owner_id
    @cost = cost
  end
end

class ExportBatch
  attr_reader :rows

  def initialize(rows)
    @rows = rows
  end
end

class ExportRowPolicy
  attr_reader :grant, :record

  def initialize(grant, record)
    @grant = grant
    @record = record
  end

  def export?
    grant.approves?(record)
  end
end

class ExportBatchPolicy
  class Scope
    def initialize(grant, batch)
      @grant = grant
      @batch = batch
    end

    def resolve
      @batch.rows.select { |row| @grant.approves?(row) }
    end
  end
end

# Each export task gets its own Pundit::Context and its own policy cache,
# so cached policies never leak from one task into another.
class ExportTask
  attr_reader :pundit

  def initialize(grant)
    @pundit = Pundit::Context.new(
      user: grant,
      policy_cache: Pundit::CacheStore::LegacyStore.new
    )
  end

  def exportable_rows(batch)
    pundit.policy_scope!(batch)
  end

  def export_row!(row)
    pundit.authorize(row, query: :export?, policy_class: nil)
  end

  def policy_for(row)
    pundit.policy!(row)
  end
end

RSpec.describe "Offline export with Pundit::Context" do
  let(:grant) do
    ExportGrant.new(requester: "alice", approved_owner_ids: [1, 2], budget: 100)
  end
  let(:task) { ExportTask.new(grant) }

  let(:approved_row) { ExportRow.new(id: 1, owner_id: 1, cost: 50) }
  let(:unapproved_owner_row) { ExportRow.new(id: 2, owner_id: 9, cost: 50) }
  let(:over_budget_row) { ExportRow.new(id: 3, owner_id: 1, cost: 150) }
  let(:batch) { ExportBatch.new([approved_row, unapproved_owner_row, over_budget_row]) }

  it "resolves the collection down to the approved scope" do
    expect(task.exportable_rows(batch)).to eq([approved_row])
  end

  it "authorizes a single record with the same fact as the collection" do
    expect(task.export_row!(approved_row)).to be(approved_row)
  end

  it "hands the very same grant object to policy and scope" do
    policy = task.policy_for(approved_row)

    expect(policy.grant).to be(grant)
    expect(task.pundit.user).to be(grant)
  end

  it "rejects records outside the approved owner scope" do
    expect { task.export_row!(unapproved_owner_row) }
      .to raise_error(Pundit::NotAuthorizedError)
  end

  it "rejects records outside the approved budget" do
    expect(task.exportable_rows(batch)).not_to include(over_budget_row)
    expect { task.export_row!(over_budget_row) }
      .to raise_error(Pundit::NotAuthorizedError)
  end

  context "without a requester" do
    let(:grant) do
      ExportGrant.new(requester: nil, approved_owner_ids: [1, 2], budget: 100)
    end

    it "resolves to an empty collection" do
      expect(task.exportable_rows(batch)).to eq([])
    end

    it "refuses to export any single record" do
      expect { task.export_row!(approved_row) }
        .to raise_error(Pundit::NotAuthorizedError)
    end
  end

  describe "policy cache isolation between tasks" do
    let(:other_grant) do
      ExportGrant.new(requester: "bob", approved_owner_ids: [9], budget: 500)
    end
    let(:other_task) { ExportTask.new(other_grant) }

    it "caches the policy within a task" do
      expect(task.policy_for(approved_row)).to equal(task.policy_for(approved_row))
    end

    it "does not inherit policies cached by another task" do
      policy = task.policy_for(approved_row)
      other_policy = other_task.policy_for(approved_row)

      expect(other_policy).not_to equal(policy)
      expect(policy.grant).to be(grant)
      expect(other_policy.grant).to be(other_grant)
    end

    it "authorizes the same record differently per task" do
      expect(other_task.export_row!(unapproved_owner_row)).to be(unapproved_owner_row)
      expect { task.export_row!(unapproved_owner_row) }
        .to raise_error(Pundit::NotAuthorizedError)
    end
  end
end
