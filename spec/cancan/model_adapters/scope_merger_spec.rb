# frozen_string_literal: true

require 'spec_helper'

# A department ability is expressed with an already filtered Active Record relation, while the
# project ability adds explicit hash approvals and denials. The combination must stay queryable
# whenever it can be expressed, and raise directly when a rule cannot be combined.
RSpec.describe CanCan::ModelAdapters::ScopeMerger do
  let(:ability) { double.extend(CanCan::Ability) }

  CanCan.valid_accessible_by_strategies.each do |strategy|
    context "with the #{strategy} strategy" do
      before do
        CanCan.accessible_by_strategy = strategy
        connect_db
        ActiveRecord::Migration.verbose = false
        ActiveRecord::Schema.define do
          create_table(:scope_merger_departments) do |t|
            t.string :name
            t.boolean :active, default: true
          end

          create_table(:scope_merger_projects) do |t|
            t.string :name
            t.integer :department_id
            t.boolean :archived, default: false
            t.integer :priority, default: 0
          end

          create_table(:scope_merger_milestones) do |t|
            t.integer :project_id
            t.boolean :completed, default: false
          end
        end

        stub_const('ScopeMergerDepartment', Class.new(ActiveRecord::Base) do
          self.table_name = 'scope_merger_departments'
          has_many :projects, class_name: 'ScopeMergerProject', inverse_of: :department
        end)

        stub_const('ScopeMergerProject', Class.new(ActiveRecord::Base) do
          self.table_name = 'scope_merger_projects'
          belongs_to :department, class_name: 'ScopeMergerDepartment', inverse_of: :projects
          has_many :milestones, class_name: 'ScopeMergerMilestone', inverse_of: :project

          scope :live, -> { where(archived: false) }
        end)

        stub_const('ScopeMergerMilestone', Class.new(ActiveRecord::Base) do
          self.table_name = 'scope_merger_milestones'
          belongs_to :project, class_name: 'ScopeMergerProject', inverse_of: :milestones
        end)
      end

      # The "department ability": projects that belong to an active department and are not archived.
      let(:department_relation) do
        ScopeMergerProject
          .joins(:department)
          .where(scope_merger_departments: { active: true })
          .live
      end

      def build_records
        active_department = ScopeMergerDepartment.create!(name: 'Engineering', active: true)
        inactive_department = ScopeMergerDepartment.create!(name: 'Legacy', active: false)

        records = {}
        records[:in_active_priority_one] =
          ScopeMergerProject.create!(name: 'A', department: active_department, priority: 1)
        records[:in_active_priority_two] =
          ScopeMergerProject.create!(name: 'B', department: active_department, priority: 2)
        records[:in_active_denied] =
          ScopeMergerProject.create!(name: 'C', department: active_department, priority: 1)
        records[:archived_in_active] =
          ScopeMergerProject.create!(name: 'D', department: active_department, archived: true)
        records[:in_inactive_priority_one] =
          ScopeMergerProject.create!(name: 'E', department: inactive_department, priority: 1)
        records
      end

      describe '#merge' do
        it 'returns nil when no rule uses a scope' do
          ability.can :read, ScopeMergerProject, priority: 1
          adapter = CanCan::ModelAdapters::AbstractAdapter.adapter_class(ScopeMergerProject)
          rules = ability.send(:relevant_rules_for_query, :read, ScopeMergerProject)

          merger = described_class.new(ScopeMergerProject, adapter.new(ScopeMergerProject, rules).compressed_rules)
          expect(merger.merge).to be_nil
        end

        it 'keeps the relation as the coverage domain when no other rule is present' do
          projects = build_records
          ability.can :read, ScopeMergerProject, department_relation

          accessible = ScopeMergerProject.accessible_by(ability)

          expect(accessible.map(&:id)).to match_array(
            [projects[:in_active_priority_one], projects[:in_active_priority_two],
             projects[:in_active_denied]].map(&:id)
          )
        end

        it 'unions explicit hash approvals with the scoped coverage domain' do
          projects = build_records
          ability.can :read, ScopeMergerProject, department_relation
          # The approval reaches an archived project that the coverage domain excludes.
          ability.can :read, ScopeMergerProject, name: 'D'

          accessible = ScopeMergerProject.accessible_by(ability)
          allowed_ids = accessible.map(&:id)

          expect(allowed_ids).to match_array(
            [
              projects[:in_active_priority_one],
              projects[:in_active_priority_two],
              projects[:in_active_denied],
              projects[:archived_in_active]
            ].map(&:id)
          )
          expect(allowed_ids).not_to include(projects[:in_inactive_priority_one].id)
        end

        it 'removes explicit hash denials from the scoped coverage domain' do
          projects = build_records
          ability.can :read, ScopeMergerProject, department_relation
          ability.cannot :read, ScopeMergerProject, name: 'C'

          accessible = ScopeMergerProject.accessible_by(ability)

          expect(accessible.map(&:id)).to match_array(
            [projects[:in_active_priority_one], projects[:in_active_priority_two]].map(&:id)
          )
        end

        it 'combines approvals and denials on top of the coverage domain' do
          projects = build_records
          ability.can :read, ScopeMergerProject, department_relation
          ability.can :read, ScopeMergerProject, name: 'D'
          ability.cannot :read, ScopeMergerProject, name: 'B'

          accessible = ScopeMergerProject.accessible_by(ability)

          expect(accessible.map(&:id)).to match_array(
            [
              projects[:in_active_priority_one],
              projects[:in_active_denied],
              projects[:archived_in_active]
            ].map(&:id)
          )
        end

        it 'filters through downstream associations with a nested hash condition' do
          projects = build_records
          blocked = projects[:in_active_priority_one]
          ScopeMergerMilestone.create!(project: blocked, completed: true)
          ability.can :read, ScopeMergerProject, department_relation
          ability.cannot :read, ScopeMergerProject, milestones: { completed: true }

          accessible = ScopeMergerProject.accessible_by(ability)

          expect(accessible.map(&:id)).not_to include(blocked.id)
          expect(accessible.map(&:id)).to include(projects[:in_active_priority_two].id)
        end

        it 'returns a chainable relation that keeps ordering and pagination' do
          projects = build_records
          ability.can :read, ScopeMergerProject, department_relation
          ability.cannot :read, ScopeMergerProject, name: 'C'

          accessible = ScopeMergerProject.accessible_by(ability)
          ordered = accessible.order(priority: :desc, id: :asc)
          first_page = ordered.limit(1).offset(0).to_a
          second_page = ordered.limit(1).offset(1).to_a

          expect(first_page).to eq([projects[:in_active_priority_two]])
          expect(second_page).to eq([projects[:in_active_priority_one]])
        end

        it 'exposes the denied ids as the complement of the allowed ids' do
          projects = build_records
          ability.can :read, ScopeMergerProject, department_relation
          ability.can :read, ScopeMergerProject, name: 'D'
          ability.cannot :read, ScopeMergerProject, name: 'C'

          allowed = ScopeMergerProject.accessible_by(ability).map(&:id)
          denied = ScopeMergerProject.pluck(:id) - allowed

          expect(allowed).to match_array(
            [
              projects[:in_active_priority_one],
              projects[:in_active_priority_two],
              projects[:archived_in_active]
            ].map(&:id)
          )
          expect(denied).to match_array(
            [
              projects[:in_active_denied],
              projects[:in_inactive_priority_one]
            ].map(&:id)
          )
        end

        it 'combines more than one scope through their primary keys' do
          projects = build_records
          archived_scope = ScopeMergerProject.where(archived: true)
          ability.can :read, ScopeMergerProject, department_relation
          ability.can :read, ScopeMergerProject, archived_scope

          accessible = ScopeMergerProject.accessible_by(ability)

          expect(accessible.map(&:id)).to match_array(
            [
              projects[:in_active_priority_one],
              projects[:in_active_priority_two],
              projects[:in_active_denied],
              projects[:archived_in_active]
            ].map(&:id)
          )
        end

        it 'raises a direct error when a scope is combined with raw SQL conditions' do
          ability.can :read, ScopeMergerProject, department_relation
          ability.can :read, ScopeMergerProject, ['priority = ?', 2]

          expect { ScopeMergerProject.accessible_by(ability) }
            .to raise_error(CanCan::Error,
                            'Unable to merge an Active Record scope with other conditions. ' \
                              'Instead use a hash or SQL for read ScopeMergerProject ability.')
        end

        it 'does not raise when the scope is an unrestricted relation' do
          build_records
          ability.can :read, ScopeMergerProject, priority: 1
          ability.can :read, ScopeMergerProject, ScopeMergerProject.all

          expect { ScopeMergerProject.accessible_by(ability) }.not_to raise_error
        end
      end
    end
  end
end
