# frozen_string_literal: true

require 'spec_helper'

# Regression coverage for keeping the two authorization entry points in sync before an
# Active Record upgrade:
#   * the list/pagination entry point: `Model.accessible_by(ability)` (SQL, with joins)
#   * the per-object detail entry point: `ability.can?(:read, record)` (in memory)
#
# The ability combines two association conditions, an explicit `cannot`, and a later
# `can` exception that overrides the deny. The data deliberately contains records with
# no association rows at all (which a missing LEFT OUTER JOIN / NULL handling would drop)
# and one record matching several join rows (which a join without de-duplication would
# surface more than once). Both rule orderings are run against SQLite.
#
# Every table and class is prefixed with `Reg` so this spec cannot share an Active Record
# schema cache or a Ruby constant with the models defined in other specs.
RSpec.describe 'accessible_by vs can? with association rules' do
  let(:ability) { double.extend(CanCan::Ability) }
  let(:page_size) { 2 }

  before :each do
    connect_db
    ActiveRecord::Migration.verbose = false

    ActiveRecord::Schema.define do
      create_table(:reg_documents) do |t|
        t.boolean :reg_archived, null: false, default: false
      end

      create_table(:reg_projects)

      create_table(:reg_project_memberships) do |t|
        t.references :reg_document, null: false
        t.references :reg_project, null: false
      end

      create_table(:reg_tags) do |t|
        t.string :reg_kind, null: false
      end

      create_table(:reg_document_tags) do |t|
        t.references :reg_document, null: false
        t.references :reg_tag, null: false
      end
    end

    class RegProject < ActiveRecord::Base
      has_many :reg_project_memberships, class_name: 'RegProjectMembership',
                                         foreign_key: :reg_project_id
      has_many :reg_documents, through: :reg_project_memberships
    end

    class RegProjectMembership < ActiveRecord::Base
      belongs_to :reg_document, class_name: 'RegDocument'
      belongs_to :reg_project, class_name: 'RegProject'
    end

    class RegTag < ActiveRecord::Base
      has_many :reg_document_tags, class_name: 'RegDocumentTag', foreign_key: :reg_tag_id
      has_many :reg_documents, through: :reg_document_tags
    end

    class RegDocumentTag < ActiveRecord::Base
      belongs_to :reg_document, class_name: 'RegDocument'
      belongs_to :reg_tag, class_name: 'RegTag'
    end

    class RegDocument < ActiveRecord::Base
      has_many :reg_project_memberships, class_name: 'RegProjectMembership',
                                         foreign_key: :reg_document_id
      has_many :reg_projects, through: :reg_project_memberships
      has_many :reg_document_tags, class_name: 'RegDocumentTag',
                                   foreign_key: :reg_document_id
      has_many :reg_tags, through: :reg_document_tags
    end

    @shared_project = RegProject.create!
    @gold_tag = RegTag.create!(reg_kind: 'gold')

    # 1: no association rows at all and not archived -> never granted, no matter the order.
    @doc1 = RegDocument.create!

    # 2: belongs to the shared project through a single join row -> granted by the project rule.
    @doc2 = RegDocument.create!
    @doc2.reg_projects << @shared_project

    # 3: tagged gold, not archived -> granted by the tag rule.
    @doc3 = RegDocument.create!
    @doc3.reg_tags << @gold_tag

    # 4: matches BOTH association conditions, one row each -> a union, never two objects.
    @doc4 = RegDocument.create!
    @doc4.reg_projects << @shared_project
    @doc4.reg_tags << @gold_tag

    # 5: archived and gold -> the explicit deny and the later exception collide here.
    @doc5 = RegDocument.create!(reg_archived: true)
    @doc5.reg_tags << @gold_tag

    # 6: matches several join rows for the SAME association condition. A join that does not
    #     de-duplicate would return this document multiple times.
    @doc6 = RegDocument.create!
    3.times { @doc6.reg_project_memberships.create!(reg_project: @shared_project) }

    # 7: archived, no associations and not gold -> the explicit deny keeps it out (negative
    #    control proving the cannot rule really constrains the result).
    @doc7 = RegDocument.create!(reg_archived: true)
  end

  # The same four rules, only the position of the overriding gold exception relative to
  # the explicit archived deny changes. These two orderings are the matrix under test.
  def define_ability(order)
    project_rule = -> { ability.can :read, RegDocument, reg_projects: { id: @shared_project.id } }
    tag_rule = -> { ability.can :read, RegDocument, reg_tags: { reg_kind: 'gold' } }
    deny_rule = -> { ability.cannot :read, RegDocument, reg_archived: true }

    case order
    when :deny_before_exception
      project_rule.call
      tag_rule.call
      deny_rule.call
      tag_rule.call
    when :exception_before_deny
      tag_rule.call
      project_rule.call
      tag_rule.call
      deny_rule.call
    else
      raise ArgumentError, "unknown order #{order.inspect}"
    end
  end

  # Pagination without an external gem: deterministic, ordered pages over the scope.
  def paginated_ids(scope, page)
    scope.order(:id).offset((page - 1) * page_size).limit(page_size).pluck(:id)
  end

  def total_pages(scope)
    (scope.count.to_f / page_size).ceil
  end

  def can_question_mark_ids
    RegDocument.order(:id).select { |document| ability.can?(:read, document) }.map(&:id)
  end

  shared_examples 'a consistent authorization scope' do
    before { define_ability(order) }

    it 'returns exactly the expected ordered ids from accessible_by' do
      expect(RegDocument.accessible_by(ability).order(:id).pluck(:id)).to eq(expected_ids)
    end

    it 'does not duplicate the record that matches several join rows' do
      expect(RegDocument.accessible_by(ability).count).to eq(expected_ids.size)
      expect(RegDocument.accessible_by(ability).map(&:id).tally.values).to all(eq(1))
    end

    it 'agrees object by object with can?' do
      accessible = RegDocument.accessible_by(ability).order(:id).pluck(:id)
      expect(accessible).to eq(can_question_mark_ids)

      RegDocument.order(:id).each do |document|
        expect(ability.can?(:read, document))
          .to eq(accessible.include?(document.id)),
              "can? mismatch for reg_document ##{document.id}"
      end
    end

    it 'paginates the same ordered set and reports the number of pages' do
      scope = RegDocument.accessible_by(ability)
      expect(total_pages(scope)).to eq((expected_ids.size.to_f / page_size).ceil)

      pages = (1..total_pages(scope)).map { |page| paginated_ids(scope, page) }
      expect(pages.flatten).to eq(expected_ids)
      expect(pages).to eq(expected_ids.each_slice(page_size).to_a)
      expect(paginated_ids(scope, total_pages(scope) + 1)).to eq([])
    end
  end

  context 'when the explicit deny is defined before the overriding exception' do
    # The later gold exception re-grants the archived, gold document (5).
    let(:expected_ids) { [@doc2, @doc3, @doc4, @doc5, @doc6].map(&:id) }
    let(:order) { :deny_before_exception }

    it_behaves_like 'a consistent authorization scope'

    it 'never grants the bare no-association documents through can?' do
      define_ability(:deny_before_exception)
      expect(ability.can?(:read, @doc1)).to be(false)
      expect(ability.can?(:read, @doc7)).to be(false)
    end
  end

  context 'when the overriding exception is defined before the explicit deny' do
    # The later archived deny wins over every earlier grant for the archived, gold
    # document (5), while the archived negative control (7) stays denied as well.
    let(:expected_ids) { [@doc2, @doc3, @doc4, @doc6].map(&:id) }
    let(:order) { :exception_before_deny }

    it_behaves_like 'a consistent authorization scope'

    it 'lets the final cannot rule override the earlier gold exception through can?' do
      define_ability(:exception_before_deny)
      expect(ability.can?(:read, @doc5)).to be(false)
      expect(ability.can?(:read, @doc1)).to be(false)
      expect(ability.can?(:read, @doc7)).to be(false)
    end
  end
end
