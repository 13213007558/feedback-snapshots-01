# frozen_string_literal: true

# 设计稿 design/bulk-association-authorization.md 的可执行验证。
# 运行：sh .feedback/ruby-env.sh rspec -r active_record -Ispec design/bulk_association_verification_spec.rb
require 'spec_helper'

# --- 参考实现：两阶段批量调整服务对象 -------------------------------------

class BulkAdjBatchRejected < StandardError; end

# 服务端审计留痕（不对客户端披露）。
module BulkAdjAudit
  def self.entries
    @entries ||= []
  end

  def self.record(entry)
    entries << entry
  end
end

class BulkAssociationAdjuster
  GENERIC_FAILURE_MESSAGE = '批次中包含当前不可操作的记录，整批未执行'

  attr_reader :applied_count

  def initialize(ability, action: :update)
    @ability = ability
    @action = action
    @applied_count = 0
  end

  # 准备期：独立作用域筛选。快照，仅用于展示与预估，不构成提交证据。
  def preparable_scope
    BulkAdjArticle.accessible_by(@ability, @action)
  end

  # 应用期：单事务内逐条 reload + authorize!（提交时证据），任一失败整批回滚。
  def apply!(ids, category:)
    BulkAdjArticle.transaction do
      BulkAdjArticle.where(id: ids).order(:id).find_each do |record|
        record.reload
        @ability.authorize!(@action, record)
        record.update!(category: category)
        @applied_count += 1
      end
    end
  rescue CanCan::AccessDenied => e
    BulkAdjAudit.record(action: e.action, subject_id: e.subject.try(:id), message: e.message)
    @applied_count = 0 # 回滚后对外恒为 0
    raise BulkAdjBatchRejected, GENERIC_FAILURE_MESSAGE
  end
end

# --- 内存库模型 ------------------------------------------------------------

class BulkAdjUser < ActiveRecord::Base
  self.table_name = 'bulk_adj_users'
end

class BulkAdjCategory < ActiveRecord::Base
  self.table_name = 'bulk_adj_categories'
end

class BulkAdjArticle < ActiveRecord::Base
  self.table_name = 'bulk_adj_articles'
  belongs_to :user, class_name: 'BulkAdjUser'
  belongs_to :category, class_name: 'BulkAdjCategory', optional: true

  # 测试钩子：模拟"操作中"发生的并发属主变更。
  after_update :simulate_concurrent_reassignment, if: -> { Thread.current[:bulk_adj_reassign_to] }

  private

  def simulate_concurrent_reassignment
    target = BulkAdjArticle.where.not(id: id).order(:id).first
    target&.update_columns(user_id: Thread.current[:bulk_adj_reassign_to]) # rubocop:disable Rails/SkipsModelValidations
  end
end

class BulkAdjAbility
  include CanCan::Ability

  def initialize(user)
    can :read, BulkAdjArticle
    can :update, BulkAdjArticle, user_id: user.id
  end
end

# --- 验证 ------------------------------------------------------------------

RSpec.describe '批量调整关联的授权设计验证' do
  before :each do
    connect_db
    ActiveRecord::Migration.verbose = false
    ActiveRecord::Schema.define do
      create_table :bulk_adj_users, force: true do |t|
        t.string :name
      end
      create_table :bulk_adj_categories, force: true do |t|
        t.string :name
      end
      create_table :bulk_adj_articles, force: true do |t|
        t.string :name
        t.integer :user_id
        t.integer :category_id
      end
    end
  end

  after { Thread.current[:bulk_adj_reassign_to] = nil }

  let!(:owner) { BulkAdjUser.create!(name: 'owner') }
  let!(:intruder) { BulkAdjUser.create!(name: 'intruder') }
  let!(:category) { BulkAdjCategory.create!(name: 'target-category') }
  let!(:article_a) { BulkAdjArticle.create!(name: 'A', user: owner) }
  let!(:article_b) { BulkAdjArticle.create!(name: 'B', user: owner) }
  let(:ability) { BulkAdjAbility.new(owner) }
  let(:adjuster) { BulkAssociationAdjuster.new(ability) }

  describe '准备期：accessible_by 只是独立作用域筛选（快照）' do
    it '作用域随状态变化而改变，不能作为提交证据' do
      expect(adjuster.preparable_scope).to contain_exactly(article_a, article_b)

      # 状态在准备之后变化：B 被划走
      article_b.update_columns(user_id: intruder.id) # rubocop:disable Rails/SkipsModelValidations

      expect(adjuster.preparable_scope.reload).to contain_exactly(article_a)
    end
  end

  describe '应用期：提交时证据必须基于新鲜状态' do
    it '陈旧内存对象会误判，reload 后的 authorize! 才算证据' do
      stale = BulkAdjArticle.find(article_b.id)
      article_b.update_columns(user_id: intruder.id) # rubocop:disable Rails/SkipsModelValidations

      expect(ability.can?(:update, stale)).to be(true) # 陈旧对象：误判为可更新
      expect(ability.can?(:update, stale.reload)).to be(false) # 刷新后：真实判定
    end

    it '两条记录均在事务内通过 authorize! 后整批落库' do
      adjuster.apply!([article_a.id, article_b.id], category: category)

      expect(adjuster.applied_count).to eq(2)
      expect(article_a.reload.category).to eq(category)
      expect(article_b.reload.category).to eq(category)
    end
  end

  describe '异常回滚：操作中关联状态变化导致整批拒绝' do
    it '第二条在提交时失去授权，第一条的修改也被回滚，错误不披露记录 id' do
      # 准备期通过：两条都在作用域内
      expect(adjuster.preparable_scope).to contain_exactly(article_a, article_b)

      # 模拟 TOCTOU：A 落库的瞬间，B 的属主被并发划走
      Thread.current[:bulk_adj_reassign_to] = intruder.id

      expect { adjuster.apply!([article_a.id, article_b.id], category: category) }
        .to raise_error(BulkAdjBatchRejected, BulkAssociationAdjuster::GENERIC_FAILURE_MESSAGE)

      # 全批回滚：A 的关联调整被撤销，B 的属主变更也被撤销
      expect(article_a.reload.category).to be_nil
      expect(article_b.reload.user).to eq(owner)
      expect(article_b.reload.category).to be_nil

      # 较少披露：对外计数恒为 0，文案不含任何记录 id
      expect(adjuster.applied_count).to eq(0)
      begin
        adjuster.apply!([article_a.id, article_b.id], category: category)
      rescue BulkAdjBatchRejected => e
        expect(e.message).not_to include(article_a.id.to_s)
        expect(e.message).not_to include(article_b.id.to_s)
      end

      # 对内审计：服务端留痕了被拒主体
      expect(BulkAdjAudit.entries.last[:subject_id]).to eq(article_b.id)
    end
  end
end
