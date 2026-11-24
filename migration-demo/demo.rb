# frozen_string_literal: true

# 分页迁入数据库后的授权规则迁移演示
# 运行: sh .feedback/ruby-env.sh ruby migration-demo/demo.rb

require "active_record"
require "cancan"

ActiveRecord::Base.establish_connection(adapter: "sqlite3", database: ":memory:")
ActiveRecord::Schema.verbose = false
ActiveRecord::Schema.define do
  create_table :documents do |t|
    t.integer :owner_id
    t.boolean :published, null: false, default: false
    t.integer :review_score
  end
end

class Document < ActiveRecord::Base
  include CanCan::ModelAdditions
end

User = Struct.new(:id, :clearance)

PER_PAGE = 10
# 23 篇已发布文档；id=5 的 review_score=50，低于访客 clearance=60，
# 其余都是 90。这样“页中间恰好有一条被拒”。
USER = User.new(7, 60)
23.times do |i|
  Document.create!(owner_id: 99, published: true,
                   review_score: (i + 1 == 5 ? 50 : 90))
end

def banner(title)
  puts "\n#{'=' * 68}\n#{title}\n#{'=' * 68}"
end

def visible_ids_ruby(ability)
  Document.order(:id).to_a.select { |d| ability.can?(:read, d) }.map(&:id)
end

def check_equivalence(label, ability)
  sql_ids  = Document.accessible_by(ability, :read).order(:id).ids
  ruby_ids = visible_ids_ruby(ability)
  puts "#{label}: SQL ids == Ruby can? 过滤 ids  ->  #{sql_ids == ruby_ids ? '等价 ✔' : "不等价 ✘ (#{sql_ids} vs #{ruby_ids})"}"
  sql_ids
end

# ---------------------------------------------------------------------------
banner "场景 1：纯 hash 条件规则 —— 可直接下推 SQL，可证明等价"

hash_ability = Class.new do
  include CanCan::Ability
  def initialize(user)
    can :read, Document, published: true
    can :read, Document, owner_id: user.id
  end
end.new(USER)

puts Document.accessible_by(hash_ability, :read).to_sql
check_equivalence("hash 规则", hash_ability)

# ---------------------------------------------------------------------------
banner "场景 2：混入 block 规则 —— accessible_by 直接拒绝生成 SQL"

block_ability = Class.new do
  include CanCan::Ability
  def initialize(user)
    can :read, Document, published: true
    can :read, Document, owner_id: user.id
    # 业务规则：低于用户 clearance 的文档不可见（旧代码里的 Ruby block）
    cannot :read, Document do |doc|
      doc.review_score < user.clearance
    end
  end
end.new(USER)

begin
  Document.accessible_by(block_ability, :read).to_a
rescue CanCan::Error => e
  puts "accessible_by 抛出 CanCan::Error:"
  puts "  #{e.message.strip}"
end

# ---------------------------------------------------------------------------
banner "场景 3：朴素迁移 —— 先按 hash 规则分页，再在 Ruby 里二次过滤"

page1_raw   = Document.accessible_by(hash_ability, :read).order(:id).offset(0).limit(PER_PAGE).to_a
page1_naive = page1_raw.select { |d| block_ability.can?(:read, d) }
page2_raw   = Document.accessible_by(hash_ability, :read).order(:id).offset(PER_PAGE).limit(PER_PAGE).to_a
page2_naive = page2_raw.select { |d| block_ability.can?(:read, d) }

puts "SQL 层第 1 页原始 ids : #{page1_raw.map(&:id).inspect}  (id=5 被 block 拒绝)"
puts "二次过滤后第 1 页 ids : #{page1_naive.map(&:id).inspect}  -> 只有 #{page1_naive.size}/#{PER_PAGE} 条，页面出现空洞"
puts "二次过滤后第 2 页 ids : #{page2_naive.map(&:id).inspect}"

true_visible = visible_ids_ruby(block_ability)
true_page1   = true_visible.first(PER_PAGE)
puts "真实可见集的第 1 页   : #{true_page1.inspect}"
puts "页漂移: id=11 本应在第 1 页末尾，朴素方案把它挤到了第 2 页 -> " \
     "第 1 页少 1 条、跨页边界整体错位，total_count(=#{Document.accessible_by(hash_ability, :read).count}) 也多算了被拒记录"

# ---------------------------------------------------------------------------
banner "场景 4：修复方案 A —— block 改写成 SQL 条件，重新证明等价"

sql_ability = Class.new do
  include CanCan::Ability
  def initialize(user)
    can :read, Document, published: true
    can :read, Document, owner_id: user.id
    cannot :read, Document, review_score: 0...user.clearance
  end
end.new(USER)

puts Document.accessible_by(sql_ability, :read).to_sql
sql_ids = check_equivalence("改写后", sql_ability)
puts "改写后与旧 block 规则逐行一致: #{sql_ids == visible_ids_ruby(block_ability) ? '✔' : '✘'}"
puts "分页恢复正常: 第 1 页 = #{Document.accessible_by(sql_ability, :read).order(:id).limit(PER_PAGE).ids.inspect} (满 #{PER_PAGE} 条)"

# ---------------------------------------------------------------------------
banner "场景 5：修复方案 B —— block 真无法下推时，超取 + 补满（over-fetch & refill）"

def fetch_page(ability, page, per_page)
  visible, offset, fetched = [], 0, 0
  target_start = (page - 1) * per_page
  while visible.size < per_page
    batch = Document.accessible_by(hash_ability_for_batch, :read)
                    .order(:id).offset(offset).limit(per_page).to_a
    break if batch.empty?
    fetched += batch.size
    batch.each { |d| ability.can?(:read, d) && (visible << d if fetched > target_start) }
    offset += batch.size
    break if visible.size >= per_page
  end
  visible.first(per_page)
end

def hash_ability_for_batch
  @hash_ability_for_batch ||= Class.new do
    include CanCan::Ability
    def initialize(user)
      can :read, Document, published: true
      can :read, Document, owner_id: user.id
    end
  end.new(USER)
end

refilled = fetch_page(block_ability, 1, PER_PAGE)
puts "补满后第 1 页 ids: #{refilled.map(&:id).inspect} (满 #{PER_PAGE} 条，与真实可见集一致: #{refilled.map(&:id) == true_page1 ? '✔' : '✘'})"
puts "代价: 需要多轮查询；总条数无法从 SQL COUNT 得到，只能全量扫描或另存计数"

banner "全部场景演示完毕"
