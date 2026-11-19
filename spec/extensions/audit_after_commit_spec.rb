# frozen_string_literal: true
require_relative "spec_helper"

describe "Sequel::Plugins::AuditAfterCommit" do
  before do
    @db = Sequel.mock(:numrows=>1)
    def @db.supports_savepoints?; true end
    @summaries = []
    summaries = @summaries
    @sink = lambda{|summary| summaries << summary}
    @c = Class.new(Sequel::Model(@db[:financial_records]))
    def @c.name; 'FinancialRecord' end
    @c.plugin :audit_after_commit, :sink=>@sink
    @c.columns :id, :amount, :status
    @o = @c.load(:id=>1, :amount=>100, :status=>'pending')
  end

  it "should raise an Error unless a :sink responding to call is provided" do
    proc{Class.new(Sequel::Model(@db[:financial_records])).plugin(:audit_after_commit)}.must_raise(Sequel::Error)
    proc{Class.new(Sequel::Model(@db[:financial_records])).plugin(:audit_after_commit, :sink=>Object.new)}.must_raise(Sequel::Error)
  end

  it "should publish the change summary immediately when not in a transaction" do
    @o.update(:amount=>150)
    @summaries.must_equal [{:model=>'FinancialRecord', :pk=>1, :changes=>{:amount=>[100, 150]}}]
  end

  it "should publish only the final change when the object is changed in the outer transaction and a committed savepoint" do
    @db.transaction do
      @o.update(:amount=>150)
      @db.transaction(:savepoint=>true) do
        @o.update(:amount=>200)
      end
    end
    @summaries.must_equal [{:model=>'FinancialRecord', :pk=>1, :changes=>{:amount=>[150, 200]}}]
  end

  it "should publish only the surviving outer change when the savepoint change is rolled back" do
    @db.transaction do
      @o.update(:amount=>150)
      @db.transaction(:savepoint=>true, :rollback=>:always) do
        @o.update(:amount=>200)
      end
    end
    @summaries.must_equal [{:model=>'FinancialRecord', :pk=>1, :changes=>{:amount=>[100, 150]}}]
  end

  it "should publish nothing when the whole transaction is rolled back" do
    @db.transaction(:rollback=>:always) do
      @o.update(:amount=>150)
      @db.transaction(:savepoint=>true) do
        @o.update(:amount=>200)
      end
    end
    @summaries.must_equal []
  end

  it "should publish nothing when a change without a transaction is rolled back" do
    @db.transaction(:rollback=>:always) do
      @o.update(:amount=>150)
    end
    @summaries.must_equal []
  end

  it "should publish one summary per committed transaction for repeated transactions" do
    @db.transaction{@o.update(:amount=>150)}
    @db.transaction{@o.update(:amount=>200)}
    @summaries.must_equal [
      {:model=>'FinancialRecord', :pk=>1, :changes=>{:amount=>[100, 150]}},
      {:model=>'FinancialRecord', :pk=>1, :changes=>{:amount=>[150, 200]}}
    ]
  end

  it "should only publish changes to the configured :columns" do
    c = Class.new(Sequel::Model(@db[:financial_records]))
    def c.name; 'FinancialRecord' end
    c.plugin :audit_after_commit, :sink=>@sink, :columns=>%i[amount]
    c.columns :id, :amount, :status
    o = c.load(:id=>1, :amount=>100, :status=>'pending')
    o.update(:status=>'approved')
    @summaries.must_equal []
    o.update(:amount=>150, :status=>'posted')
    @summaries.must_equal [{:model=>'FinancialRecord', :pk=>1, :changes=>{:amount=>[100, 150]}}]
  end

  it "should track objects independently" do
    o2 = @c.load(:id=>2, :amount=>500, :status=>'pending')
    @db.transaction do
      @o.update(:amount=>150)
      o2.update(:amount=>600)
    end
    @summaries.must_equal [
      {:model=>'FinancialRecord', :pk=>1, :changes=>{:amount=>[100, 150]}},
      {:model=>'FinancialRecord', :pk=>2, :changes=>{:amount=>[500, 600]}}
    ]
  end
end
