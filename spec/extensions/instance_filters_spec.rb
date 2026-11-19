# frozen_string_literal: true
require_relative "spec_helper"

describe "instance_filters plugin" do
  before do
    @c = Class.new(Sequel::Model(:people))
    @c.columns :id, :name, :num
    @c.plugin :instance_filters
    @p = @c.load(:id=>1, :name=>'John', :num=>1)
    DB.sqls
  end

  it "should raise an error when updating a stale record" do
    @p.update(:name=>'Bob')
    DB.sqls.must_equal ["UPDATE people SET name = 'Bob' WHERE (id = 1)"]
    @p.instance_filter(:name=>'Jim')
    @p.instance_variable_set(:@this, @p.this.with_numrows(0))
    proc{@p.update(:name=>'Joe')}.must_raise(Sequel::Plugins::InstanceFilters::Error)
    DB.sqls.must_equal ["UPDATE people SET name = 'Joe' WHERE ((id = 1) AND (name = 'Jim'))"]
  end 

  it "should raise an error when destroying a stale record" do
    @p.destroy
    DB.sqls.must_equal ["DELETE FROM people WHERE id = 1"]
    @p.instance_filter(:name=>'Jim')
    @p.instance_variable_set(:@this, @p.this.with_numrows(0))
    proc{@p.destroy}.must_raise(Sequel::Plugins::InstanceFilters::Error)
    DB.sqls.must_equal ["DELETE FROM people WHERE ((id = 1) AND (name = 'Jim'))"]
  end 
  
  it "should work when using the prepared_statements plugin" do
    @c.plugin :prepared_statements

    @p.update(:name=>'Bob')
    DB.sqls.must_equal ["UPDATE people SET name = 'Bob' WHERE (id = 1)"]
    @p.instance_filter(:name=>'Jim')
    @p.instance_variable_set(:@this, @p.this.with_numrows(0))
    proc{@p.update(:name=>'Joe')}.must_raise(Sequel::Plugins::InstanceFilters::Error)
    DB.sqls.must_equal ["UPDATE people SET name = 'Joe' WHERE ((id = 1) AND (name = 'Jim'))"]

    @p = @c.load(:id=>1, :name=>'John', :num=>1)
    @p.instance_variable_set(:@this, @p.this.with_numrows(1))
    @c.instance_variable_set(:@fast_instance_delete_sql, nil)
    @p.destroy
    DB.sqls.must_equal ["DELETE FROM people WHERE (id = 1)"]
    @p.instance_filter(:name=>'Jim')
    @p.instance_variable_set(:@this, @p.this.with_numrows(0))
    proc{@p.destroy}.must_raise(Sequel::Plugins::InstanceFilters::Error)
    DB.sqls.must_equal ["DELETE FROM people WHERE ((id = 1) AND (name = 'Jim'))"]
    
    @c.create.must_be_kind_of(@c)
  end 
  
  it "should work when using the prepared_statements plugin when loading the prepared_statements plugin first" do
    @c = Class.new(Sequel::Model(:people))
    @c.columns :id, :name, :num
    @c.plugin :prepared_statements
    @c.plugin :instance_filters
    @p = @c.load(:id=>1, :name=>'John', :num=>1)
    DB.sqls

    @p.update(:name=>'Bob')
    DB.sqls.must_equal ["UPDATE people SET name = 'Bob' WHERE (id = 1)"]
    @p.instance_filter(:name=>'Jim')
    @p.instance_variable_set(:@this, @p.this.with_numrows(0))
    proc{@p.update(:name=>'Joe')}.must_raise(Sequel::Plugins::InstanceFilters::Error)
    DB.sqls.must_equal ["UPDATE people SET name = 'Joe' WHERE ((id = 1) AND (name = 'Jim'))"]

    @p = @c.load(:id=>1, :name=>'John', :num=>1)
    @p.instance_variable_set(:@this, @p.this.with_numrows(1))
    @c.instance_variable_set(:@fast_instance_delete_sql, nil)
    @p.destroy
    DB.sqls.must_equal ["DELETE FROM people WHERE (id = 1)"]
    @p.instance_filter(:name=>'Jim')
    @p.instance_variable_set(:@this, @p.this.with_numrows(0))
    proc{@p.destroy}.must_raise(Sequel::Plugins::InstanceFilters::Error)
    DB.sqls.must_equal ["DELETE FROM people WHERE ((id = 1) AND (name = 'Jim'))"]
    
    @c.create.must_be_kind_of(@c)
  end 
  
  it "should apply all instance filters" do
    @p.instance_filter(:name=>'Jim')
    @p.instance_filter{num > 2}
    @p.update(:name=>'Bob')
    DB.sqls.must_equal ["UPDATE people SET name = 'Bob' WHERE ((id = 1) AND (name = 'Jim') AND (num > 2))"]
  end 

  it "should drop instance filters after updating" do
    @p.instance_filter(:name=>'Joe')
    @p.update(:name=>'Joe')
    DB.sqls.must_equal ["UPDATE people SET name = 'Joe' WHERE ((id = 1) AND (name = 'Joe'))"]
    @p.update(:name=>'Bob')
    DB.sqls.must_equal ["UPDATE people SET name = 'Bob' WHERE (id = 1)"]
  end

  it "should drop instance filters after updating even if no columns were modified" do
    @p.instance_filter(:name=>'Joe')
    @p.update(:name=>'John')
    DB.sqls.must_equal []
    @p.update(:name=>'Bob')
    DB.sqls.must_equal ["UPDATE people SET name = 'Bob' WHERE (id = 1)"]
  end

  it "shouldn't allow instance filters on frozen objects" do
    @p.instance_filter(:name=>'Joe')
    @p.freeze
    proc{@p.instance_filter(:name=>'Jim')}.must_raise
  end 

  it "should have dup duplicate internal structures" do
    @p.instance_filter(:name=>'Joe')
    @p.dup.send(:instance_filters).must_equal @p.send(:instance_filters)
    @p.dup.send(:instance_filters).wont_be_same_as(@p.send(:instance_filters))
  end

  it "should treat filters without the dependent option as only applying to the object" do
    @p.instance_filter(:name=>'Joe')
    @p.send(:instance_filter_dependents?).must_equal true
    @p.send(:instance_filter_dependency_filters?).must_equal false
    @p.instance_filter_dataset(DB[:people]).sql.must_equal "SELECT * FROM people WHERE (name = 'Joe')"
  end

  it "should track instance dependency filters separately" do
    @p.instance_filter(:name=>'Joe')
    @p.instance_dependency_filter(:tenant_id=>1)
    @p.send(:instance_filter_dependents?).must_equal true
    @p.send(:instance_filter_dependency_filters?).must_equal true
    @p.instance_filter_dataset(DB[:people]).sql.must_equal "SELECT * FROM people WHERE ((name = 'Joe') AND (tenant_id = 1))"
    @p.instance_filter_dependency_dataset(DB[:people]).sql.must_equal "SELECT * FROM people WHERE (tenant_id = 1)"
  end

  it "should query the database to check if the object matches the filters" do
    @p.instance_filter_matches?.must_equal true
    @p.instance_filter(:name=>'Joe')
    DB.fetch = {:one=>1}
    @p.instance_filter_matches?.must_equal true
    DB.sqls.must_equal ["SELECT 1 AS v FROM people WHERE ((id = 1) AND (name = 'Joe')) LIMIT 1"]
    DB.fetch = []
    @p.instance_filter_matches?.must_equal false
  ensure
    DB.fetch = {:id=>1, :x=>1}
  end

  it "should raise an error when checking filters and the object does not match" do
    @p.instance_filter(:name=>'Joe')
    @p.instance_filter_check!.must_equal true
    DB.fetch = []
    proc{@p.instance_filter_check!}.must_raise(Sequel::Plugins::InstanceFilters::Error)
    @p.send(:instance_filters).wont_be_empty
  ensure
    DB.fetch = {:id=>1, :x=>1}
  end
end
