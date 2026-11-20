# frozen_string_literal: true
require_relative "spec_helper"

describe "A paginated dataset" do
  before do
    count = @count = [153]
    @d = Sequel.mock.dataset.extension(:pagination).with_extend{define_method(:count){count.first}}
    @paginated = @d.paginate(1, 20)
  end
  
  it "should raise an error if the dataset already has a limit" do
    proc{@d.limit(10).paginate(1,10)}.must_raise(Sequel::Error)
    proc{@paginated.paginate(2,20)}.must_raise(Sequel::Error)
    proc{@d.limit(10).each_page(10){|ds|}}.must_raise(Sequel::Error)
    proc{@d.limit(10).each_page(10)}.must_raise(Sequel::Error)
  end
  
  it "should set the limit and offset options correctly" do
    @paginated.opts[:limit].must_equal 20
    @paginated.opts[:offset].must_equal 0
  end
  
  it "should set the page count correctly" do
    @paginated.page_count.must_equal 8
    @d.paginate(1, 50).page_count.must_equal 4

    @count[0] = 0
    @d.paginate(1, 50).page_count.must_equal 1
  end
  
  it "should set the current page number correctly" do
    @paginated.current_page.must_equal 1
    @d.paginate(3, 50).current_page.must_equal 3
  end
  
  it "should return the next page number or nil if we're on the last" do
    @paginated.next_page.must_equal 2
    @d.paginate(4, 50).next_page.must_be_nil
  end
  
  it "should return the previous page number or nil if we're on the first" do
    @paginated.prev_page.must_be_nil
    @d.paginate(4, 50).prev_page.must_equal 3
  end
  
  it "should return the page range" do
    @paginated.page_range.must_equal(1..8)
    @d.paginate(4, 50).page_range.must_equal(1..4)
  end
  
  it "should return the record range for the current page" do
    @paginated.current_page_record_range.must_equal(1..20)
    @d.paginate(4, 50).current_page_record_range.must_equal(151..153)
    @d.paginate(5, 50).current_page_record_range.must_equal(0..0)
  end

  it "should return the record count for the current page" do
    @paginated.current_page_record_count.must_equal 20
    @d.paginate(3, 50).current_page_record_count.must_equal 50
    @d.paginate(4, 50).current_page_record_count.must_equal 3
    @d.paginate(5, 50).current_page_record_count.must_equal 0
  end

  it "should know if current page is last page" do
    @paginated.last_page?.must_equal false
    @d.paginate(2, 20).last_page?.must_equal false
    @d.paginate(5, 30).last_page?.must_equal false
    @d.paginate(6, 30).last_page?.must_equal true

    @count[0] = 0
    @d.paginate(1, 30).last_page?.must_equal true
    @d.paginate(2, 30).last_page?.must_equal false
  end

  it "should know if current page is first page" do
    @paginated.first_page?.must_equal true
    @d.paginate(1, 20).first_page?.must_equal true
    @d.paginate(2, 20).first_page?.must_equal false
  end

  it "should work with fixed sql" do
    ds = @d.clone(:sql => 'select * from blah')
    @count[0] = 150
    ds.paginate(2, 50).sql.must_equal 'SELECT * FROM (select * from blah) AS t1 LIMIT 50 OFFSET 50'
  end

  it "should not use at-least pagination by default" do
    @paginated.at_least_pagination?.must_equal false
    @paginated.has_next_page?.must_equal true
    @paginated.next_page?.must_equal true
  end
end

describe "At-least pagination" do
  def mock_rows(visible_ids)
    Sequel.mock(:fetch=>proc do |sql|
      offset = sql[/OFFSET (\d+)/, 1].to_i
      limit = sql[/LIMIT (\d+)/, 1].to_i
      (visible_ids[offset, limit] || []).map{|id| {:id=>id}}
    end)
  end

  before do
    @visible_ids = [1, 2, 4]
    @db = mock_rows(@visible_ids)
    @d = @db[:items].extension(:pagination).where(:authorized=>true).order(:id)
  end

  it "should not do a count query" do
    page = @d.paginate(1, 2, :at_least=>true)
    page.all
    @db.sqls.must_equal ['SELECT * FROM items WHERE (authorized IS TRUE) ORDER BY id LIMIT 2 OFFSET 0']
  end

  it "should not disclose record counts, page counts, or ranges" do
    page = @d.paginate(1, 2, :at_least=>true)
    page.at_least_pagination?.must_equal true
    page.pagination_record_count.must_be_nil
    page.page_count.must_be_nil
    page.page_range.must_be_nil
    page.current_page_record_count.must_be_nil
    page.current_page_record_range.must_be_nil
  end

  it "should use the same filter for the page query and the navigation query" do
    page = @d.paginate(1, 2, :at_least=>true)
    page.all.must_equal [{:id=>1}, {:id=>2}]
    page.has_next_page?.must_equal true
    page.next_page.must_equal 2
    @db.sqls.must_equal [
      'SELECT * FROM items WHERE (authorized IS TRUE) ORDER BY id LIMIT 2 OFFSET 0',
      'SELECT * FROM items WHERE (authorized IS TRUE) ORDER BY id LIMIT 1 OFFSET 2',
    ]
  end

  it "should use the navigation query to determine the last page" do
    page = @d.paginate(2, 2, :at_least=>true)
    page.all.must_equal [{:id=>4}]
    page.has_next_page?.must_equal false
    page.next_page.must_be_nil
    page.next_page?.must_equal false
    page.last_page?.must_equal true
    page.prev_page.must_equal 1
    page.first_page?.must_equal false
  end

  it "should not use a count or navigation query on the last page when the page is empty" do
    page = @d.paginate(3, 2, :at_least=>true)
    page.all.must_be_empty
    page.has_next_page?.must_equal false
    page.last_page?.must_equal true
    @db.sqls.must_equal [
      'SELECT * FROM items WHERE (authorized IS TRUE) ORDER BY id LIMIT 2 OFFSET 4',
      'SELECT * FROM items WHERE (authorized IS TRUE) ORDER BY id LIMIT 1 OFFSET 6',
    ]
  end

  it "should raise an error if a record count is provided with :at_least" do
    proc{@d.paginate(1, 2, 3, :at_least=>true)}.must_raise(Sequel::Error)
  end

  it "should raise an error if options are provided after an options hash" do
    proc{@d.paginate(1, 2, {:at_least=>true}, :foo=>true)}.must_raise(Sequel::Error)
  end

  it "should support each_page with :at_least without a count query" do
    pages = []
    enum = @d.each_page(2, :at_least=>true)
    enum.each{|page| pages << [page.current_page, page.all]}
    pages.must_equal [[1, [{:id=>1}, {:id=>2}]], [2, [{:id=>4}]]]
    @db.sqls.must_equal [
      'SELECT * FROM items WHERE (authorized IS TRUE) ORDER BY id LIMIT 2 OFFSET 0',
      'SELECT * FROM items WHERE (authorized IS TRUE) ORDER BY id LIMIT 1 OFFSET 2',
      'SELECT * FROM items WHERE (authorized IS TRUE) ORDER BY id LIMIT 2 OFFSET 2',
      'SELECT * FROM items WHERE (authorized IS TRUE) ORDER BY id LIMIT 1 OFFSET 4',
    ]
  end

  it "should return an enumerator from each_page with :at_least if no block is given" do
    enum = @d.each_page(2, :at_least=>true)
    enum.map{|page| page.current_page}.must_equal [1, 2]
  end

  it "should yield a single empty page from each_page with :at_least for an empty dataset" do
    @visible_ids.clear
    pages = []
    @d.each_page(2, :at_least=>true){|page| pages << page.all}
    pages.must_equal [[]]
    @db.sqls.must_equal [
      'SELECT * FROM items WHERE (authorized IS TRUE) ORDER BY id LIMIT 2 OFFSET 0',
      'SELECT * FROM items WHERE (authorized IS TRUE) ORDER BY id LIMIT 1 OFFSET 2',
    ]
  end

  it "should work with a dataset using fixed sql" do
    db = Sequel.mock(:fetch=>proc do |sql|
      sql =~ /OFFSET 2/ ? [] : [{:id=>1}, {:id=>2}]
    end)
    page = db.dataset.clone(:sql=>'select * from blah').extension(:pagination).paginate(1, 2, :at_least=>true)
    page.has_next_page?.must_equal false
  end
end

describe "Dataset#each_page" do
  before do
    @d = Sequel.mock[:items].extension(:pagination).with_extend{def count; 153 end}
  end
  
  it "should raise an error if the dataset already has a limit" do
    proc{@d.limit(10).each_page(10){}}.must_raise(Sequel::Error)
  end
  
  it "should iterate over each page in the resultset as a paginated dataset" do
    a = []
    @d.each_page(50) {|p| a << p}
    a.map {|p| p.sql}.must_equal [
      'SELECT * FROM items LIMIT 50 OFFSET 0',
      'SELECT * FROM items LIMIT 50 OFFSET 50',
      'SELECT * FROM items LIMIT 50 OFFSET 100',
      'SELECT * FROM items LIMIT 50 OFFSET 150',
    ]
  end

  it "should return an enumerator if no block is given" do
    enum = @d.each_page(50)
    enum.map {|p| p.sql}.must_equal [
      'SELECT * FROM items LIMIT 50 OFFSET 0',
      'SELECT * FROM items LIMIT 50 OFFSET 50',
      'SELECT * FROM items LIMIT 50 OFFSET 100',
      'SELECT * FROM items LIMIT 50 OFFSET 150',
    ]
  end
end

begin
  require 'sqlite3'
rescue LoadError
  warn "Skipping pagination SQLite specs: can't load sqlite3"
else
describe "pagination extension with SQLite" do
  def sql_log(db)
    sqls = []
    logger = Object.new
    logger.define_singleton_method(:info){|sql| sqls << sql.sub(/\A\([^)]*\) /, '')}
    db.loggers << logger
    sqls
  end

  before do
    @db = Sequel.sqlite
    @db.create_table(:tickets) do
      primary_key :id
      String :name
      TrueClass :visible
    end
    @db[:tickets].import([:id, :name, :visible], [
      [1, 'visible 1', true],
      [2, 'visible 2', true],
      [3, 'hidden 1', false],
      [4, 'visible 3', true],
      [5, 'hidden 2', false],
      [6, 'visible 4', true],
      [7, 'visible 5', true],
    ])
    @visible = @db[:tickets].where(:visible=>true).order(:id).extension(:pagination)
  end

  after do
    @db.disconnect
  end

  it "should paginate only visible rows continuously using next-page navigation" do
    sqls = sql_log(@db)
    rows = []
    page_no = 1
    loop do
      page = @visible.paginate(page_no, 2, :at_least=>true)
      page.at_least_pagination?.must_equal true
      page.pagination_record_count.must_be_nil
      page.page_count.must_be_nil
      rows.concat(page.all)
      break unless page.has_next_page?
      page_no = page.next_page
    end

    rows.must_equal [
      {:id=>1, :name=>'visible 1', :visible=>true},
      {:id=>2, :name=>'visible 2', :visible=>true},
      {:id=>4, :name=>'visible 3', :visible=>true},
      {:id=>6, :name=>'visible 4', :visible=>true},
      {:id=>7, :name=>'visible 5', :visible=>true},
    ]
    page_no.must_equal 3

    sqls.must_equal [
      'SELECT * FROM `tickets` WHERE (`visible` = 1) ORDER BY `id` LIMIT 2 OFFSET 0',
      'SELECT * FROM `tickets` WHERE (`visible` = 1) ORDER BY `id` LIMIT 1 OFFSET 2',
      'SELECT * FROM `tickets` WHERE (`visible` = 1) ORDER BY `id` LIMIT 2 OFFSET 2',
      'SELECT * FROM `tickets` WHERE (`visible` = 1) ORDER BY `id` LIMIT 1 OFFSET 4',
      'SELECT * FROM `tickets` WHERE (`visible` = 1) ORDER BY `id` LIMIT 2 OFFSET 4',
      'SELECT * FROM `tickets` WHERE (`visible` = 1) ORDER BY `id` LIMIT 1 OFFSET 6',
    ]
    sqls.each{|sql| sql.must_include "(`visible` = 1)"}
    sqls.wont_include 'SELECT count(*)'
  end

  it "should use each_page to return only visible rows in continuous pages" do
    sqls = sql_log(@db)
    pages = []
    @visible.each_page(2, :at_least=>true){|page| pages << page.all.map{|r| r[:id]}}
    pages.must_equal [[1, 2], [4, 6], [7]]
    sqls.grep(/count/i).must_be_empty
    sqls.each{|sql| sql.must_include "(`visible` = 1)"}
  end

  it "should not include hidden rows when the hidden rows would fill a page" do
    db = @db
    db[:tickets].where(:id=>4).update(:visible=>false)
    page = @visible.paginate(1, 2, :at_least=>true)
    page.all.map{|r| r[:id]}.must_equal [1, 2]
    page.has_next_page?.must_equal true
    page.next_page.must_equal 2

    page = @visible.paginate(2, 2, :at_least=>true)
    page.all.map{|r| r[:id]}.must_equal [6, 7]
    page.has_next_page?.must_equal false
  end

  it "should only consider visible rows when determining the next page" do
    db = @db
    db[:tickets].where(:visible=>true, :id=>[4, 6, 7]).delete
    page = @visible.paginate(1, 2, :at_least=>true)
    page.all.map{|r| r[:id]}.must_equal [1, 2]
    page.has_next_page?.must_equal false
    page.next_page.must_be_nil
  end

  it "should allow an internal report to use the exact total count" do
    page = @visible.paginate(1, 2)
    page.at_least_pagination?.must_equal false
    page.pagination_record_count.must_equal 5
    page.page_count.must_equal 3
    page.page_range.must_equal(1..3)
    page.current_page_record_count.must_equal 2
    page.has_next_page?.must_equal true
    page.last_page?.must_equal false

    page = @visible.paginate(3, 2)
    page.pagination_record_count.must_equal 5
    page.current_page_record_count.must_equal 1
    page.has_next_page?.must_equal false
    page.last_page?.must_equal true
    page.next_page.must_be_nil

    hidden = @db[:tickets].extension(:pagination).paginate(1, 10)
    hidden.pagination_record_count.must_equal 7
  end
end
end
