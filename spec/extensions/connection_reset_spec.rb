# frozen_string_literal: true
require_relative "spec_helper"

connection_reset_specs = Module.new do
  extend Minitest::Spec::DSL

  before do
    @db = db
    @m = Module.new do
      def disconnect_connection(conn)
        @sqls << 'disconnect'
      end
      def connect(server)
        conn = super
        conn.extend(Module.new do
          attr_accessor :reset_error
        end)
        conn
      end
      def _execute(conn, sql, opts=OPTS, &block)
        if sql == 'RESET ROLE' && (error = conn.reset_error)
          @sqls << sql
          raise error
        end
        super
      end
    end
    @db.extend @m
    @db.extension(:connection_reset)
    @db.pool.connection_reset = 'RESET ROLE'
  end

  it "should run configured reset on checkin and reuse the connection" do
    c1 = @db.synchronize{|c| c}
    @db.sqls.must_equal ['RESET ROLE']
    @db.synchronize{|c| c}.must_be_same_as c1
    @db.sqls.must_equal ['RESET ROLE']
  end

  it "should not run any reset if connection_reset is not set" do
    @db.pool.connection_reset = nil
    @db.synchronize{}
    @db.sqls.must_equal []
  end

  it "should support a callable as the reset" do
    @db.pool.connection_reset = proc{|conn| conn.execute('RESET ALL')}
    @db.synchronize{}
    @db.sqls.must_equal ['RESET ALL']
  end

  it "should disconnect connection and raise ResetError if reset fails for non-disconnect reasons" do
    c1 = @db.synchronize{|c| c}
    @db.sqls.must_equal ['RESET ROLE']
    error = Sequel::DatabaseError.new('cannot reset role')
    c1.reset_error = error
    e = proc{@db.synchronize{}}.must_raise Sequel::ConnectionReset::ResetError
    e.database_error.must_be_same_as error
    @db.sqls.must_equal ['RESET ROLE', 'disconnect']
    @db.pool.size.must_equal 0
    c2 = @db.synchronize{|c| c}
    c2.wont_be_same_as c1
    @db.sqls.must_equal ['RESET ROLE']
  end

  it "should disconnect connection and raise DatabaseDisconnectError if reset fails due to disconnect" do
    c1 = @db.synchronize{|c| c}
    @db.sqls.must_equal ['RESET ROLE']
    c1.reset_error = Sequel::DatabaseDisconnectError.new('connection lost')
    proc{@db.synchronize{}}.must_raise Sequel::DatabaseDisconnectError
    @db.sqls.must_equal ['RESET ROLE', 'disconnect']
    @db.pool.size.must_equal 0
    c2 = @db.synchronize{|c| c}
    c2.wont_be_same_as c1
    @db.sqls.must_equal ['RESET ROLE']
  end

  it "should run reset after rollback when transaction is interrupted, without retrying the transaction" do
    conn = nil
    count = 0
    proc do
      @db.transaction do |c|
        conn = c
        count += 1
        @db.run 'business'
        raise ArgumentError, 'interrupt'
      end
    end.must_raise ArgumentError
    count.must_equal 1
    @db.sqls.must_equal ['BEGIN', 'business', 'ROLLBACK', 'RESET ROLE']
    @db.synchronize{|c| c}.must_be_same_as conn
    @db.sqls.must_equal ['RESET ROLE']
  end

  it "should not run reset on connections discarded after disconnect errors during transaction" do
    count = 0
    proc do
      @db.transaction do
        count += 1
        raise Sequel::DatabaseDisconnectError
      end
    end.must_raise Sequel::DatabaseDisconnectError
    count.must_equal 1
    @db.sqls.must_equal ['BEGIN', 'ROLLBACK', 'disconnect']
    @db.pool.size.must_equal 0
  end

  it "should not hide an in-flight exception when reset fails during checkin" do
    c1 = @db.synchronize{|c| c}
    @db.sqls.must_equal ['RESET ROLE']
    c1.reset_error = Sequel::DatabaseError.new('cannot reset role')
    count = 0
    proc do
      @db.transaction do
        count += 1
        raise ArgumentError, 'interrupt'
      end
    end.must_raise ArgumentError
    count.must_equal 1
    @db.sqls.must_equal ['BEGIN', 'ROLLBACK', 'RESET ROLE', 'disconnect']
    @db.pool.size.must_equal 0
  end

  it "should not retry an already started transaction when reset fails after commit" do
    @db.extension(:transaction_connection_validator)
    c1 = @db.synchronize{|c| c}
    @db.sqls.must_equal ['RESET ROLE']
    c1.reset_error = Sequel::DatabaseDisconnectError.new('connection lost')
    count = 0
    proc do
      @db.transaction{count += 1}
    end.must_raise Sequel::DatabaseDisconnectError
    count.must_equal 1
    @db.sqls.must_equal ['BEGIN', 'COMMIT', 'RESET ROLE', 'disconnect']
    @db.pool.size.must_equal 0
  end
end

threaded_connection_reset_specs = Module.new do
  extend Minitest::Spec::DSL

  it "should handle :connection_handling => :disconnect setting" do
    @db = Sequel.mock(@db.opts.merge(:connection_handling => :disconnect))
    @db.extend @m
    @db.extension(:connection_reset)
    @db.pool.connection_reset = 'RESET ROLE'
    @db.synchronize{}
    @db.sqls.must_equal ['disconnect']
  end
end

describe "Sequel::ConnectionReset with single threaded pool" do
  it "should raise an error if trying to load the connection_reset extension into a single connection pool" do
    db = Sequel.mock(:test=>false, :pool_class=>:single)
    proc{db.extension(:connection_reset)}.must_raise Sequel::Error
  end
end

describe "Sequel::ConnectionReset with sharded single threaded pool" do
  it "should raise an error if trying to load the connection_reset extension into a single connection pool" do
    db = Sequel.mock(:test=>false, :pool_class=>:sharded_single)
    proc{db.extension(:connection_reset)}.must_raise Sequel::Error
  end
end

describe "Sequel::ConnectionReset with threaded pool" do
  def db
    Sequel.mock(:test=>false, :pool_class=>:threaded)
  end
  include connection_reset_specs
  include threaded_connection_reset_specs
end

describe "Sequel::ConnectionReset with sharded threaded pool" do
  def db
    Sequel.mock(:test=>false, :servers=>{}, :pool_class=>:sharded_threaded)
  end
  include connection_reset_specs
  include threaded_connection_reset_specs
end

describe "Sequel::ConnectionReset with timed_queue pool" do
  def db
    Sequel.mock(:test=>false, :pool_class=>:timed_queue)
  end
  include connection_reset_specs
end if RUBY_VERSION >= '3.2'

describe "Sequel::ConnectionReset with sharded_timed_queue pool" do
  def db
    Sequel.mock(:test=>false, :pool_class=>:sharded_timed_queue)
  end
  include connection_reset_specs
end if RUBY_VERSION >= '3.2'
