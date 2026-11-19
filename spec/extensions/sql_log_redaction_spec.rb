# frozen_string_literal: true
require_relative "spec_helper"

describe "sql_log_redaction database extension" do
  before do
    @log_stream = StringIO.new
    logger = @logger = Object.new
    log_stream = @log_stream
    logger.define_singleton_method(:info){|s| log_stream.write("INFO #{s}\n")}
    logger.define_singleton_method(:warn){|s| log_stream.write("WARN #{s}\n")}
    logger.define_singleton_method(:error){|s| log_stream.write("ERROR #{s}\n")}

    @db = Sequel.mock(:logger=>logger, :fetch=>{:id=>1, :name=>'foo'}, :numrows=>1, :autoid=>1)
    @db.extension(:sql_comments)
    @db.extension(:sql_log_redaction)
    @db.register_sql_log_redaction(:accounts, :columns=>[:password, :ssn], :comment_fields=>[:email])
    @ds = @db[:accounts]
  end

  def log_lines
    @log_stream.rewind
    @log_stream.read.split("\n")
  end

  def log_message
    log_lines.last.sub(/\A(?:INFO|WARN|ERROR) \(\d\.\d{6}s\) /, '')
  end

  it "should be disabled unless the extension is loaded" do
    db = Sequel.mock(:logger=>@logger)
    db[:accounts].where(:password=>'secret').first
    log_message.must_equal "SELECT * FROM accounts WHERE (password = 'secret') LIMIT 1"
  end

  it "should redact literals for declared sensitive columns, leaving other values alone" do
    @ds.where(:name=>'alice', :password=>'secret', :ssn=>'123').first
    log_message.must_equal "SELECT * FROM accounts WHERE ((name = 'alice') AND (password = [REDACTED]) AND (ssn = [REDACTED])) LIMIT 1"
  end

  it "should not change the SQL or arguments passed to the database" do
    args = [1, 'secret']
    yielded = nil
    @db.log_connection_yield("SELECT * FROM accounts WHERE ((id = ?) AND (password = ?))", nil, args){yielded = args}
    yielded.must_be_same_as args
    args.must_equal [1, 'secret']
    log_message.must_equal "SELECT * FROM accounts WHERE ((id = ?) AND (password = ?)); [1, \"[REDACTED]\"]"
  end

  it "should not change the SQL stored by the mock database" do
    @ds.where(:password=>'secret').first
    @db.sqls.must_equal ["SELECT * FROM accounts WHERE (password = 'secret') LIMIT 1"]
  end

  it "should redact sensitive values in INSERT statements" do
    @ds.insert(:name=>'foo', :password=>'secret', :ssn=>'123')
    log_message.must_equal "INSERT INTO accounts (name, password, ssn) VALUES ('foo', [REDACTED], [REDACTED])"
    @db.sqls.must_equal ["INSERT INTO accounts (name, password, ssn) VALUES ('foo', 'secret', '123')"]
  end

  it "should fail closed for INSERT statements without a column list when the table has sensitive columns" do
    @db.log_connection_yield("INSERT INTO accounts VALUES ('secret')", nil){}
    log_message.must_equal "INSERT INTO accounts VALUES ([REDACTED])"
  end

  it "should redact sensitive values in UPDATE statements" do
    @ds.where(:id=>1).update(:password=>'secret', :name=>'foo')
    log_message.must_equal "UPDATE accounts SET password = [REDACTED], name = 'foo' WHERE (id = 1)"
    @db.sqls.must_equal ["UPDATE accounts SET password = 'secret', name = 'foo' WHERE (id = 1)"]
  end

  it "should redact sensitive values in comparisons in either order, and for IN/BETWEEN/LIKE" do
    @ds.where(Sequel.lit('123 = ssn' => nil)).all rescue nil
    @ds.where(:ssn=>%w'1 2').all
    log_message.must_equal "SELECT * FROM accounts WHERE (ssn IN ([REDACTED], [REDACTED]))"
    @ds.where(Sequel.lit('ssn BETWEEN 1 AND 2')).all
    log_message.must_equal "SELECT * FROM accounts WHERE (ssn BETWEEN [REDACTED] AND [REDACTED])"
    @ds.where(:password=>'sec%').all
    log_message.must_equal "SELECT * FROM accounts WHERE (password = [REDACTED])"
  end

  it "should not redact columns from tables without declarations" do
    @db[:other].where(:password=>'secret', :name=>'foo').first
    log_message.must_equal "SELECT * FROM other WHERE ((password = 'secret') AND (name = 'foo')) LIMIT 1"
  end

  it "should redact comment fields declared for the model" do
    @db.with_comments(:email=>'alice@example.com', :path=>'/accounts') do
      @ds.where(:name=>'foo').first
    end
    log_message.must_equal "SELECT * FROM accounts WHERE (name = 'foo') LIMIT 1 -- email:[REDACTED],path:/accounts"
  end

  it "should redact comment fields in dataset specific comments" do
    @ds.comment("email:alice@example.com,path:/accounts").first
    log_message.must_equal "SELECT * FROM accounts LIMIT 1 -- email:[REDACTED],path:/accounts"
  end

  it "should redact declarations for other tables separately" do
    @db.register_sql_log_redaction(:other, :columns=>[:token])
    @db[:other].where(:password=>'secret', :token=>'abc').first
    log_message.must_equal "SELECT * FROM other WHERE ((password = 'secret') AND (token = [REDACTED])) LIMIT 1"
  end

  it "should not include the SQL or arguments for non-prepared log messages that do not match declared tables" do
    @db.register_sql_log_redaction(:other, :columns=>[:token])
    @db[:items].where(:token=>'secret').first
    log_message.must_equal "SELECT * FROM items WHERE (token = 'secret') LIMIT 1"
  end

  it "should support a custom redaction value" do
    @db.sql_log_redaction_value = '***'
    @ds.where(:password=>'secret').first
    log_message.must_equal "SELECT * FROM accounts WHERE (password = ***) LIMIT 1"
  end

  it "should log only the template when using the :template strategy" do
    @db.sql_log_redaction_mode = :template
    @ds.where(:name=>'foo', :password=>'secret').first
    log_message.must_equal "SELECT * FROM accounts WHERE ((name = ?) AND (password = ?)) LIMIT ?"
  end

  it "should not redact anything when using the :none strategy" do
    @db.sql_log_redaction_mode = :none
    @ds.where(:password=>'secret').first
    log_message.must_equal "SELECT * FROM accounts WHERE (password = 'secret') LIMIT 1"
  end

  it "should raise for invalid strategies" do
    proc{@db.sql_log_redaction_mode = :invalid}.must_raise Sequel::Error
  end

  it "should support declaring comment fields that apply to all tables" do
    @db.sql_log_redaction_comment_fields = [:token]
    @db.with_comments(:token=>'s3cr3t', :path=>'/x') do
      @db[:other].all
    end
    log_message.must_equal "SELECT * FROM other -- token:[REDACTED],path:/x"
  end

  it "should redact comment fields only for tables with declarations" do
    @db.with_comments(:email=>'alice@example.com', :path=>'/accounts') do
      @db[:other].all
    end
    log_message.must_equal "SELECT * FROM other -- email:alice@example.com,path:/accounts"
  end

  it "should redact arguments for emulated prepared statements without changing the SQL sent" do
    ps = @ds.where(:name=>:$n, :password=>:$p).prepare(:first, :by_name)
    ps.call(:n=>'alice', :p=>'secret')
    log_message.must_equal "SELECT * FROM accounts WHERE ((name = 'alice') AND (password = [REDACTED])) LIMIT 1"
    @db.sqls.must_equal ["SELECT * FROM accounts WHERE ((name = 'alice') AND (password = 'secret')) LIMIT 1"]
  end

  it "should redact arguments for emulated prepared statements called by name" do
    @ds.where(:name=>:$n, :password=>:$p).prepare(:first, :by_name)
    @db.call(:by_name, :n=>'bob', :p=>'hunter2')
    log_message.must_equal "SELECT * FROM accounts WHERE ((name = 'bob') AND (password = [REDACTED])) LIMIT 1"
    @db.sqls.must_equal ["SELECT * FROM accounts WHERE ((name = 'bob') AND (password = 'hunter2')) LIMIT 1"]
  end

  it "should work with caller_logging regardless of extension load order" do
    [[:caller_logging, :sql_log_redaction], [:sql_log_redaction, :caller_logging]].each do |first, second|
      stream = StringIO.new
      logger = Object.new
      logger.define_singleton_method(:info){|s| stream.write(s)}
      db = Sequel.mock(:logger=>logger)
      db.extension(first)
      db.extension(second)
      db.register_sql_log_redaction(:accounts, :columns=>[:password])
      db[:accounts].where(:password=>'secret', :name=>'foo').first
      stream.string.must_match(/\A\(\d\.\d{6}s\) \(source: #{__FILE__}:\d+:in [`']block/)
      stream.string.must_match(/WHERE \(\(password = \[REDACTED\]\) AND \(name = 'foo'\)\) LIMIT 1\z/)
    end
  end

  it "should redact the SQL stored by the error_sql extension when logging is enabled" do
    @db.extension(:error_sql)
    sql = "SELECT * FROM accounts WHERE (password = 'secret') LIMIT 1"
    error = proc do
      @db.log_connection_yield(sql, nil){raise Sequel::Error, 'boom'}
    end.must_raise Sequel::Error
    @db.log_exception(error, "SELECT * FROM accounts WHERE (password = 'secret') LIMIT 1")
    log_lines.last.must_equal "ERROR Sequel::Error: boom: SELECT * FROM accounts WHERE (password = [REDACTED]) LIMIT 1"
  end

  it "should work when the sql_comments extension is loaded before or after this extension" do
    db = Sequel.mock(:logger=>@logger)
    db.extension(:sql_log_redaction)
    db.extension(:sql_comments)
    db.register_sql_log_redaction(:accounts, :comment_fields=>[:email])
    db.with_comments(:email=>'alice@example.com', :path=>'/accounts'){db[:accounts].all}
    log_message.must_equal "SELECT * FROM accounts -- email:[REDACTED],path:/accounts"
  end

  it "should log the statement template for prepared statements and redact the bound arguments" do
    ps = @ds.where(:name=>:$n, :password=>:$p).prepare(:first, :by_name)
    @db.log_connection_yield("EXECUTE by_name (#{ps.prepared_sql})", nil, ['alice', 'secret']) do
      :result
    end
    log_message.must_equal "EXECUTE by_name (SELECT * FROM accounts WHERE ((name = $n) AND (password = $p)) LIMIT 1); [\"alice\", \"[REDACTED]\"]"
  end

  it "should resolve the template on a prepared statement cache hit when the adapter only logs the statement name" do
    ps = @ds.where(:name=>:$n, :password=>:$p).prepare(:first, :by_name)
    args = ['bob', 'hunter2']
    @db.log_connection_yield("EXECUTE by_name", nil, args){}
    log_message.must_equal "EXECUTE by_name (SELECT * FROM accounts WHERE ((name = $n) AND (password = $p)) LIMIT 1); [\"bob\", \"[REDACTED]\"]"
    args.must_equal ['bob', 'hunter2']
  end

  it "should not log the template for prepared statements when templates are disabled" do
    ps = @ds.where(:name=>:$n, :password=>:$p).prepare(:first, :by_name)
    @db.sql_log_redaction_include_templates = false
    @db.log_connection_yield("EXECUTE by_name", nil, ['bob', 'hunter2']){}
    log_message.must_equal "EXECUTE by_name; [\"bob\", \"[REDACTED]\"]
".strip
  end

  it "should redact all arguments for prepared statement executions that cannot be resolved" do
    @db.log_connection_yield("EXECUTE unknown_name", nil, ['bob', 'hunter2']){}
    log_message.must_equal "EXECUTE unknown_name; [\"[REDACTED]\", \"[REDACTED]\"]"
  end

  it "should redact bound arguments for a prepared statement when the placeholder is sensitive" do
    ps = @ds.where(:id=>:$id, :password=>:$p).prepare(:first, :by_id)
    @db.log_connection_yield("EXECUTE by_id (#{ps.prepared_sql})", nil, [1, 'secret']){}
    log_message.must_equal "EXECUTE by_id (SELECT * FROM accounts WHERE ((id = $id) AND (password = $p)) LIMIT 1); [1, \"[REDACTED]\"]"
  end

  it "should redact all arguments and literals when using the :template strategy for prepared statements" do
    ps = @ds.where(:name=>:$n, :password=>:$p).prepare(:first, :by_name)
    @db.sql_log_redaction_mode = :template
    @db.log_connection_yield("EXECUTE by_name (#{ps.prepared_sql})", nil, ['bob', 'hunter2']){}
    log_message.must_equal "EXECUTE by_name (SELECT * FROM accounts WHERE ((name = ?) AND (password = ?)) LIMIT ?); [\"[REDACTED]\", \"[REDACTED]\"]"
  end

  it "should log an execution error with the same redacted template and arguments" do
    sql = "SELECT * FROM accounts WHERE (password = 'secret') LIMIT 1"
    proc do
      @db.log_connection_yield(sql, nil){raise Sequel::Error, 'boom'}
    end.must_raise Sequel::Error
    log_message.must_equal "ERROR Sequel::Error: boom: SELECT * FROM accounts WHERE (password = [REDACTED]) LIMIT 1"
    sql.must_equal "SELECT * FROM accounts WHERE (password = 'secret') LIMIT 1"
  end

  it "should log a prepared statement execution error with the same redacted template and arguments" do
    ps = @ds.where(:name=>:$n, :password=>:$p).prepare(:first, :by_name)
    sql = "EXECUTE by_name (#{ps.prepared_sql})"
    proc do
      @db.log_connection_yield(sql, nil, ['bob', 'hunter2']){raise Sequel::Error, 'boom'}
    end.must_raise Sequel::Error
    log_message.must_equal "ERROR Sequel::Error: boom: EXECUTE by_name (SELECT * FROM accounts WHERE ((name = $n) AND (password = $p)) LIMIT 1); [\"bob\", \"[REDACTED]\"]"
    sql.must_equal "EXECUTE by_name (SELECT * FROM accounts WHERE ((name = $n) AND (password = $p)) LIMIT 1)"
  end

  it "should fail closed for data modification statements with a sensitive reference but no findable value" do
    @ds.where(:id=>1).update(Sequel.lit('password = password'))
    log_message.must_equal "UPDATE accounts SET password = password WHERE (id = [REDACTED])"
    @db.sqls.must_equal ["UPDATE accounts SET password = password WHERE (id = 1)"]
  end
end

native_prepared_spec = Module.new do
  def self.extended(db)
    bind_module = Sequel::Dataset.send(:prepared_statements_module, :bind, [Sequel::Dataset::UnnumberedArgumentMapper], %w'execute execute_dui')
    prepared_module = Sequel::Dataset.send(:prepared_statements_module, :prepare, bind_module, %w'execute execute_dui')
    db.extend_datasets(Module.new do
      private
      define_method(:prepared_statement_modules){[prepared_module]}
    end)
  end

  # Simulate an adapter with native prepared statement support, using the
  # log formats used by the built-in native adapters.
  def execute(sql, opts=OPTS, &block)
    if sql.is_a?(Symbol) || sql.is_a?(Sequel::Dataset::ArgumentMapper)
      execute_native_prepared_statement(sql, opts, &block)
    else
      super
    end
  end

  def execute_dui(sql, opts=OPTS, &block)
    if sql.is_a?(Symbol) || sql.is_a?(Sequel::Dataset::ArgumentMapper)
      execute_native_prepared_statement(sql, opts, &block)
    else
      super
    end
  end

  def native_prepared_executions
    @native_prepared_executions ||= []
  end

  private

  def execute_native_prepared_statement(ps, opts)
    if ps.is_a?(Sequel::Dataset::ArgumentMapper)
      name = ps.prepared_statement_name
    else
      name = ps
      ps = prepared_statement(name)
    end
    sql = ps.prepared_sql
    args = opts[:arguments]
    @native_prepared_cache ||= {}
    conn = synchronize(opts[:server]){|c| c}

    unless @native_prepared_cache[name] == sql
      log_connection_yield("PREPARE #{name} AS #{sql}", conn){}
      @native_prepared_cache[name] = sql
    end

    native_prepared_executions << [sql, args]
    log_connection_yield("EXECUTE #{name} (#{sql})", conn, args) do
      raise Sequel::DatabaseError, 'boom' if args && args.last == 'boom'
      {:id=>1}
    end
  end
end

describe "sql_log_redaction with native prepared statements" do
  before do
    @log_stream = StringIO.new
    logger = Object.new
    log_stream = @log_stream
    logger.define_singleton_method(:info){|s| log_stream.write("INFO #{s}\n")}
    logger.define_singleton_method(:warn){|s| log_stream.write("WARN #{s}\n")}
    logger.define_singleton_method(:error){|s| log_stream.write("ERROR #{s}\n")}

    @db = Sequel.mock(:logger=>logger, :fetch=>{:id=>1})
    @db.extend(native_prepared_spec)
    @db.extension(:sql_log_redaction)
    @db.register_sql_log_redaction(:accounts, :columns=>[:password])
    @ps = @db[:accounts].where(:name=>:$n, :password=>:$p).prepare(:first, :select_by_name)
    @log_stream.truncate(0)
    @log_stream.rewind
  end

  def log_lines
    @log_stream.rewind
    @log_stream.read.split("\n")
  end

  it "should log a prepared request and a cache hit with the same redacted template and arguments" do
    @ps.call(:n=>'alice', :p=>'s3cret')
    first = log_lines
    @log_stream.truncate(0)
    @log_stream.rewind
    @ps.call(:n=>'alice', :p=>'hunter2')
    second = log_lines

    first.length.must_equal 2
    first[0].must_match(/\AINFO \(\d\.\d{6}s\) PREPARE select_by_name AS SELECT \* FROM accounts WHERE \(\(name = \?\) AND \(password = \?\)\) LIMIT 1\z/)
    first[0].wont_match(/s3cret/)
    first[1].must_match(/EXECUTE select_by_name \(SELECT \* FROM accounts WHERE \(\(name = \?\) AND \(password = \?\)\) LIMIT 1\); \["alice", "\[REDACTED\]"\]\z/)

    second.length.must_equal 1
    second[0].must_match(/EXECUTE select_by_name \(SELECT \* FROM accounts WHERE \(\(name = \?\) AND \(password = \?\)\) LIMIT 1\); \["alice", "\[REDACTED\]"\]\z/)
    second[0].wont_match(/hunter2/)

    @db.native_prepared_executions.last(2).must_equal [
      ["SELECT * FROM accounts WHERE ((name = ?) AND (password = ?)) LIMIT 1", ['alice', 's3cret']],
      ["SELECT * FROM accounts WHERE ((name = ?) AND (password = ?)) LIMIT 1", ['alice', 'hunter2']],
    ]
  end

  it "should log an execution failure with the same redacted template and arguments" do
    proc{@ps.call(:n=>'alice', :p=>'boom')}.must_raise Sequel::DatabaseError
    log_lines.last.must_match(/ERROR Sequel::DatabaseError: boom: EXECUTE select_by_name \(SELECT \* FROM accounts WHERE \(\(name = \?\) AND \(password = \?\)\) LIMIT 1\); \["alice", "\[REDACTED\]"\]\z/)
    @db.native_prepared_executions.last.must_equal ["SELECT * FROM accounts WHERE ((name = ?) AND (password = ?)) LIMIT 1", ['alice', 'boom']]
  end
end

describe "sql_log_redaction model plugin" do
  before do
    @log_stream = StringIO.new
    logger = Object.new
    log_stream = @log_stream
    logger.define_singleton_method(:info){|s| log_stream.write("\n#{s}")}
    @db = Sequel.mock(:logger=>logger, :fetch=>{:id=>1, :name=>'foo'}, :numrows=>1)
    @db.extension(:sql_comments)

    @c = Class.new(Sequel::Model(@db[:accounts]))
    @c.columns :id, :name, :password, :ssn
    @c.plugin :sql_log_redaction, :columns=>[:password, :ssn], :comment_fields=>[:email]
    @db.sqls
    @log_stream.truncate(0)
    @log_stream.rewind
  end

  def log_message
    @log_stream.rewind
    @log_stream.read.split("\n").last.sub(/\A\(\d\.\d{6}s\) /, '')
  end

  it "should store the model declarations in the database" do
    @c.sql_log_redaction.must_equal({:columns=>[:password, :ssn], :comment_fields=>[:email]})
    @db.sql_log_redaction_rules['accounts'][:columns].must_equal %w'password ssn'
    @db.sql_log_redaction_rules['accounts'][:comment_fields].must_equal %w'email'
    @db.sql_log_redaction_rules['accounts'][:model_names].must_equal [@c.to_s]
  end

  it "should apply the declarations to dataset queries" do
    @c.where(:password=>'secret', :name=>'foo').first
    log_message.must_equal "SELECT * FROM accounts WHERE ((password = [REDACTED]) AND (name = 'foo')) LIMIT 1"
  end

  it "should apply the declarations to model save queries" do
    @c.load(:id=>1, :name=>'foo', :password=>'secret').update(:password=>'newsecret')
    log_message.must_equal "UPDATE accounts SET password = [REDACTED] WHERE (id = 1)"
  end

  it "should apply the declarations to model create queries" do
    @c.create(:name=>'foo', :password=>'secret')
    log_message.must_equal "SELECT * FROM accounts WHERE (id IS NULL) LIMIT 1"
    @log_stream.rewind
    @log_stream.read.split("\n").grep(/INSERT/).last.sub(/\A\(\d\.\d{6}s\) /, '').must_equal "INSERT INTO accounts (name, password) VALUES ('foo', [REDACTED])"
  end

  it "should redact comment fields for model queries when using the sql_comments plugin" do
    @c.plugin :sql_comments
    @c.find(:name=>'foo')
    log_message.must_equal "SELECT * FROM accounts WHERE (name = 'foo') LIMIT 1 -- model:#{@c},method_type:class,method:find"
  end

  it "should apply the declarations to association loads" do
    @c.many_to_one :account, :class=>@c, :key=>:id
    @c.load(:id=>1).account
    log_message.must_equal "SELECT * FROM accounts WHERE (id = 1) LIMIT 1"
  end

  it "should support :except column declarations" do
    c = Class.new(Sequel::Model(@db[:items]))
    c.columns :id, :name, :password
    c.plugin :sql_log_redaction, :columns=>{:except=>[:id, :name]}
    c.where(:password=>'secret', :name=>'foo').first
    log_message.must_equal "SELECT * FROM items WHERE ((password = [REDACTED]) AND (name = 'foo')) LIMIT 1"
  end

  it "should support :only column declarations" do
    c = Class.new(Sequel::Model(@db[:items2]))
    c.columns :id, :name, :password
    c.plugin :sql_log_redaction, :columns=>{:only=>[:password]}
    c.where(:password=>'secret', :name=>'foo').first
    log_message.must_equal "SELECT * FROM items2 WHERE ((password = [REDACTED]) AND (name = 'foo')) LIMIT 1"
  end

  it "should merge declarations made multiple times" do
    @c.set_sql_log_redaction(:columns=>[:token], :comment_fields=>[:user])
    @c.sql_log_redaction[:columns].must_equal [:password, :ssn, :token]
    @c.sql_log_redaction[:comment_fields].must_equal [:email, :user]
  end

  it "should work with a subclass of a model using the plugin" do
    c = Class.new(@c)
    c.dataset = @db[:other_items]
    c.columns :id, :name, :password
    c.where(:password=>'secret').first
    log_message.must_equal "SELECT * FROM other_items WHERE (password = [REDACTED]) LIMIT 1"
    c.sql_log_redaction[:columns].must_equal [:password, :ssn]
  end
end
