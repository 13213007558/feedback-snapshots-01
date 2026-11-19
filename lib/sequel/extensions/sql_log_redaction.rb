# frozen-string-literal: true
#
# The sql_log_redaction extension makes it possible to redact sensitive
# values from SQL log messages, without changing the SQL or arguments
# that are actually sent to the database.  This is useful for database
# operations, where statement templates are helpful for troubleshooting,
# but bound arguments and SQL comments may contain confidential data.
#
# This extension is opt-in.  By default, it redacts the values related
# to columns declared as sensitive, and leaves everything else alone:
#
#   DB.extension :sql_log_redaction
#   DB.register_sql_log_redaction(:accounts, :columns=>[:password, :ssn])
#   DB[:accounts].where(:name=>'foo', :password=>'secret').first
#   # Logger:
#   # SELECT * FROM accounts WHERE ((name = 'foo') AND (password = [REDACTED])) LIMIT 1
#
# The application still sends the original SQL and arguments to the
# database.  Only the string passed to the logger is changed.
#
# Comment fields can also be declared sensitive.  This works with
# comments added by the sql_comments extension, including comments added
# by Database#with_comments:
#
#   DB.register_sql_log_redaction(:accounts, :comment_fields=>[:user, :email])
#   DB.with_comments(:user=>'alice', :email=>'alice@example.com', :path=>'/accounts') do
#     DB[:accounts].all
#   end
#   # Logger:
#   # SELECT * FROM accounts -- user:[REDACTED],email:[REDACTED],path:/accounts
#
# The extension supports three logging strategies, controlled by
# Database#sql_log_redaction_mode:
#
# :redact :: The default.  Redact values for declared sensitive columns
#            and comment fields.  Other values are logged normally, and
#            prepared statement templates are included in the log message.
# :template :: Log the statement template only.  All SQL literals, bound
#              arguments, and comment values are replaced.  The statement
#              shape remains available for troubleshooting.
# :none :: Disable redaction.  Logs are the same as if this extension was
#          not loaded.
#
# Ordinary queries and prepared statements use the same rules.  For
# prepared statements, the logged message is the statement template
# (for example, <tt>EXECUTE name (SELECT ... WHERE password = $1)</tt>),
# and the logged arguments are redacted, whether or not the statement
# was already cached on the connection.  On an execution error, the error
# log contains the same redacted template and arguments.
#
# Database#sql_log_redaction_include_templates can be set to false to
# omit the template from prepared statement log messages, in which case
# only the statement name is logged.
#
# If a sensitive column is used in a data modification statement in a way
# that cannot be identified from the SQL with confidence (for example, an
# UPDATE with an expression), the extension fails closed for that log
# message and redacts the loggable values.  This only affects the log
# message, never the query sent to the database.
#
# Related module: Sequel::SQLLogRedaction

module Sequel
  module SQLLogRedaction
    # The placeholder used for redacted values in log messages.
    REDACTED = '[REDACTED]'.freeze

    # The placeholder used in place of literals when logging templates.
    TEMPLATE_VALUE = '?'.freeze

    # Tokens are used only for the log copy of the SQL.  +start+ and +finish+
    # are offsets into the original SQL string.
    Token = Struct.new(:type, :value, :start, :finish)

    # The information needed to log a given SQL string.
    Plan = Struct.new(:sql, :placeholder_indexes, :sensitive_arg_names, :fail_closed)

    def self.extended(db)
      db.instance_variable_set(:@sql_log_redaction_rules, {})
      db.instance_variable_set(:@sql_log_redaction_comment_fields, [])
      db.instance_variable_set(:@sql_log_redaction_include_templates, true)
      db.instance_variable_set(:@sql_log_redaction_value, REDACTED)
      db.instance_variable_set(:@sql_log_redaction_mode, :redact)
      db.instance_variable_set(:@sql_log_redaction_mutex, Mutex.new)
    end

    # A hash keyed by lowercased table name, with the sensitive columns,
    # comment fields, and model names declared for the table.
    attr_reader :sql_log_redaction_rules

    # The redaction strategy to use, one of :redact, :template, or :none.
    def sql_log_redaction_mode
      @sql_log_redaction_mode || :redact
    end

    # Set the redaction strategy, see the extension documentation for
    # the supported values.
    def sql_log_redaction_mode=(mode)
      mode = mode.to_sym if mode.is_a?(String)
      unless mode == :redact || mode == :template || mode == :none
        raise Error, "unsupported sql_log_redaction_mode: #{mode.inspect}"
      end
      @sql_log_redaction_mode = mode
    end

    # Whether prepared statement logs include the statement template.
    # True by default.
    def sql_log_redaction_include_templates?
      @sql_log_redaction_include_templates
    end

    # Set whether prepared statement logs include the statement template.
    def sql_log_redaction_include_templates=(v)
      @sql_log_redaction_include_templates = !!v
    end

    # The comment fields that should always be redacted from logged SQL.
    def sql_log_redaction_comment_fields
      @sql_log_redaction_comment_fields || []
    end

    # Set the comment fields that should always be redacted from logged SQL.
    def sql_log_redaction_comment_fields=(fields)
      @sql_log_redaction_comment_fields = Array(fields).map(&:to_s)
    end

    # The string used in place of redacted values.  Defaults to
    # <tt>[REDACTED]</tt>.
    def sql_log_redaction_value
      @sql_log_redaction_value || REDACTED
    end

    # Set the string used in place of redacted values.
    def sql_log_redaction_value=(v)
      @sql_log_redaction_value = v.to_s.freeze
    end

    # Declare the sensitive columns and comment fields for the given table
    # or model.  This may be called multiple times for the same table, and
    # the declarations will be merged.
    #
    # Options:
    # :columns :: An array of column names (or symbols) containing values
    #             that should not be logged.
    # :comment_fields :: An array of comment field names (or symbols) that
    #                    should not be logged.
    # :model :: The model class associated with the declaration, used by
    #           the sql_log_redaction model plugin.  This is optional.
    def register_sql_log_redaction(table, opts=OPTS)
      table = table.to_s.split('.').last.downcase
      columns = Array(opts[:columns]).map{|c| c.to_s.downcase}
      comment_fields = Array(opts[:comment_fields]).map(&:to_s)
      model_name = opts[:model].to_s if opts[:model]
      @sql_log_redaction_mutex.synchronize do
        rules = @sql_log_redaction_rules.dup
        entry = (rules[table] || {:columns=>[], :comment_fields=>[], :model_names=>[]}).dup
        entry[:columns] = entry[:columns] | columns
        entry[:comment_fields] = entry[:comment_fields] | comment_fields
        if model_name
          entry[:model_names] = (entry[:model_names] + [model_name]).uniq
        end
        rules[table] = entry
        @sql_log_redaction_rules = rules
        entry
      end
    end
    alias add_sql_log_redaction register_sql_log_redaction

    # Redact the message if an exception is logged directly with SQL in
    # the message, as the error_sql extension can do.
    def log_exception(exception, message)
      if message.is_a?(String) && sql_log_redaction_relevant?(message)
        message = sql_log_redaction_rewrite(message, nil).first
      end
      super
    end

    # Rewrite the log copy of the SQL and arguments, then log as normal.
    # The values passed to the block, and the values given to the database,
    # are not modified.
    def log_connection_yield(sql, conn, args=nil)
      return super if skip_logging?
      mode = sql_log_redaction_mode
      return super if mode == :none
      return super unless sql_log_redaction_relevant?(sql)
      sql, args = sql_log_redaction_rewrite(sql, args)
      super(sql, conn, args)
    end

    private

    # Whether the SQL could contain information that needs redaction.
    def sql_log_redaction_relevant?(sql)
      return false unless sql.is_a?(String)
      return true if sql_log_redaction_mode == :template
      return true unless @sql_log_redaction_comment_fields.empty?
      return false if @sql_log_redaction_rules.empty?
      if sql_log_redaction_prepared_sql?(sql)
        # Prepared statement messages may contain a template or only a name,
        # and the template may reference declared tables that the message
        # itself does not contain.
        return true
      end
      sql_lower = sql.downcase
      @sql_log_redaction_rules.any? do |table, entry|
        (!entry[:columns].empty? || !entry[:comment_fields].empty?) && sql_log_redaction_references_table?(sql_lower, table)
      end
    end

    # Whether the lowercased SQL references the given lowercased table,
    # without matching a longer identifier that contains the table name.
    def sql_log_redaction_references_table?(sql_lower, table)
      !!(sql_lower =~ /(?:\A|[^a-z0-9_])#{Regexp.escape(table)}(?:[^a-z0-9_]|\z)/)
    end

    def sql_log_redaction_rewrite(sql, args)
      return [sql, args] unless sql.is_a?(String)

      # Extensions such as caller_logging can prepend an annotation to the
      # log message before calling super.  Process the SQL separately from
      # the annotation so the annotation is never parsed as SQL.
      prefix = ''
      if sql =~ /\A(\(source: .*\)) (?=(?:SELECT|INSERT|UPDATE|DELETE|WITH|EXECUTE|Executing|BEGIN|COMMIT|ROLLBACK|PREPARE|CREATE|ALTER|DROP|TRUNCATE|SET|PRAGMA|SHOW|CALL)\b)/m
        prefix = "#{$1} "
        sql = $'
      end

      if sql_log_redaction_prepared_sql?(sql)
        info = sql_log_redaction_prepared_info(sql) || {}
        template = info[:template]
        if template
          plan = sql_log_redaction_plan(template)
          if info[:ps] && (prepared_args = info[:ps].prepared_args)
            prepared_args.each_with_index do |name, i|
              plan.sensitive_arg_names[name.to_s] = true if plan.placeholder_indexes[i+1]
            end
            # If any placeholder is not represented in prepared_args, the
            # argument mapping is not reliable, so redact all arguments.
            plan.fail_closed = true if prepared_args.length < plan.placeholder_indexes.keys.max.to_i
          end
          args = sql_log_redaction_redact_args(args, plan)
          text = "#{info[:verb]} #{info[:name]}"
          text += " (#{plan.sql})" if sql_log_redaction_include_templates?
          ["#{prefix}#{text}", args]
        else
          args = sql_log_redaction_redact_all_args(args) if args && !@sql_log_redaction_rules.empty?
          text = info[:verb] && info[:name] ? "#{info[:verb]} #{info[:name]}" : sql
          ["#{prefix}#{text}", args]
        end
      else
        plan = sql_log_redaction_plan(sql)
        ["#{prefix}#{plan.sql}", sql_log_redaction_redact_args(args, plan)]
      end
    end

    # Return whether the passed SQL is a prepared statement log message.
    def sql_log_redaction_prepared_sql?(sql)
      sql =~ /\A(?:EXECUTE|Executing)\s/
    end

    # For prepared statements, return the verb, name, and template from the
    # logged message.  Adapters use slightly different formats for this
    # message, but the statement name is always followed by an optional
    # parenthesized template.
    def sql_log_redaction_prepared_info(sql)
      return unless sql =~ /\A(EXECUTE|Executing)\s+([^\s(]+)(?:\s+\((.*)\))?\z/m
      verb, name, template = $1, $2, $3
      ps = begin
        prepared_statement(name.to_sym)
      rescue
        nil
      end
      template ||= ps.prepared_sql if ps
      {:verb=>verb, :name=>name, :template=>template, :ps=>ps}
    end

    def sql_log_redaction_plan(sql)
      tokens = sql_log_redaction_tokenize(sql)
      template_mode = sql_log_redaction_mode == :template
      tables = sql_log_redaction_tables(tokens)
      sensitive = template_mode ? {} : sql_log_redaction_sensitive_columns(tables)
      sensitive_tables = template_mode ? {} : sql_log_redaction_sensitive_tables(tables)
      comment_fields = sql_log_redaction_comment_fields_for(tables)

      if !template_mode && sensitive.empty? && comment_fields.empty?
        return Plan.new(sql, {}, {}, false)
      end

      replace = template_mode ? TEMPLATE_VALUE : sql_log_redaction_value
      marks = {}
      sensitive_placeholders = {}
      placeholders = {}
      ordinal = 0
      tokens.each do |t|
        if t.type == :placeholder
          ordinal += 1
          placeholders[t] = if t.value.start_with?('$')
            value = t.value[1..]
            value =~ /\A\d+\z/ ? value.to_i : nil
          else
            ordinal
          end
        end
      end

      fail_closed = false
      if template_mode
        tokens.each do |t|
          marks[t] = replace if t.type == :string || t.type == :number || t.type == :placeholder
        end
      else
        value_marks, value_placeholders, sensitive_ref, mapped = sql_log_redaction_mark_tokens(tokens, sensitive, sensitive_tables, replace)
        fail_closed = sensitive_ref && !mapped && sql =~ /\A\s*(?:INSERT|UPDATE|DELETE)\b/i
        # NOTE: fail_closed only applies when the sensitive reference was not mapped
        if fail_closed
          tokens.each do |t|
            marks[t] = replace if t.type == :string || t.type == :number
            sensitive_placeholders[t] = true if t.type == :placeholder
          end
        else
          marks = value_marks
          sensitive_placeholders = value_placeholders
        end
      end

      unless comment_fields.empty?
        tokens.each do |t|
          next unless t.type == :comment
          text = sql_log_redaction_redact_comment(t.value, comment_fields)
          marks[t] = text if text != t.value
        end
      end

      placeholder_indexes = {}
      if template_mode
        placeholders.each do |t, i|
          placeholder_indexes[i || placeholders.keys.index(t) + 1] = true
        end
      else
        placeholders.each do |t, i|
          next unless sensitive_placeholders[t] || marks.key?(t)
          placeholder_indexes[i || placeholders.keys.index(t) + 1] = true
        end
      end

      Plan.new(sql_log_redaction_apply_marks(sql, marks), placeholder_indexes, {}, fail_closed)
    end

    # Return the lowercased identifiers present in the SQL.  Used to limit
    # declarations to the tables referenced by the query.
    def sql_log_redaction_tables(tokens)
      tables = {}
      tokens.each do |t|
        if t.type == :ident || t.type == :quoted_ident
          value = t.value.downcase
          tables[value] = true
          tables[$1] = true if value =~ /\A(.+)\.[^.]+\z/
        end
      end
      tables
    end

    # Return the set of lowercased sensitive column names for tables that
    # are referenced in the given SQL.
    def sql_log_redaction_sensitive_columns(tables)
      cols = {}
      @sql_log_redaction_rules.each do |table, entry|
        next unless tables[table]
        entry[:columns].each{|c| cols[c] = true}
      end
      cols
    end

    # Return the lowercased table names with sensitive columns that are
    # referenced in the given SQL.
    def sql_log_redaction_sensitive_tables(tables)
      sensitive_tables = {}
      @sql_log_redaction_rules.each do |table, entry|
        sensitive_tables[table] = true if tables[table] && !entry[:columns].empty?
      end
      sensitive_tables
    end

    # Return the comment fields that should be redacted for the tables
    # referenced in the given SQL, combined with the global fields.
    def sql_log_redaction_comment_fields_for(tables)
      fields = sql_log_redaction_comment_fields.dup
      @sql_log_redaction_rules.each do |table, entry|
        next unless tables[table]
        fields |= entry[:comment_fields]
      end
      fields
    end

    # Keywords that compare a column with a value.
    OPERATOR_KEYWORDS = %w[LIKE ILIKE SIMILAR REGEXP IN BETWEEN IS].freeze

    # Keywords that end an expression when scanning to the left.
    LEFT_EXPRESSION_BOUNDARIES = %w[
      AND OR WHERE SET ON HAVING SELECT VALUES WHEN THEN ELSE BY ORDER GROUP
      LIMIT OFFSET RETURNING USING FROM JOIN LEFT RIGHT INNER OUTER CROSS FULL
      UNION EXCEPT INTERSECT AS
    ].freeze

    # Keywords that end an expression when scanning to the right.
    RIGHT_EXPRESSION_BOUNDARIES = %w[
      AND OR WHERE SET ON HAVING LIMIT OFFSET RETURNING ORDER GROUP FOR
      UNION EXCEPT INTERSECT WHEN THEN ELSE END AS USING JOIN LEFT RIGHT
      INNER OUTER CROSS FULL
    ].freeze

    # Punctuation that compares a column with a value.
    OPERATOR_PUNCTUATION = %w[= < > <= >= <> != ~ ~* !~ !~*].freeze

    # Mark the loggable values related to sensitive columns.  Returns the
    # literal marks, placeholder tokens needing argument redaction, whether
    # a sensitive column was referenced, and whether any value was mapped.
    def sql_log_redaction_mark_tokens(tokens, sensitive, sensitive_tables, replace)
      marks = {}
      placeholders = {}
      sensitive_ref = false
      mapped = false

      tokens.each_with_index do |t, j|
        next unless sql_log_redaction_operator?(t)
        next unless left = sql_log_redaction_left_expression(tokens, j)
        next unless right = sql_log_redaction_right_expression(tokens, j)

        left_sensitive = sql_log_redaction_sensitive_tokens?(tokens, left, sensitive)
        right_sensitive = sql_log_redaction_sensitive_tokens?(tokens, right, sensitive)
        next unless left_sensitive || right_sensitive
        sensitive_ref = true

        if left_sensitive
          mapped = true if sql_log_redaction_mark_range(tokens, right, marks, placeholders, replace)
        end
        if right_sensitive
          mapped = true if sql_log_redaction_mark_range(tokens, left, marks, placeholders, replace)
        end

        # For BETWEEN, the upper bound comes after the AND keyword.
        if t.type == :ident && t.value.upcase == 'BETWEEN' && left_sensitive
          if second = sql_log_redaction_between_second_expression(tokens, right[1])
            mapped = true if sql_log_redaction_mark_range(tokens, second, marks, placeholders, replace)
          end
        end
      end

      insert_marks, insert_placeholders, insert_ref, insert_mapped = sql_log_redaction_mark_insert_values(tokens, sensitive, sensitive_tables, replace)
      marks.merge!(insert_marks)
      placeholders.merge!(insert_placeholders)
      sensitive_ref ||= insert_ref
      mapped ||= insert_mapped

      [marks, placeholders, sensitive_ref, mapped]
    end

    def sql_log_redaction_operator?(token)
      if token.type == :punct
        OPERATOR_PUNCTUATION.include?(token.value)
      elsif token.type == :ident
        OPERATOR_KEYWORDS.include?(token.value.upcase)
      else
        false
      end
    end

    # Return the [first, last] token indexes for the expression to the left
    # of the operator at index j, or nil if there is no left expression.
    def sql_log_redaction_left_expression(tokens, j)
      i = j - 1
      depth = 0
      start = j
      while i >= 0
        t = tokens[i]
        if t.type == :punct && t.value == ')'
          depth += 1
        elsif t.type == :punct && t.value == '('
          depth -= 1 if depth > 0
        elsif depth == 0 && sql_log_redaction_left_boundary?(t)
          break
        end
        start = i
        i -= 1
      end
      return nil if start == j
      [start, j-1]
    end

    # Return the [first, last] token indexes for the expression to the right
    # of the operator at index j, or nil if there is no right expression.
    def sql_log_redaction_right_expression(tokens, j)
      i = j + 1
      depth = 0
      finish = j
      while i < tokens.length
        t = tokens[i]
        if t.type == :punct && t.value == '('
          depth += 1
        elsif t.type == :punct && t.value == ')'
          break if depth == 0
          depth -= 1
        elsif t.type == :ident && t.value.upcase == 'SELECT'
          break
        elsif depth == 0 && sql_log_redaction_right_boundary?(t)
          break
        end
        finish = i
        i += 1
      end
      return nil if finish == j
      [j+1, finish]
    end

    # Return the [first, last] token indexes for the expression between
    # the AND keyword after a BETWEEN and the end of the expression.
    def sql_log_redaction_between_second_expression(tokens, start)
      i = start
      depth = 0
      while i < tokens.length
        t = tokens[i]
        if t.type == :punct && t.value == '('
          depth += 1
        elsif t.type == :punct && t.value == ')'
          break if depth == 0
          depth -= 1
        elsif depth == 0 && t.type == :ident && t.value.upcase == 'AND'
          return sql_log_redaction_right_expression(tokens, i)
        end
        i += 1
      end
      nil
    end

    def sql_log_redaction_left_boundary?(token)
      if token.type == :punct
        token.value == ','
      elsif token.type == :ident
        LEFT_EXPRESSION_BOUNDARIES.include?(token.value.upcase)
      else
        false
      end
    end

    def sql_log_redaction_right_boundary?(token)
      if token.type == :punct
        token.value == ','
      elsif token.type == :ident
        RIGHT_EXPRESSION_BOUNDARIES.include?(token.value.upcase)
      else
        false
      end
    end

    # Whether the expression range contains a sensitive column.
    def sql_log_redaction_sensitive_tokens?(tokens, range, sensitive)
      range[0].upto(range[1]) do |i|
        t = tokens[i]
        return true if sql_log_redaction_identifier?(t) && sensitive[t.value.downcase]
      end
      false
    end

    # Mark the loggable values in the expression range.  Returns true if
    # any value was marked.
    def sql_log_redaction_mark_range(tokens, range, marks, placeholders, replace)
      count = 0
      range[0].upto(range[1]) do |i|
        t = tokens[i]
        if t.type == :string || t.type == :number
          marks[t] = replace
          count += 1
        elsif t.type == :placeholder
          placeholders[t] = true
          count += 1
        end
      end
      count > 0
    end

    # Mark the loggable values in INSERT statements that include sensitive
    # columns.
    def sql_log_redaction_mark_insert_values(tokens, sensitive, sensitive_tables, replace)
      marks = {}
      placeholders = {}
      sensitive_ref = false
      mapped = false
      i = 0
      while i < tokens.length
        t = tokens[i]
        unless t.type == :ident && t.value.upcase == 'INSERT'
          i += 1
          next
        end
        j = sql_log_redaction_next_token(tokens, i+1)
        unless j && tokens[j].type == :ident && tokens[j].value.upcase == 'INTO'
          i += 1
          next
        end
        j = sql_log_redaction_next_token(tokens, j+1)
        table_name = nil
        while j && sql_log_redaction_identifier?(tokens[j])
          table_name = tokens[j].value.downcase
          nxt = sql_log_redaction_next_token(tokens, j+1)
          unless nxt && tokens[nxt].type == :punct && tokens[nxt].value == '.'
            j = nxt
            break
          end
          j = sql_log_redaction_next_token(tokens, nxt+1)
        end
        unless j
          i += 1
          next
        end
        if table_name && sensitive_tables[table_name] && !(tokens[j].type == :punct && tokens[j].value == '(')
          # An INSERT without a column list cannot be mapped to sensitive
          # columns, so fail closed for this statement.
          sensitive_ref = true
          i += 1
          next
        end
        while j && !(tokens[j].type == :punct && tokens[j].value == '(')
          j = sql_log_redaction_next_token(tokens, j+1)
        end
        unless j
          i += 1
          next
        end
        cols, j = sql_log_redaction_collect_items(tokens, j)
        insert_sensitive = cols.any? do |col|
          col_name = col.reverse.find{|ct| sql_log_redaction_identifier?(ct)}
          col_name && sensitive[col_name.value.downcase]
        end
        sensitive_ref ||= insert_sensitive
        v = j
        while v < tokens.length
          if tokens[v].type == :ident && tokens[v].value.upcase == 'VALUES'
            break
          end
          v += 1
        end
        unless v < tokens.length
          i += 1
          next
        end
        v = sql_log_redaction_next_token(tokens, v+1)
        while v && tokens[v].type == :punct && tokens[v].value == '('
          vals, v = sql_log_redaction_collect_items(tokens, v)
          cols.each_with_index do |col, idx|
            col_name = col.reverse.find{|ct| sql_log_redaction_identifier?(ct)}
            next unless col_name && sensitive[col_name.value.downcase]
            sensitive_ref = true
            mark_list = vals[idx] || []
            mark_list.each do |vt|
              if vt.type == :string || vt.type == :number
                marks[vt] = replace
                mapped = true
              elsif vt.type == :placeholder
                placeholders[vt] = true
                mapped = true
              end
            end
          end
          v = sql_log_redaction_next_token(tokens, v)
          v = sql_log_redaction_next_token(tokens, v+1) if v && tokens[v].type == :punct && tokens[v].value == ','
        end
        i += 1
      end
      [marks, placeholders, sensitive_ref, mapped]
    end

    # Collect the comma separated items in the passed parenthesized list.
    # +idx+ must point at the opening parenthesis.  Returns the items and
    # the index after the closing parenthesis.
    def sql_log_redaction_collect_items(tokens, idx)
      items = []
      current = []
      depth = 0
      i = idx
      while i < tokens.length
        t = tokens[i]
        if t.type == :punct
          case t.value
          when '('
            depth += 1
            current << t if depth > 1
          when ')'
            depth -= 1
            if depth == 0
              items << current unless current.empty?
              return [items, i+1]
            end
            current << t
          when ','
            if depth == 1
              items << current
              current = []
            else
              current << t
            end
          else
            current << t
          end
        else
          current << t
        end
        i += 1
      end
      [items, i]
    end

    def sql_log_redaction_next_token(tokens, idx)
      idx += 1 while idx < tokens.length && tokens[idx].type == :comment
      idx < tokens.length ? idx : nil
    end

    def sql_log_redaction_identifier?(token)
      token.type == :ident || token.type == :quoted_ident
    end

    # Redact argument values based on the plan, without changing the
    # original argument collection.
    def sql_log_redaction_redact_args(args, plan)
      return args if args.nil?
      if args.is_a?(Hash)
        out = {}
        args.each do |k, v|
          key = k.to_s
          redact = sql_log_redaction_mode == :template ||
            plan.fail_closed ||
            plan.sensitive_arg_names[key] ||
            plan.sensitive_arg_names[key.sub(/\A[$:]/, '')]
          out[k] = redact ? sql_log_redaction_value : v
        end
        out
      elsif args.respond_to?(:map)
        i = 0
        args.map do |v|
          i += 1
          (sql_log_redaction_mode == :template || plan.placeholder_indexes[i] || plan.fail_closed) ? sql_log_redaction_value : v
        end
      else
        args
      end
    end

    def sql_log_redaction_redact_all_args(args)
      if args.is_a?(Hash)
        args.each_with_object({}){|(k, _), h| h[k] = sql_log_redaction_value}
      elsif args.respond_to?(:map)
        args.map{sql_log_redaction_value}
      else
        args
      end
    end

    def sql_log_redaction_redact_comment(text, fields)
      if text.start_with?('--')
        '--' + sql_log_redaction_redact_comment_body(text[2..-1], fields)
      elsif text.start_with?('/*') && text.end_with?('*/')
        '/*' + sql_log_redaction_redact_comment_body(text[2...-2], fields) + '*/'
      else
        text
      end
    end

    def sql_log_redaction_redact_comment_body(body, fields)
      body.split(',', -1).map do |part|
        if part =~ /\A(\s*)([A-Za-z0-9_.-]+):(.*)\z/m && fields.include?($2)
          "#{$1}#{$2}:#{sql_log_redaction_value}"
        else
          part
        end
      end.join(',')
    end

    # Apply the token replacements to a copy of the SQL.
    def sql_log_redaction_apply_marks(sql, marks)
      return sql if marks.empty?
      changes = marks.map{|t, v| [t.start, t.finish, v]}.sort_by{|c| -c[0]}
      out = sql.dup
      changes.each do |start, finish, value|
        out[start...finish] = value
      end
      out
    end

    # Tokenize the SQL, for the log copy only.  This is intentionally a
    # small scanner that understands strings, quoted identifiers, comments,
    # numbers, placeholders, and punctuation.
    def sql_log_redaction_tokenize(sql)
      tokens = []
      i = 0
      len = sql.length
      while i < len
        c = sql[i]
        case c
        when " ", "\t", "\n", "\r"
          i += 1
        when "'"
          start = i
          i += 1
          while i < len
            if sql[i] == "'"
              if sql[i+1] == "'"
                i += 2
              else
                i += 1
                break
              end
            elsif sql[i] == "\\"
              i += 2
            else
              i += 1
            end
          end
          tokens << Token.new(:string, sql[start...i], start, i)
        when '"', '`'
          quote = c
          start = i
          i += 1
          value = String.new
          while i < len
            if sql[i] == quote
              if sql[i+1] == quote
                value << quote
                i += 2
              else
                i += 1
                break
              end
            else
              value << sql[i]
              i += 1
            end
          end
          tokens << Token.new(:quoted_ident, value, start, i)
        when '-'
          if sql[i+1] == '-'
            start = i
            i += 2
            i += 1 while i < len && sql[i] != "\n"
            tokens << Token.new(:comment, sql[start...i], start, i)
          else
            tokens << Token.new(:punct, c, i, i+1)
            i += 1
          end
        when '/'
          if sql[i+1] == '*'
            start = i
            finish = sql.index('*/', i+2)
            i = finish ? finish + 2 : len
            tokens << Token.new(:comment, sql[start...i], start, i)
          else
            tokens << Token.new(:punct, c, i, i+1)
            i += 1
          end
        when '$'
          if sql[i+1] && sql[i+1] =~ /[A-Za-z0-9_]/
            start = i
            i += 2
            i += 1 while i < len && sql[i] =~ /[A-Za-z0-9_]/
            tokens << Token.new(:placeholder, sql[start...i], start, i)
          else
            tokens << Token.new(:punct, c, i, i+1)
            i += 1
          end
        when '?'
          tokens << Token.new(:placeholder, c, i, i+1)
          i += 1
        when /\d/
          start = i
          i += 1
          i += 1 while i < len && sql[i] =~ /[\d.]/
          tokens << Token.new(:number, sql[start...i], start, i)
        when /[A-Za-z_]/
          start = i
          i += 1
          i += 1 while i < len && sql[i] =~ /[A-Za-z0-9_$]/
          tokens << Token.new(:ident, sql[start...i], start, i)
        else
          op = sql[i, 2]
          if %w[<= >= <> != || ::].include?(op)
            tokens << Token.new(:punct, op, i, i+2)
            i += 2
          else
            tokens << Token.new(:punct, c, i, i+1)
            i += 1
          end
        end
      end
      tokens
    end
  end

  Database.register_extension(:sql_log_redaction, SQLLogRedaction)
end
