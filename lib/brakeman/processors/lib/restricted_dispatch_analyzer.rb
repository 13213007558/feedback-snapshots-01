require 'brakeman/util'

# Attempts to prove that the method name given to a dynamic dispatch
# (send/public_send/__send__/try, Method#call or Proc#call) can only be one
# of a fixed set of harmless methods.
#
# The analysis is intentionally restricted. A proof is only accepted when the
# method name can be traced through one of these patterns:
#
# 1. A provable literal mapping:
#
#      name = FIXED_HASH[request_value]   # every hash value is a literal
#      name = FIXED_ARRAY.fetch(request_value, :safe)
#
# 2. A case/when dispatch where every branch assigns a literal:
#
#      case request_value
#      when :a then name = :one
#      when :b then name = :two
#      else fail # or return/raise
#      end
#
# 3. An early-reject branch guarding a fixed allow list:
#
#      fail unless [:a, :b].include?(request_value)
#      obj.send(request_value)
#
# Anything outside these patterns (later reassignment, a default branch that
# falls back to the request value, a mutated allow list, an unknown method
# call producing the name, ...) invalidates the proof. When a proof cannot be
# established the analyzer reports +proven?+ as false and records the location
# where the proof was lost, so checks can lower their confidence instead of
# claiming the dispatch is safe.
class Brakeman::RestrictedDispatchAnalyzer
  include Brakeman::Util

  UNPROVEN = :BRAKEMAN_DISPATCH_UNPROVEN

  DISPATCH_METHODS = [:send, :public_send, :__send__, :try].freeze

  # Methods that mutate a collection in place. If any of these touch a
  # constant/literal collection relied on by a proof, the proof is invalid.
  MUTATING_METHODS = [
    :<<, :push, :append, :pop, :shift, :unshift,
    :[]=, :merge!, :update, :replace, :delete, :delete_if,
    :reject!, :select!, :filter!, :keep_if, :clear, :insert,
    :prepend, :concat, :collect!, :map!, :flatten!, :uniq!
  ].to_set.freeze

  Proof = Struct.new(:proven, :methods, :entry, :lost_at, :reason, keyword_init: true) do
    def proven?
      proven
    end
  end

  # Runs the analysis against a method body.
  #
  # +dispatch_call+ is the send/call expression from the call index (which
  # may be alias-processed), +method_body+ the enclosing method (the analyzer
  # handles both the raw and alias-processed forms), and +known_constants+
  # maps constant names to literal collection Sexps resolved outside the
  # method body.
  def self.analyze method_body, dispatch_call, known_constants = {}
    new(known_constants).analyze(method_body, dispatch_call)
  end

  def initialize known_constants = {}
    # Variable name (Symbol) => tracked value.
    # Values are either a Sexp, a Set of literals, or UNPROVEN.
    @env = {}
    # Constant name (Symbol) => literal Sexp proven not to be mutated.
    # Seeded with constants resolved from the wider program.
    @constants = {}
    known_constants.each do |name, value|
      record_constant(name, value)
    end
    # Local variables that the AliasProcessor replaced with a
    # BRAKEMAN_SAFE_LITERAL after an allow-list guard, mapped to the concrete
    # set of literals the guard permits.
    @safe_literal_vars = {}
    # Stack of allow-list sets currently in effect because an early-reject
    # guard was passed. The AliasProcessor marks surviving uses of the guarded
    # value with BRAKEMAN_SAFE_LITERAL, often without a line number, so the
    # active set is tracked by scope rather than by marker line.
    @active_guard_sets = []
    # Variable name (Symbol) => :method_call or :to_proc, when the variable
    # holds a reflected callable produced by method(...) or (...).to_proc.
    @reflected_callables = {}
    @dispatch_seen = false
    # When walking an assignment right-hand side, the call there defines the
    # assigned variable rather than invalidating its receiver.
    @in_assignment_rhs = false
  end

  def analyze method_body, dispatch_call
    @dispatch_call = dispatch_call
    @matched_dispatch = nil

    record_constants method_body
    walk method_body

    if @dispatch_seen and @matched_dispatch
      @entry = dispatch_entry(@matched_dispatch)
      proof_for(@matched_dispatch)
    else
      @entry = dispatch_entry(dispatch_call)
      unproven(dispatch_call, "dispatch site was not reached by the restricted analysis")
    end
  end

  private

  # Build the proof for the dispatch expression found in the walked body.
  def proof_for call
    entry = dispatch_entry(call) || @entry
    methods = possible_methods(call)

    if methods.is_a?(Set) and not methods.empty? and methods.all? { |m| literal_name? m }
      Proof.new(proven: true, methods: methods, entry: entry, lost_at: nil)
    else
      unproven(call, methods == UNPROVEN ? nil : "converged method set contains non-literal values")
    end
  end

  def unproven exp, reason
    Proof.new(
      proven: false,
      methods: nil,
      entry: @entry,
      lost_at: sexp?(exp) ? exp.line : nil,
      reason: reason
    )
  end

  # Returns a Set of literal Sexps, an UNPROVEN marker, or a single literal
  # Sexp wrapped in a Set.
  def possible_methods call
    case call.node_type
    when :call, :safe_call
      if DISPATCH_METHODS.include? call.method
        resolve(call.first_arg)
      elsif call.method == :call
        resolve(call.target)
      else
        UNPROVEN
      end
    else
      UNPROVEN
    end
  end

  # Classify the dangerous entry point represented by the call.
  def dispatch_entry call
    return unless call? call

    if DISPATCH_METHODS.include? call.method
      call.method
    elsif call.method == :call
      target = call.target

      if call? target and target.method == :to_proc
        :to_proc
      elsif call? target and target.method == :method
        :method_call
      elsif sexp? target and target.node_type == :lvar
        @reflected_callables[target.value] || :call
      else
        :call
      end
    elsif call.method == :to_proc and call? call.target
      :to_proc
    end
  end

  # Resolve an expression to the converged set of possible literal method
  # names. Returns UNPROVEN when the set cannot be bounded.
  def resolve exp
    return UNPROVEN unless sexp? exp

    case exp.node_type
    when :lit, :str
      if safe_literal? exp
        resolve_safe_literal
      else
        Set[exp]
      end
    when :lvar
      resolve_variable(exp.value)
    when :or
      combine_or(exp)
    when :call, :safe_call
      resolve_call(exp)
    when :if
      then_set = sexp?(exp.then_clause) ? resolve(exp.then_clause) : UNPROVEN
      else_set = sexp?(exp.else_clause) ? resolve(exp.else_clause) : UNPROVEN
      merge_sets(then_set, else_set)
    else
      UNPROVEN
    end
  end

  # A BRAKEMAN_SAFE_LITERAL is only trustworthy inside a passing allow-list
  # guard whose concrete set is currently active; otherwise it proves nothing.
  def resolve_safe_literal
    @active_guard_sets.last || UNPROVEN
  end

  def resolve_variable name
    value = @env[name]
    return @safe_literal_vars[name] || UNPROVEN if value.nil?
    return UNPROVEN if value == UNPROVEN

    if value.is_a? Set
      value
    elsif value.is_a? Sexp
      resolve value
    else
      UNPROVEN
    end
  end

  def combine_or exp
    merge_sets(resolve(exp.lhs), resolve(exp.rhs))
  end

  def merge_sets left, right
    return UNPROVEN if left == UNPROVEN or right == UNPROVEN

    left | right
  end

  # Only provable literal mappings (constant hash/array indexed by a request
  # value) and method/to_proc wrappers are understood here.
  def resolve_call exp
    if exp.method == :[] or exp.method == :fetch
      literal_mapping(exp)
    elsif exp.method == :method
      # method(symbol_literal) is a fixed method; method(request_value) is not.
      arg = exp.first_arg
      arg && literal_name?(arg) ? Set[arg] : UNPROVEN
    elsif exp.method == :to_proc
      arg = exp.target
      literal_name?(arg) ? Set[arg] : UNPROVEN
    else
      UNPROVEN
    end
  end

  # Matches:
  #
  #   {a: :one}[request_value]
  #   CONSTANT[request_value]
  #   CONSTANT.fetch(request_value, literal_default)
  #
  # where the collection holds literal values. Constant-backed collections
  # are only trusted when they are never mutated in the method.
  def literal_mapping exp
    target = exp.target
    collection =
      if hash?(target) or array?(target)
        target
      elsif constant? target
        @constants[target.value]
      end

    return UNPROVEN if collection.nil?

    index_expr = exp.first_arg
    return UNPROVEN unless sexp? index_expr
    return UNPROVEN unless request_index?(index_expr)

    values =
      if hash? collection
        hash_values(collection)
      elsif array? collection
        array_values(collection)
      end

    return UNPROVEN if values.nil? or values.empty?
    return UNPROVEN unless values.all? { |v| literal_name? v }

    if exp.method == :fetch and exp.args.length > 1
      default = exp.args.last
      return UNPROVEN unless literal_name? default

      values = values + [default]
    end

    values.to_set
  end

  def hash_values hash_exp
    values = []

    hash_exp.each_sexp.each_slice(2) do |key, value|
      return nil if key.nil? or value.nil?
      values << value
    end

    values
  end

  def array_values array_exp
    array_exp.each_sexp.to_a
  end

  def literal_name? exp
    symbol?(exp) or string?(exp)
  end

  # The index of a literal mapping is request-derived when it is the request
  # expression itself, a local variable currently holding that expression, or
  # an AliasProcessor safe-literal standing in for a guarded request value.
  def request_index? exp
    if safe_literal? exp
      not @active_guard_sets.empty?
    elsif exp.node_type == :lvar
      tracked = @env[exp.value]
      return true if tracked.is_a?(Sexp) and request_value?(tracked)
      return true if tracked.is_a?(Sexp) and safe_literal?(tracked)
      return true if @safe_literal_vars.key? exp.value

      false
    else
      request_value? exp
    end
  end

  # Linear walk of the method body. Branching constructs are handled
  # explicitly; everything else falls through to generic processing.
  def walk exp
    return unless sexp? exp

    case exp.node_type
    when :block, :rlist
      exp.each_sexp { |child| walk child }
    when :defn, :defs
      walk_method(exp)
    when :lasgn, :iasgn
      handle_assignment(exp[1], exp[2] || s(:nil))
    when :cdecl
      handle_constant_assignment(exp[1], exp[2] || s(:nil))
    when :masgn
      handle_multiple_assignment(exp)
    when :if
      walk_if(exp)
    when :case
      walk_case(exp)
    when :call, :safe_call
      walk_call(exp)
    when :attrasgn
      walk_attrasgn(exp)
    when :return
      exp.each_sexp { |child| walk child }
    when :iter
      walk_in_scope(exp)
    else
      exp.each_sexp { |child| walk child }
    end
  end

  # Top-level method definition: walk its body directly so the method's
  # local assignments populate the analysis environment.
  def walk_method exp
    body_index = exp.node_type == :defs ? 4 : 3
    body = exp[body_index]
    return unless sexp? body

    if body.node_type == :scope
      walk(body[1]) if sexp? body[1]
    elsif block? body
      body.each_sexp { |child| walk child }
    else
      # The parser stores multiple body expressions as sibling nodes starting
      # at the body index, so walk every node from there.
      (body_index...exp.length).each do |index|
        node = exp[index]
        walk(node) if sexp?(node)
      end
    end
  end

  # Nested blocks have their own variable scope. Analyze them without
  # letting assignments leak into the outer method.
  def walk_in_scope exp
    saved = snapshot
    exp.each_sexp { |child| walk child }
  ensure
    restore(saved)
  end

  def handle_assignment name, value
    if name.is_a? Symbol
      @env[name] = assignment_rhs { track_value(value) }
      remember_safe_literal_var(name, value)
      remember_reflected_callable(name, value)
    else
      walk value
    end
  end

  # Runs a block while marking the walker as being inside an assignment
  # right-hand side, so receiver calls define a new variable instead of
  # invalidating an existing one.
  def assignment_rhs
    previous = @in_assignment_rhs
    @in_assignment_rhs = true
    yield
  ensure
    @in_assignment_rhs = previous
  end

  def remember_reflected_callable name, value
    return unless sexp? value and call? value

    if value.method == :method
      @reflected_callables[name] = :method_call
    elsif value.method == :to_proc
      @reflected_callables[name] = :to_proc
    end
  end

  # v = ... may collapse to a safe-literal assignment. Inside an active guard
  # the variable then names the guard's concrete allowed set.
  def remember_safe_literal_var name, value
    return unless sexp? value and safe_literal? value

    set = @active_guard_sets.last
    @safe_literal_vars[name] = set if set
  end

  def handle_constant_assignment name, value
    record_constant(name, value)
    walk value
  end

  def handle_multiple_assignment exp
    values = exp[2]
    return unless sexp? values

    values = values[1] if values.node_type == :array and values.length == 2 and sexp?(values[1]) and values[1].node_type == :to_ary

    rhs =
      if values.node_type == :array
        values.each_sexp.to_a
      elsif values.node_type == :splat
        [values[1]]
      else
        [values]
      end

    lhs = exp[1]
    return unless lhs.node_type == :array

    lhs.each_sexp.each_with_index do |target, i|
      value = rhs[i]
      next unless value

      if target.node_type == :lasgn
        @env[target.value] = track_value(value)
      elsif target.node_type == :iasgn
        @env[target.value] = track_value(value)
      else
        walk value
      end
    end
  end

  # Converts a right-hand side into a tracked env value.
  def track_value exp
    return UNPROVEN unless sexp? exp

    case exp.node_type
    when :lit, :str
      return resolve_safe_literal if safe_literal? exp

      exp
    when :lvar
      @env.fetch(exp.value, UNPROVEN)
    when :or
      left = track_value(exp.lhs)
      right = track_value(exp.rhs)
      return UNPROVEN if left == UNPROVEN or right == UNPROVEN

      as_set(left) | as_set(right)
    when :if
      then_value = sexp?(exp.then_clause) ? track_value(exp.then_clause) : UNPROVEN
      else_value = sexp?(exp.else_clause) ? track_value(exp.else_clause) : UNPROVEN
      return UNPROVEN if then_value == UNPROVEN or else_value == UNPROVEN

      as_set(then_value) | as_set(else_value)
    when :case
      track_case_value(exp)
    when :call, :safe_call
      if request_value?(exp)
        exp
      else
        track_call_value(exp)
      end
    when :hash
      exp
    else
      UNPROVEN
    end
  end

  # Evaluate a case expression used directly as a value. Only literal when
  # branches are accepted, and the else must be absent or terminate; a
  # continuing default that could fall back to the request value is unproven.
  def track_case_value exp
    branches = exp.each_sexp.select { |e| e.node_type == :when }
    last = exp.last
    else_clause =
      if sexp?(last) and last.node_type != :when
        last
      end

    return UNPROVEN if branches.empty?
    return UNPROVEN if else_clause and not terminates?(else_clause)
    return UNPROVEN unless branches.all? { |w| when_literals(w) }

    values = Set.new

    branches.each do |branch|
      body = branch[2]
      value = body.nil? ? UNPROVEN : track_value(body)
      return UNPROVEN if value == UNPROVEN

      values.merge(as_set(value))
    end

    # With no else, a non-matching subject yields nil rather than a
    # request-derived method name, so the converged literal set is still safe.
    values
  end

  def track_call_value exp
    if exp.method == :[] or exp.method == :fetch
      literal_mapping(exp)
    elsif exp.method == :method
      # method(:foo) names a fixed method; method(request_value) does not.
      arg = exp.first_arg
      literal_name?(arg) ? Set[arg] : UNPROVEN
    elsif exp.method == :to_proc
      # :foo.to_proc names a fixed method; request_value.to_proc does not.
      arg = exp.target
      literal_name?(arg) ? Set[arg] : UNPROVEN
    else
      UNPROVEN
    end
  end

  def as_set value
    return value if value.is_a? Set
    return Set[value] if value.is_a? Sexp

    UNPROVEN
  end

  # if/unless handling. Only the allow-list guard pattern can add knowledge:
  # an include?/in? check on a fixed literal collection whose failing branch
  # terminates (return/raise/fail/...). Because the failing branch terminates,
  # the guard remains in effect for the code following the if as well.
  def walk_if exp
    condition = exp.condition

    if early_reject_guard?(condition, exp.else_clause)
      activate_guard(condition)
      walk(exp.then_clause) if sexp? exp.then_clause
    elsif early_reject_guard?(negate(condition), exp.then_clause)
      activate_guard(negate(condition))
      walk(exp.else_clause) if sexp? exp.else_clause
    else
      walk_branches(exp.then_clause, exp.else_clause)
    end
  end

  # Records the allow list and concrete guarded variable for code that runs
  # after a passing early-reject guard.
  def activate_guard condition
    allowed = guard_values_from(condition)
    return if allowed.nil? or allowed.empty?
    return unless allowed.all? { |v| literal_name? v }

    set = allowed.to_set

    variable =
      if condition.method == :include?
        condition.first_arg
      else
        condition.target
      end

    if sexp?(variable) and variable.node_type == :lvar
      @env[variable.value] = set
      @safe_literal_vars[variable.value] = set
    end

    @active_guard_sets.push(set)
  end

  def guard_values_from condition
    collection =
      if condition.method == :include?
        condition.target
      else
        condition.first_arg
      end

    guard_values(collection)
  end

  def walk_branches then_clause, else_clause
    saved = snapshot

    walk(then_clause) if sexp? then_clause
    then_env = snapshot

    restore(saved)
    walk(else_clause) if sexp? else_clause
    else_env = snapshot

    restore(merge_environments(then_env, else_env))
  end

  # case/when handling. A variable is considered proven only when every when
  # value is literal and the case either has no else or an else that
  # terminates. A default branch that continues (and could reach the dispatch
  # with the original request value) invalidates the proof.
  def walk_case exp
    subject = exp[1]
    branches = exp.each_sexp.select { |e| e.node_type == :when }
    last = exp.last
    else_clause =
      if sexp?(last) and last.node_type != :when
        last
      end

    return generic_case(exp, branches, else_clause) unless
      subject and subject.node_type == :lvar and not branches.empty?

    literal_whens = branches.all? { |w| literals = when_literals(w); literals and not literals.empty? }

    return generic_case(exp, branches, else_clause) unless literal_whens

    saved = snapshot

    if else_clause.nil?
      # Without an else, a value that does not match a when keeps its value
      # from before the case, so request-derived values cannot be proven.
      walk_case_without_else(subject, branches, saved)
    elsif terminates?(else_clause)
      walk_case_with_terminating_else(branches, saved)
    else
      restore(saved)
      generic_case(exp, branches, else_clause)
    end
  end

  def walk_case_with_terminating_else branches, saved
    merged = nil

    branches.each do |branch|
      restore(saved)
      walk_when_branch(branch)
      branch_env = snapshot
      merged = merged.nil? ? branch_env : merge_environments(merged, branch_env)
    end

    restore(merged)
  end

  def walk_case_without_else subject, branches, saved
    merged = nil

    branches.each do |branch|
      restore(saved)
      walk_when_branch(branch)
      branch_env = snapshot

      if subject_tracks_request?(subject, branch_env)
        branch_env[:env][subject.value] = UNPROVEN
      end

      merged = merged.nil? ? branch_env : merge_environments(merged, branch_env)
    end

    restore(merged)
  end

  def subject_tracks_request? subject, snap
    value = snap[:env][subject.value]
    value.is_a?(Sexp) and request_value?(value)
  end

  def generic_case exp, branches, else_clause
    branches.each { |b| walk_when_branch(b) }
    walk(else_clause) if sexp? else_clause
  end

  def walk_when_branch when_exp
    body = when_exp[2]
    walk(body) if sexp? body
  end

  def when_literals when_exp
    list = when_exp[1]
    return nil unless sexp? list and list.node_type == :array

    values = list.each_sexp.to_a
    return nil if values.empty?

    values if values.all? { |v| literal_name? v }
  end

  def early_reject_guard? condition, failing_branch
    return false unless sexp? failing_branch
    return false unless terminates?(failing_branch)

    fixed_collection_guard?(condition)
  end

  # [:a, :b].include?(x), {a: 1}.include?(x), or x.in?([:a, :b])
  def fixed_collection_guard? condition
    return false unless call? condition

    if condition.method == :include? and literal_collection?(condition.target)
      true
    elsif condition.method == :in? and literal_collection?(condition.first_arg)
      true
    else
      false
    end
  end

  def literal_collection? exp
    return false unless sexp? exp

    if exp.node_type == :array
      exp.each_sexp.all? { |e| literal_name? e }
    elsif exp.node_type == :hash
      values = hash_values(exp)
      values and values.all? { |e| literal_name? e }
    elsif constant?(exp)
      collection = @constants[exp.value]
      return false if collection.nil?

      literal_collection?(collection)
    else
      false
    end
  end

  def guard_values collection
    case collection.node_type
    when :array
      collection.each_sexp.to_a
    when :hash
      hash_values(collection)
    else
      if constant?(collection)
        stored = @constants[collection.value]
        return nil if stored.nil?

        stored.node_type == :array ? stored.each_sexp.to_a : hash_values(stored)
      end
    end
  end

  def negate condition
    if call? condition and condition.method == :!
      condition.target
    else
      s(:call, condition, :!)
    end
  end

  # A branch terminates when control flow cannot continue to the dispatch:
  # return/raise/fail/throw, or a block whose last statement does so.
  def terminates? exp
    return false unless sexp? exp

    case exp.node_type
    when :return, :break, :next
      true
    when :call, :safe_call
      [:raise, :fail, :throw].include? exp.method
    when :block, :rlist
      last = exp.each_sexp.to_a.last
      terminates?(last)
    when :if
      sexp?(exp.then_clause) and sexp?(exp.else_clause) and
        terminates?(exp.then_clause) and terminates?(exp.else_clause)
    else
      false
    end
  end

  # Read-only calls that observe a tracked variable without changing the
  # value it names. They must not invalidate a proof.
  READ_ONLY_METHODS = [
    :include?, :in?, :==, :!=, :eql?, :equal?, :to_s, :to_str, :inspect,
    :present?, :blank?, :presence, :nil?, :is_a?, :kind_of?, :instance_of?
  ].to_set.freeze

  def walk_call exp
    walk_mutation_call?(exp)
    mark_dispatch(exp) if dangerous_dispatch?(exp)
    invalidate_tracked_target(exp)

    exp.each_sexp { |child| walk child }
  end

  # A call whose receiver is a tracked local variable either mutates it
  # (handled separately) or produces a new value the analysis cannot bound.
  # Request-holding variables are exempt: reading params does not change the
  # fact that the variable names a request-derived value. Calls inside an
  # assignment right-hand side define a new variable and are tracked there.
  def invalidate_tracked_target exp
    return if @in_assignment_rhs

    target = exp.target
    return unless sexp? target and target.node_type == :lvar and @env.key?(target.value)
    return if DISPATCH_METHODS.include?(exp.method) or exp.method == :call
    return if exp.method == :method or exp.method == :to_proc
    return if READ_ONLY_METHODS.include?(exp.method)

    tracked = @env[target.value]
    return if tracked.is_a?(Sexp) and request_value?(tracked)

    @env[target.value] = UNPROVEN
  end

  def walk_attrasgn exp
    target = exp.target

    if constant?(target) and MUTATING_METHODS.include?(exp.method)
      @constants.delete(target.value)
    elsif sexp? target and target.node_type == :lvar and MUTATING_METHODS.include?(exp.method)
      @env[target.value] = UNPROVEN
    end

    exp.each_sexp { |child| walk child }
  end

  # In-place mutation calls such as ALLOWED << :x are plain :call nodes.
  def walk_mutation_call? exp
    target = exp.target

    if constant?(target) and MUTATING_METHODS.include?(exp.method)
      @constants.delete(target.value)
    elsif sexp? target and target.node_type == :lvar and MUTATING_METHODS.include?(exp.method)
      @env[target.value] = UNPROVEN
    end
  end

  def dangerous_dispatch? exp
    return true if DISPATCH_METHODS.include? exp.method
    return true if exp.method == :call

    if exp.method == :to_proc and call? exp.target
      return true
    end

    false
  end

  def mark_dispatch exp
    return if @dispatch_seen

    if exp.equal?(@dispatch_call) or matching_dispatch?(exp, @dispatch_call)
      @dispatch_seen = true
      @matched_dispatch = exp
    end
  end

  # The dispatch expression comes from the (alias-processed) call index while
  # the walker traverses the re-parsed raw method body, so the two trees only
  # share a line number and a dispatch shape. An aliased guarded +send+ may
  # also have been collapsed into a direct BRAKEMAN_SAFE_LITERAL call.
  def matching_dispatch? exp, target
    return false unless sexp? target and call? exp
    return false unless exp.line and target.line and exp.line == target.line

    same_dispatch_shape?(exp, target) or collapsed_safe_literal_send?(exp, target)
  end

  # Both expressions are a dispatch entry of the same kind. The argument
  # expressions are allowed to differ because aliasing rewrites variables and
  # safe calls normalize between :call and :safe_call.
  def same_dispatch_shape? exp, target
    if DISPATCH_METHODS.include?(target.method)
      DISPATCH_METHODS.include?(exp.method)
    elsif target.method == :call
      exp.method == :call
    elsif target.method == :to_proc
      exp.method == :to_proc
    else
      false
    end
  end

  def collapsed_safe_literal_send? exp, target
    DISPATCH_METHODS.include?(target.method) and
      call?(exp) and
      exp.method == :BRAKEMAN_SAFE_LITERAL
  end

  # Record constants that hold fixed literal collections. A constant is only
  # trusted while no mutation of it exists anywhere in the method.
  def record_constants method_body
    walk_constant_declarations(method_body)
    invalidate_mutated_constants(method_body)
  end

  def walk_constant_declarations exp
    return unless sexp? exp

    if exp.node_type == :cdecl
      record_constant(exp[1], exp[2])
    end

    exp.each_sexp { |child| walk_constant_declarations(child) }
  end

  def record_constant name, value
    return unless name.is_a? Symbol and sexp? value

    if value.node_type == :hash
      values = hash_values(value)
      @constants[name] = value if values and not values.empty? and values.all? { |v| literal_name? v }
    elsif value.node_type == :array
      values = array_values(value)
      @constants[name] = value if not values.empty? and values.all? { |v| literal_name? v }
    end
  end

  def invalidate_mutated_constants method_body
    mutators = []
    find_mutations(method_body, mutators)

    mutators.each do |exp|
      target = exp.target
      @constants.delete(target.value) if constant? target
    end
  end

  def find_mutations exp, acc
    return unless sexp? exp

    if exp.node_type == :attrasgn and MUTATING_METHODS.include?(exp.method)
      acc << exp
    elsif exp.node_type == :call and constant?(exp.target) and MUTATING_METHODS.include?(exp.method)
      acc << exp
    end

    exp.each_sexp { |child| find_mutations(child, acc) }
  end

  def snapshot
    {
      env: @env.transform_values { |value| deep_copy_value(value) },
      constants: @constants.dup
    }
  end

  def restore snap
    @env = snap[:env].transform_values { |value| deep_copy_value(value) }
    @constants = snap[:constants].dup
  end

  # Sets are mutable shared values in the environment, so duplicate them (and
  # their contents) when taking a snapshot.
  def deep_copy_value value
    case value
    when Set
      value.dup
    when Sexp
      value.deep_clone
    else
      value
    end
  end

  # Branch merge: a variable keeps a proven value only when both branches
  # converge on the same set; otherwise the proof is dropped. Returns a fresh
  # snapshot without depending on (or mutating) the current @env.
  def merge_environments left, right
    merged_env = {}
    names = (left[:env].keys | right[:env].keys).sort

    names.each do |name|
      left_value = left[:env][name]
      right_value = right[:env][name]

      merged_env[name] =
        if left_value.nil? or right_value.nil? or left_value == UNPROVEN or right_value == UNPROVEN
          UNPROVEN
        elsif left_value == right_value
          left_value
        elsif left_value.is_a?(Set) and right_value.is_a?(Set)
          left_value | right_value
        elsif literal_tracked?(left_value) and literal_tracked?(right_value)
          Set[left_value, right_value]
        else
          UNPROVEN
        end
    end

    { env: merged_env, constants: left[:constants].merge(right[:constants]) }
  end

  def literal_tracked? value
    value.is_a?(Sexp) and literal_name?(value)
  end
end
