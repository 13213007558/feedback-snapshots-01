require 'brakeman/checks/base_check'

# Checks for timing side channels in hand-written credential checks
# (the blocks that sit inside +authenticate_or_request_with_http_basic+
# or similar custom authentication methods).
#
# The framework-level checks cover +http_basic_authenticate_with+, but the
# application's own comparison logic is not inspected. This check looks at
# how submitted credentials are compared against stored secrets:
#
#   username == "foo" && password == secret        # short-circuits, leaks length/prefix
#   secure_compare(u, a) && secure_compare(p, b)   # still short-circuits at the &&
#
# Non-short-circuit combinations evaluate every comparison, so the work
# does not depend on which credential matched first:
#
#   ok_user = secure_compare(u, a)
#   ok_pass = secure_compare(p, b)
#   ok_user & ok_pass                               # both comparisons always run
#
# The check is opt-in because it reasons about application intent and can
# produce lower-confidence findings.
class Brakeman::CheckCredentialComparisonTiming < Brakeman::BaseCheck
  Brakeman::Checks.add_optional self

  @description = "Check for short-circuiting credential comparisons that leak timing information"

  # Credential blocks are only interesting when they are passed to one of
  # these authentication entry points. The method name alone must never be
  # trusted: only these documented calling conventions are modeled.
  AUTHENTICATION_METHODS = Set[
    :authenticate_or_request_with_http_basic,
    :authenticate_with_http_basic,
    :http_basic_authenticate_with
  ]

  # A method name has to look like a comparison helper before it is treated
  # as an unknown one. This avoids flagging unrelated calls in the block.
  COMPARE_METHOD_PATTERN = /(?:^|_)(?:secure_)?compare(?:_|$)|secure/i

  # One-argument digest/hash constructors. Comparing digests with == is safe
  # against prefix leakage because both sides have a fixed-length digest, so
  # == cannot short-circuit past a fixed number of bytes.
  DIGEST_METHODS = Set[:hexdigest, :digest, :base64digest]

  SHORT_CIRCUIT_OPS = Set[:and, :or]

  Comparison = Struct.new(:node, :classification, :method_name, keyword_init: true) do
    def unsafe?
      classification == :unsafe_equality
    end

    def unknown?
      classification == :unknown_helper
    end
  end

  def run_check
    tracker.each_method do |src, _set_name, _method_name, file|
      @current_file = file
      find_authentication_blocks(src)
    end
  end

  # Walk a method body looking for an authentication entry point that takes
  # a block, then analyze the block's credential comparisons.
  def find_authentication_blocks exp
    return unless sexp? exp

    if node_type?(exp, :iter)
      call = exp[1]

      if call?(call) and AUTHENTICATION_METHODS.include?(call.method) and exp.block_args
        analyze_block exp.block, exp.block_args
      end
    end

    exp.each do |child|
      find_authentication_blocks child if sexp? child
    end
  end

  def analyze_block block, block_args
    @credential_vars = Set.new(block_args[1..].map { |arg| arg.is_a?(Symbol) ? arg : arg.value })
    @local_credentials = Set.new(@credential_vars)
    @assignments = {}
    @reported = Set.new

    collect_local_assignments block

    analyze_expression block
  ensure
    @credential_vars = nil
    @local_credentials = nil
    @assignments = nil
    @reported = nil
  end

  # Record local variables that wrap a credential (e.g. +user = username+),
  # and remember the expression assigned to each local variable so a later
  # +user_ok && pass_ok+ can be resolved back to the comparison it stores.
  def collect_local_assignments exp
    return unless sexp? exp

    if node_type?(exp, :lasgn)
      name = exp[1]
      value = exp[2]

      @assignments[name] = value if sexp? value

      if sexp?(value) and references_credential?(value)
        @local_credentials << name
      end
    end

    exp.each { |child| collect_local_assignments child if sexp? child }
  end

  def analyze_expression exp
    return unless sexp? exp

    if SHORT_CIRCUIT_OPS.include?(exp.node_type)
      analyze_boolean exp
    elsif node_type?(exp, :if)
      analyze_expression exp.condition if sexp?(exp.condition)
      analyze_expression exp.then_clause if sexp?(exp.then_clause)
      analyze_expression exp.else_clause if sexp?(exp.else_clause)
    elsif node_type?(exp, :lasgn)
      # A comparison stored in a local variable is evaluated unconditionally
      # at assignment time, so it is not a standalone finding and must not be
      # treated as an inline operand of a later boolean operator.
      value = exp[2]
      analyze_expression value if sexp?(value) and not comparison_expression?(value)
    elsif block?(exp)
      exp.each { |child| analyze_expression child if sexp?(child) }
    else
      # A standalone comparison (not part of a boolean combination) can only
      # report a single credential and is handled on its own merits.
      comparison = classify_comparison(exp)
      warn_for_standalone comparison if comparison
    end
  end

  def comparison_expression? exp
    call?(exp) and classify_comparison(exp)
  end

  # A short-circuiting &&/|| only evaluates the right-hand side after the
  # left-hand side, so any credential comparison embedded directly in the
  # tree reveals whether earlier comparisons succeeded. Comparisons hidden
  # behind a local variable were already evaluated unconditionally.
  def analyze_boolean boolean_node
    direct_comparisons = boolean_leaves(boolean_node).filter_map do |leaf|
      next if node_type?(leaf, :lvar)

      classify_comparison(leaf)
    end

    return if direct_comparisons.empty?

    direct_comparisons.select(&:unknown?).each do |comparison|
      warn_unknown_helper boolean_node, comparison
    end

    # Even when every primitive is constant time, joining the checks with
    # &&/|| makes the second check conditional on the first, which is the
    # timing channel this check is about.
    warn_short_circuit boolean_node, direct_comparisons
  end

  # Flatten a left-associative &&/|| tree into its operands. Mixed operators
  # are treated conservatively: the presence of any short-circuit node keeps
  # the whole subtree on the short-circuiting path.
  def boolean_leaves exp
    if sexp?(exp) and SHORT_CIRCUIT_OPS.include?(exp.node_type)
      boolean_leaves(exp[1]) + boolean_leaves(exp[2])
    else
      [exp]
    end
  end

  # Classify a single comparison call. Returns nil when the expression is not
  # a recognized credential comparison.
  def classify_comparison exp
    return unless call?(exp) and credential_comparison?(exp)

    if exp.method == :== or exp.method == :!=
      if digest_comparison?(exp)
        Comparison.new(node: exp, classification: :fixed_length_digest, method_name: exp.method)
      else
        Comparison.new(node: exp, classification: :unsafe_equality, method_name: exp.method)
      end
    elsif known_secure_compare?(exp)
      Comparison.new(node: exp, classification: :secure_compare, method_name: exp.method)
    elsif compare_like_method?(exp.method)
      Comparison.new(node: exp, classification: :unknown_helper, method_name: exp.method)
    end
  end

  # A call participates in credential checking when one operand derives from
  # a block argument (or a local wrapping one) and the other is the secret.
  # For method-style helpers only the arguments are operands; the receiver is
  # the helper/module and must never be treated as a secret.
  def credential_comparison? call_exp
    args = call_exp.args
    return false if args.nil? or args.empty?

    if call_exp.method == :== or call_exp.method == :!=
      operands = [call_exp.target, *args]
    else
      operands = args
    end

    operands = operands.select { |operand| sexp?(operand) }

    operands.any? { |operand| credential_operand?(operand) } and
      operands.any? { |operand| secret_operand?(operand) }
  end

  def credential_operand? exp
    if node_type?(exp, :lvar)
      @local_credentials.include?(exp.value)
    elsif call?(exp) and digest_call?(exp)
      exp.args.any? { |arg| sexp?(arg) and credential_operand?(arg) }
    else
      false
    end
  end

  # Secrets are modeled, never read: literals, constants, ENV/credentials/
  # secrets access, or a local variable that wraps one of those. The actual
  # value is not included in any warning.
  def secret_operand? exp
    return false unless sexp?(exp)

    case exp.node_type
    when :str, :lit, :const, :colon2, :colon3
      true
    when :lvar
      assigned = @assignments[exp.value]
      assigned ? secret_operand?(assigned) : false
    when :call
      secret_source_call?(exp) or digest_call?(exp)
    else
      false
    end
  end

  SECRET_NAME_PATTERN = /(?:^|_)(?:secret|password|passwd|credential|token|api[_-]?key)(?:_|$)|admin/i

  def secret_source_call? exp
    return false unless call?(exp)

    if exp.method == :[] and node_type?(exp.target, :const) and exp.target.value == :ENV
      return true
    end

    chain = call_chain(exp).map(&:to_s)
    return true if chain.any? { |name| SECRET_NAME_PATTERN.match?(name) }

    receiver_name = constant_name(exp.target)
    !receiver_name.nil? && SECRET_NAME_PATTERN.match?(receiver_name)
  end

  def call_chain exp
    names = []

    while call?(exp)
      names << exp.method
      exp = exp.target
    end

    names
  end

  # Digest::SHA256.hexdigest(value), OpenSSL::Digest::SHA256.new.digest(value),
  # and friends.
  def digest_call? exp
    return false unless call?(exp)
    return true if DIGEST_METHODS.include?(exp.method) and digest_receiver?(exp.target)

    exp.method == :digest and exp.args.any? { |arg| sexp?(arg) and digest_call?(arg) }
  end

  def digest_receiver? exp
    return false unless sexp?(exp)

    receiver_name = constant_name(exp)
    return false if receiver_name.nil?

    receiver_name.include?("Digest") or receiver_name == "OpenSSL"
  end

  def constant_name exp
    return nil unless sexp?(exp)

    case exp.node_type
    when :const
      exp.value.to_s
    when :colon2, :colon3
      prefix = constant_name(exp[1])
      prefix ? "#{prefix}::#{exp[2]}" : exp[2].to_s
    when :call
      constant_name(exp.target)
    end
  end

  # Both sides reduced through a fixed-length digest, so == compares a
  # constant number of bytes regardless of the secret length.
  def digest_comparison? call_exp
    args = call_exp.args
    return false unless args and args.length == 1

    digest_call?(call_exp.target) and digest_call?(args.first)
  end

  # Only documented constant-time comparison conventions are accepted. A
  # method named "secure_something" does not qualify on the name alone.
  def known_secure_compare? call_exp
    case call_exp.method
    when :secure_compare
      args = call_exp.args
      return false unless args and args.length == 2

      # Receiverless `secure_compare(a, b)` is the documented convention after
      # `include ActiveSupport::SecurityUtils`; an explicit receiver must be a
      # known constant-time provider. A custom target is not assumed safe.
      call_exp.target.nil? or secure_compare_receiver?(call_exp.target)
    when :fixed_length_secure_compare
      node_type?(call_exp.target, :const) and
        call_exp.target.value == :OpenSSL and
        call_exp.args.length == 2
    else
      false
    end
  end

  def secure_compare_receiver? target
    return true if target.nil?
    return false unless sexp?(target)

    name = constant_name(target)
    name == "ActiveSupport::SecurityUtils" or name == "Rack::Utils"
  end

  def compare_like_method? method_name
    COMPARE_METHOD_PATTERN.match?(method_name.to_s)
  end

  def references_credential? exp
    return false unless sexp?(exp)

    if node_type?(exp, :lvar)
      return @credential_vars.include?(exp.value)
    end

    exp.any? { |child| sexp?(child) and references_credential?(child) }
  end

  def warn_for_standalone comparison
    case comparison.classification
    when :unknown_helper
      warn_unknown_helper comparison.node, comparison
    when :unsafe_equality
      timing_warning(
        :single_credential_comparison,
        comparison.node,
        "Credential compared with == or !=; use a fixed-length comparison (digest or secure_compare) to avoid leaking the secret through timing"
      )
    end
  end

  def warn_short_circuit boolean_node, comparisons
    operators = comparisons.map { |comparison| comparison.method_name.to_s }.uniq.sort
    message =
      "Short-circuiting credential check combines #{operators.join(", ")} " \
      "with &&/||, so later comparisons are skipped when an earlier one fails; " \
      "evaluate every comparison and combine the boolean results with & or |"

    timing_warning(:short_circuit_credential_comparison, boolean_node, message)
  end

  def warn_unknown_helper location, comparison
    message =
      "Unrecognized comparison helper #{comparison.method_name}; only " \
      "ActiveSupport::SecurityUtils.secure_compare, Rack::Utils.secure_compare, " \
      "and OpenSSL.fixed_length_secure_compare are modeled as constant time"

    timing_warning(:unknown_credential_comparison_helper, location, message)
  end

  def timing_warning warning_code, location, message
    line = location.original_line || location.line
    key = [warning_code, line]
    return if @reported.include?(key)
    @reported << key

    warn(
      :warning_type => "Timing Attack",
      :warning_code => warning_code,
      :message => message,
      :confidence => warning_code == :short_circuit_credential_comparison ? :high : :medium,
      :line => line,
      :file => @current_file,
      :cwe_id => [208]
    )
  end
end
