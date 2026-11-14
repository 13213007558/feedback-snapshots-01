require 'brakeman/checks/base_check'
require 'brakeman/processors/lib/restricted_dispatch_analyzer'

#Checks for user controlled method execution through dynamic dispatch:
# send/public_send/__send__/try, Method#call and Proc#call (to_proc).
#
#When the dispatched method name is provably restricted to a fixed set of
#literal values (a literal mapping, a case/when with literal branches, or an
#early-reject allow list), no warning is emitted. When the restricted analysis
#cannot complete a proof, confidence is lowered instead of claiming the call
#is safe.
class Brakeman::CheckSend < Brakeman::BaseCheck
  Brakeman::Checks.add self

  @description = "Check for unsafe use of Object#send"

  SEND_METHODS = [:send, :try, :__send__, :public_send]

  def run_check
    Brakeman.debug("Finding instances of #send")
    calls = tracker.find_call :methods => SEND_METHODS + [:call, :to_proc], :nested => true

    calls.each do |call|
      process_result call
    end
  end

  def process_result result
    return unless original? result

    @current_result = result
    dispatch_call = dangerous_dispatch result[:call]
    return unless dispatch_call

    # A `request.to_proc.call` produces both a to_proc and a call result.
    # Warn once, at the outer call.
    return if to_proc_only_called?(result, dispatch_call)

    method_arg = dispatch_method_arg(dispatch_call)
    input = dispatch_user_input(method_arg)

    return unless input

    proof = restricted_dispatch_proof result, dispatch_call

    if proof&.proven?
      Brakeman.debug("Restricted dispatch proof converged on #{proof.methods.map { |m| m.value.inspect }.join(', ')}")
      return
    end

    warn :result => result,
      :warning_type => "Dangerous Send",
      :warning_code => :dangerous_send,
      :message => warning_message(dispatch_call, proof),
      :user_input => input,
      :confidence => proof.nil? ? :high : :weak,
      :cwe_id => [77]
  end

  # Recursively check call chain for a dangerous dispatch entry point.
  # Plain Method#call/Proc#call invocations only count when the callable was
  # produced from a method(:name)/to_proc reflection, not ordinary objects.
  def dangerous_dispatch exp
    if call? exp
      if SEND_METHODS.include? exp.method
        exp
      elsif exp.method == :call and reflected_callable? exp.target
        exp
      elsif exp.method == :to_proc and call? exp.target
        exp
      else
        dangerous_dispatch exp.target
      end
    end
  end

  def reflected_callable? target
    return false unless sexp? target

    if target.node_type == :lvar
      # The variable may resolve to method(x) or x.to_proc after aliasing.
      return true
    end

    call?(target) and (target.method == :method or target.method == :to_proc)
  end

  # True when this result is a to_proc whose value is immediately invoked via
  # #call, in which case the outer call site carries the warning.
  def to_proc_only_called? result, dispatch_call
    return false unless dispatch_call.method == :to_proc

    full = result[:full_call]
    full_call = full.is_a?(Hash) ? full[:call] : full

    # The full call is the outer #call(...) wrapping the to_proc.
    if call?(full_call) and full_call.method == :call and
       call?(full_call.target) and full_call.target.method == :to_proc
      return true
    end

    # Otherwise look for a sibling #call result whose receiver is this to_proc.
    call_sites = tracker.find_call :methods => :call, :nested => true
    call_sites.any? do |other|
      target = other[:call].target
      call?(target) and target.method == :to_proc and target.inspect == dispatch_call.inspect
    end
  end

  # The expression that selects the method to run.
  def dispatch_method_arg dispatch_call
    if SEND_METHODS.include? dispatch_call.method
      dispatch_call.first_arg
    elsif dispatch_call.method == :call
      dispatch_call.target
    else # to_proc
      dispatch_call.target
    end
  end

  # Finds immediate user input in the method-selecting expression. Unwraps the
  # reflection wrappers (method(x) / x.to_proc) and the :or branches an alias
  # pass produces for case dispatch, then falls back to the generic check.
  def dispatch_user_input method_arg
    return false unless sexp? method_arg

    if method_arg.node_type == :or
      return dispatch_user_input(method_arg.lhs) ||
             dispatch_user_input(method_arg.rhs)
    end

    if call? method_arg and [:method, :to_proc].include?(method_arg.method)
      inner = method_arg.method == :method ? method_arg.first_arg : method_arg.target
      return has_immediate_user_input?(inner)
    end

    # A bare local variable may resolve (after aliasing) to a request value,
    # as happens when a case default falls back to the original input.
    if method_arg.node_type == :lvar
      expanded = expand_local_variable(method_arg)
      return has_immediate_user_input?(expanded) if expanded
    end

    has_immediate_user_input?(method_arg)
  end

  def expand_local_variable lvar
    body = enclosing_method_body(@current_result)
    return unless body

    processed = Brakeman::AliasProcessor.new(tracker).process_safely body.deep_clone
    resolved = find_lvar_value(processed, lvar.value)
    resolved if sexp?(resolved) and resolved.node_type != :lvar
  rescue StandardError
    nil
  end

  def find_lvar_value exp, name
    return nil unless sexp? exp

    if exp.node_type == :lasgn and exp[1] == name
      return exp[2]
    end

    exp.each_sexp do |child|
      found = find_lvar_value(child, name)
      return found if found
    end

    nil
  end

  # Build the restricted dispatch proof against the enclosing method body.
  # Returns nil when no enclosing body can be located (nothing is proven,
  # but no proof-loss location is available either).
  def restricted_dispatch_proof result, dispatch_call
    body = raw_method_body(result) || enclosing_method_body(result)
    return nil unless body

    Brakeman::RestrictedDispatchAnalyzer.analyze(
      body.deep_clone,
      dispatch_call,
      known_dispatch_constants
    )
  rescue StandardError => e
    Brakeman.debug "Restricted dispatch analysis failed: #{e.class}: #{e.message}"
    nil
  end

  # Literal collection constants the tracker resolved elsewhere in the
  # program. The analyzer independently drops any constant that is mutated
  # inside the analyzed method.
  def known_dispatch_constants
    constants = tracker.constants
    return {} unless constants.respond_to? :each

    result = {}

    constants.each do |constant|
      value = constant.value
      next unless sexp? value and (array?(value) or hash?(value))

      name = base_constant_name(constant.name)
      result[name] = value if name
    end

    result
  rescue StandardError
    {}
  end

  def base_constant_name name
    return name if name.is_a? Symbol
    return name.last if name.is_a? Array and name.last.is_a? Symbol

    nil
  end

  def enclosing_method_body result
    method_info(result)&.src
  end

  # The stored method body has been through alias processing, which collapses
  # literal mappings and guarded values into BRAKEMAN_SAFE_LITERAL markers and
  # rewrites local variables. Re-parse the original source so the analyzer can
  # see the literal mapping and assignment structure directly.
  def raw_method_body result
    info = method_info(result)
    return unless info

    file = info.file
    return unless file and File.exist? file.absolute

    parsed = RubyParser.new.parse(File.read(file.absolute), file.relative)
    find_named_method(parsed, info.name)
  rescue StandardError => e
    Brakeman.debug "Could not re-parse #{file&.relative} for dispatch analysis: #{e.message}"
    nil
  end

  def find_named_method exp, name
    return unless sexp? exp

    if (exp.node_type == :defn or exp.node_type == :defs) and exp.method_name == name
      return exp
    end

    exp.each_sexp do |child|
      found = find_named_method(child, name)
      return found if found
    end

    nil
  end

  def method_info result
    location = result[:location]
    class_name = location[:class]
    method_name = location[:method]
    return unless class_name and method_name

    collection =
      tracker.controllers[class_name] ||
      tracker.models[class_name] ||
      tracker.libs[class_name]

    return unless collection

    collection.get_method(method_name.to_s.split(".").last.to_sym)
  end

  def warning_message dispatch_call, proof
    entry = proof&.entry || dispatch_call.method

    unless proof
      return msg("User controlled method execution via ", msg_code(entry))
    end

    message = msg("User controlled method execution via ", msg_code(entry),
                  " (restricted branch analysis could not prove a fixed method set")

    if proof.lost_at
      message << " (proof lost at line #{proof.lost_at})"
    else
      message << " (proof outside supported patterns)"
    end

    message << ")"
    message
  end
end
