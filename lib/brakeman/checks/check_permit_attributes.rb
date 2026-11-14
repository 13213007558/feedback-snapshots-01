require 'brakeman/checks/base_check'
require 'set'

class Brakeman::CheckPermitAttributes < Brakeman::BaseCheck
  Brakeman::Checks.add self

  @description = "Warn on potentially dangerous attributes allowed via permit"

  SUSPICIOUS_KEYS = {
    admin: :high,
    account_id: :high,
    role: :medium,
    banned: :medium,
  }

  # Mass assignment methods that write permitted parameters to a model
  MASS_ASSIGN_METHODS = [
    :new,
    :attributes=,
    :assign_attributes,
    :build,
    :create,
    :create!,
    :first_or_create,
    :first_or_create!,
    :first_or_initialize,
    :first_or_initialize!,
    :update,
    :update!,
    :update_attributes,
    :update_attributes!,
  ]

  # A potential source of mass-assigned attributes
  Source = Struct.new(:type, :paths, :partial, :exp, :params_exp)

  def run_check
    tracker.find_call(:method => :permit).each do |result|
      check_permit result
    end

    check_sensitive_attributes
  end

  def check_permit result
    return unless original? result

    call = result[:call]

    call.each_arg do |arg|
      if symbol? arg
        if SUSPICIOUS_KEYS.key? arg.value
          warn_on_permit_key result, arg
        end
      end
    end
  end

  def warn_on_permit_key result, key, confidence = nil
    warn :result => result,
      :warning_type => "Mass Assignment",
      :warning_code => :dangerous_permit_key,
      :message => "Potentially dangerous key allowed for mass assignment",
      :confidence => (confidence || SUSPICIOUS_KEYS[key.value]),
      :user_input => key,
      :cwe_id => [915]
  end

  # Check for permitted parameters flowing into sensitive attributes
  # via mass assignment.
  #
  # Sensitive attributes are configured by the caller, per model,
  # using full attribute paths:
  #
  #   Brakeman.run app_path: "...",
  #     sensitive_attributes: { "User" => ["role", "account.plan"] }
  #
  # A key like `role` is only treated as sensitive for the models it is
  # configured on. A display field with the same name on another model
  # is not affected.
  def check_sensitive_attributes
    sensitive = sensitive_attributes
    return if sensitive.empty?

    @sensitive_results = []

    tracker.find_call(:chained => true,
                      :targets => sensitive.keys,
                      :methods => MASS_ASSIGN_METHODS).each do |result|
      check_sensitive_sink result, sensitive
    end
  end

  # Normalize configured sensitive attributes to
  # { ModelName => Set[[path, parts, ...]] }
  def sensitive_attributes
    return @sensitive_attributes if defined? @sensitive_attributes

    configured = tracker.options[:sensitive_attributes]

    @sensitive_attributes = {}

    if configured.is_a? Hash
      configured.each do |model, paths|
        paths = Array(paths).map do |path|
          path.to_s.split(".").map(&:to_sym).freeze
        end

        @sensitive_attributes[model.to_sym] = Set.new(paths)
      end
    end

    @sensitive_attributes
  end

  def check_sensitive_sink result, sensitive
    # Do not use original?/add_result here: those are shared with the
    # permit-key check above and would suppress results on the same line.
    return if result[:call].original_line

    location, line = get_location result
    return if @sensitive_results.include? [line, location]
    @sensitive_results << [line, location]

    call = result[:call]
    model = result[:chain].first
    sensitive_paths = sensitive[model]
    return unless sensitive_paths

    arg = if call.method == :update or call.method == :update!
            call.second_arg
          else
            call.first_arg
          end

    return unless sexp? arg

    trace_param_sources(arg, result).each do |source|
      case source.type
      when :permit
        matched = source.paths & sensitive_paths

        unless matched.empty?
          warn_on_sensitive_permit result, source, matched, model
        end

        if source.partial and matched.empty?
          warn_on_unknown_permit result, source, model, sensitive_paths
        end
      when :all
        warn_on_permit_all result, source, model, sensitive_paths
      when :unpermitted
        warn_on_unpermitted result, source, model, sensitive_paths
      when :unknown
        warn_on_unknown_permit result, source, model, sensitive_paths
      end
    end
  end

  # Trace an expression back to the sources of mass-assigned attributes:
  # permit() calls, permit!, unpermitted parameters, or values that
  # cannot be determined statically.
  def trace_param_sources exp, result, depth = 0
    return [Source.new(:unknown, nil, false, exp, nil)] if depth > 5
    return [] unless sexp? exp

    case exp.node_type
    when :call, :safe_call
      case exp.method
      when :permit, :slice
        if params? exp.target
          paths, partial = permit_paths(call_args(exp))
          [Source.new(:permit, paths, partial, exp, params_source(exp.target))]
        else
          [Source.new(:unknown, nil, false, exp, nil)]
        end
      when :permit!
        if params? exp.target
          [Source.new(:all, nil, false, exp, params_source(exp.target))]
        else
          [Source.new(:unknown, nil, false, exp, nil)]
        end
      when :require
        # params.require(...) without permit is unpermitted input
        if params? exp
          [Source.new(:unpermitted, nil, false, exp, params_source(exp))]
        else
          trace_param_sources(exp.target, result, depth + 1)
        end
      when :merge, :merge!
        sources = trace_param_sources(exp.target, result, depth + 1)
        merged = exp.first_arg

        if literal_hash? merged
          # Merging trusted, literal values set by the application
          sources
        else
          sources + trace_param_sources(merged, result, depth + 1)
        end
      when :to_h, :to_unsafe_h
        if params? exp.target
          [Source.new(:unpermitted, nil, false, exp, params_source(exp.target))]
        else
          [Source.new(:unknown, nil, false, exp, nil)]
        end
      else
        if exp.target.nil?
          # Local method call, e.g. user_params
          trace_method_sources exp, result, depth
        elsif params? exp
          # Raw parameters, e.g. params[:user]
          [Source.new(:unpermitted, nil, false, exp, params_source(exp))]
        else
          [Source.new(:unknown, nil, false, exp, nil)]
        end
      end
    when :hash
      # Literal hash: keys are explicitly chosen by the application
      []
    when :lasgn
      trace_param_sources(exp[2], result, depth + 1)
    when :rlist
      trace_param_sources(exp.last, result, depth + 1)
    when :if
      trace_param_sources(exp.then_clause, result, depth + 1) +
        trace_param_sources(exp.else_clause, result, depth + 1)
    else
      [Source.new(:unknown, nil, false, exp, nil)]
    end
  end

  # Follow a local method call (e.g. user_params) to its definition
  # and trace the returned value
  def trace_method_sources call, result, depth
    klass = result[:location][:class]
    klass = klass[:name] if klass.is_a? Hash

    method = klass && tracker.find_method(call.method, klass)

    if method
      trace_param_sources(method.src.body_list, result, depth + 1)
    else
      [Source.new(:unknown, nil, false, call, nil)]
    end
  end

  # Collect permitted attribute paths from permit() arguments,
  # expanding nested hashes and array declarations into full paths.
  #
  # Returns [Set of paths, partial] where +partial+ is true when some
  # arguments could not be analyzed statically.
  def permit_paths args, prefix = []
    paths = Set.new
    partial = false

    args.each do |arg|
      if symbol? arg
        paths << (prefix + [arg.value]).freeze
      elsif hash? arg
        hash_iterate arg do |key, value|
          if symbol? key
            key_path = (prefix + [key.value]).freeze
            paths << key_path

            if array? value
              sub_paths, sub_partial = permit_paths(value.sexp_body.to_a, key_path)
              paths.merge sub_paths
              partial ||= sub_partial
            elsif hash? value
              sub_paths, sub_partial = permit_paths([value], key_path)
              paths.merge sub_paths
              partial ||= sub_partial
            else
              partial = true
            end
          else
            partial = true
          end
        end
      elsif node_type? arg, :splat
        splatted = arg[1]

        if array? splatted
          sub_paths, sub_partial = permit_paths(splatted.sexp_body.to_a, prefix)
          paths.merge sub_paths
          partial ||= sub_partial
        else
          partial = true
        end
      else
        # Dynamic values (variables, method calls, etc.)
        partial = true
      end
    end

    [paths, partial]
  end

  def call_args call
    args = []
    call.each_arg { |arg| args << arg }
    args
  end

  # Find the params expression at the root of a chain like
  # params.require(:user).permit(...)
  def params_source exp
    while call? exp
      if exp.method == :require and params? exp.target
        return exp
      end

      exp = exp.target
    end

    if node_type? exp, :params
      exp
    else
      s(:params)
    end
  end

  def literal_hash? exp
    return false unless hash? exp

    hash_iterate(exp) do |key, value|
      return false unless symbol? key
      return false unless literal_value? value
    end

    true
  end

  def literal_value? exp
    not sexp? exp or
      node_type? exp, :lit, :str, :true, :false, :nil, :sym
  end

  def format_paths model, paths
    paths.map { |path| "#{model}.#{path.join(".")}" }.sort.join(", ")
  end

  def warn_on_sensitive_permit result, source, matched, model
    formatted = format_paths(model, matched)

    warn :result => result,
      :warning_type => "Mass Assignment",
      :warning_code => :sensitive_permit_key,
      :message => msg("Permitted parameters from ", msg_code(format_output(source.params_exp)),
        " are assigned to sensitive ", formatted, " in mass assignment"),
      :code => result[:call],
      :line => result[:call].line,
      :user_input => source.params_exp,
      :confidence => :high,
      :cwe_id => [915]
  end

  def warn_on_permit_all result, source, model, sensitive_paths
    formatted = format_paths(model, sensitive_paths)

    warn :result => result,
      :warning_type => "Mass Assignment",
      :warning_code => :sensitive_permit_key,
      :message => msg(msg_code("permit!"), " permits all parameters, including sensitive ",
        formatted, ", in mass assignment"),
      :code => result[:call],
      :line => result[:call].line,
      :user_input => source.params_exp,
      :confidence => :high,
      :cwe_id => [915]
  end

  def warn_on_unpermitted result, source, model, sensitive_paths
    formatted = format_paths(model, sensitive_paths)

    warn :result => result,
      :warning_type => "Mass Assignment",
      :warning_code => :sensitive_permit_key,
      :message => msg("Unpermitted parameters from ", msg_code(format_output(source.params_exp)),
        " may overwrite sensitive ", formatted, " in mass assignment"),
      :code => result[:call],
      :line => result[:call].line,
      :user_input => source.params_exp,
      :confidence => :medium,
      :cwe_id => [915]
  end

  def warn_on_unknown_permit result, source, model, sensitive_paths
    formatted = format_paths(model, sensitive_paths)

    warn :result => result,
      :warning_type => "Mass Assignment",
      :warning_code => :sensitive_permit_key,
      :message => msg("Cannot determine permitted keys in mass assignment on ",
        model.to_s, "; sensitive ", formatted, " may be permitted"),
      :code => result[:call],
      :line => result[:call].line,
      :user_input => source.params_exp,
      :confidence => :weak,
      :cwe_id => [915]
  end
end
