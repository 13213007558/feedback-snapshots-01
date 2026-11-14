require 'brakeman/checks/base_check'

class Brakeman::CheckDeserialize < Brakeman::BaseCheck
  Brakeman::Checks.add self

  @description = "Checks for unsafe deserialization of objects"

  def run_check
    check_yaml
    check_csv
    check_marshal
    check_oj
  end

  def check_yaml
    check_methods :YAML, :load_documents, :load_stream, :parse_documents, :parse_stream

    # Check for safe_yaml gem use with YAML.load(..., safe: true)
    if uses_safe_yaml?
      tracker.find_call(target: :YAML, method: :load).each do |result|
        call = result[:call]
        options = call.second_arg

        if hash? options and true? hash_access(options, :safe)
          next
        else
          check_deserialize result, :YAML
        end
      end
    else
      check_methods :YAML, :load
    end
  end

  def check_csv
    check_methods :CSV, :load
  end

  def check_marshal
    check_methods :Marshal, :load, :restore
  end

  def check_oj
    check_methods :Oj, :object_load # Always unsafe, regardless of mode

    safe_default = oj_safe_default?

    tracker.find_call(:target => :Oj, :method => :load).each do |result|
      call = result[:call]
      options = call.second_arg
      mode = oj_mode_from_options(options)

      # An explicit call-level mode decides on its own, independent of the
      # global default. Only a provably non-object mode is safe; an unknown
      # value (variable, environment value, conditional) must be treated as
      # potentially unsafe rather than silently skipped.
      if mode == :object or mode == :unknown or (mode.nil? and not safe_default)
        check_deserialize result, :Oj
      end
    end
  end

  def check_methods target, *methods
    tracker.find_call(:target => target, :methods => methods ).each do |result|
      check_deserialize result, target
    end
  end

  def check_deserialize result, target, arg = nil
    return unless original? result

    arg ||= result[:call].first_arg
    method = result[:call].method

    if input = has_immediate_user_input?(arg)
      confidence = :high
    elsif input = include_user_input?(arg)
      confidence = :medium
    elsif target == :Marshal
      confidence = :low
      message = msg("Use of ", msg_code("#{target}.#{method}"), " may be dangerous")
    end

    if confidence
      message ||= msg(msg_code("#{target}.#{method}"), " called with ", msg_input(input))

      warn :result => result,
        :warning_type => "Remote Code Execution",
        :warning_code => :unsafe_deserialize,
        :message => message,
        :user_input => input,
        :confidence => confidence,
        :link_path => "unsafe_deserialization",
        :cwe_id => [502]
    end
  end

  private

  # Returns true only when the effective global Oj default can be proven safe
  # from the source. Oj ships in :object mode, so with no configuration the
  # default is unsafe.
  #
  # Ordering is only knowable inside a single file (line order); calls spread
  # across files are loaded in an order the source does not encode, so a
  # "safe" call in one file cannot be chosen over an "unsafe"/unknown one in
  # another. A value coming from an environment variable or a branch is not a
  # provable constant and yields multiple possible modes.
  def oj_safe_default?
    events = oj_default_events

    return false if events.empty?

    files = events.map { |event| event[:file] }.uniq

    if files.length == 1
      # Within one file the last unconditional assignment wins and overwrites
      # everything before it. A guarded event after it only runs on some paths,
      # so it cannot make an unsafe default safe.
      last = events.reverse.find { |event| not event[:guarded] } || events.last

      oj_event_safe?(last)
    else
      # Cross-file load order is unknown. The default is safe only if every
      # possible final event is provably safe; a single object mode, guarded
      # assignment, or unknown value means an unsafe default is reachable.
      events.all? { |event| oj_event_safe?(event) }
    end
  end

  # Collects every piece of source that changes Oj's global default, paired
  # with the file and line it appears on so intra-file order can be used.
  def oj_default_events
    events = []

    tracker.find_call(target: :Oj, method: :mimic_JSON).each do |result|
      events << oj_location(result).merge(mode: :strict)
    end

    tracker.find_call(target: :Oj, method: :default_options=).each do |result|
      mode = oj_mode_from_options(result[:call].first_arg)
      events << oj_location(result).merge(mode: mode || :object)
    end

    oj_mark_branch_guarded(events)

    events.sort_by! { |event| [event[:file].to_s, event[:line] || 0] }
  end

  def oj_location result
    location = result[:location]
    file = location && location[:file]

    {
      :file => file && file.relative,
      :line => result[:call].line
    }
  end

  # A default change nested inside a conditional only runs on some execution
  # paths, so it cannot be treated as an unconditional final assignment. Flag
  # those events by walking the stored initializer syntax trees.
  def oj_mark_branch_guarded events
    guarded = {}

    tracker.initializers.each do |path, ast|
      guarded[path.relative] = oj_guarded_lines(ast)
    end

    events.each do |event|
      lines = guarded[event[:file]]
      event[:guarded] = lines && lines.include?(event[:line])
    end
  end

  # Returns the source lines of Oj default changes that sit beneath a branch.
  def oj_guarded_lines exp, inside_branch = false, lines = Set.new
    return lines unless sexp? exp

    if exp.node_type == :if
      # The condition (first child) is not a branch body; only its children are.
      exp[1..].each { |branch| oj_guarded_lines(branch, true, lines) }
      return lines
    end

    if exp.node_type == :case
      # First child is the case subject; the :when clauses and the else body
      # are all conditional.
      exp[1..].each { |branch| oj_guarded_lines(branch, true, lines) }
      return lines
    end

    if inside_branch and oj_default_change? exp
      lines << exp.line
    end

    exp.each_sexp { |child| oj_guarded_lines(child, inside_branch, lines) }

    lines
  end

  def oj_default_change? exp
    return false unless sexp? exp

    node_type = exp.node_type
    return false unless node_type == :call or node_type == :attrasgn

    target = exp.target
    method = exp.method

    target and target.node_type == :const and target.value == :Oj and
      (method == :default_options= or method == :mimic_JSON)
  end

  # Oj.mimic_JSON and a default_options= whose mode is a known non-object
  # symbol are the only provably safe events. A conditional event leaves the
  # previous (possibly unsafe) default reachable and is never provably safe.
  def oj_event_safe? event
    not event[:guarded] and event[:mode] != :object and event[:mode] != :unknown
  end

  # Extracts the :mode from an options hash.
  #
  # Returns :object for a literal :object symbol, :safe for any other literal
  # (non-object) symbol, and :unknown when the mode is not a resolvable
  # constant (environment value, variable, conditional, or absent key).
  def oj_mode_from_options options
    return nil unless hash? options

    mode = hash_access(options, :mode)
    return nil unless mode

    if symbol? mode
      mode.value == :object ? :object : :safe
    else
      :unknown
    end
  end

  def uses_safe_yaml?
    tracker.config.has_gem? :safe_yaml
  end
end
