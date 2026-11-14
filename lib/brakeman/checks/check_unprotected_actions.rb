require 'brakeman/checks/base_check'

#Checks that routable controller actions in a protected scope are
#covered by an authentication callback (e.g. +authenticate_user!+).
#
#The check computes the effective callback chain for each routable
#action, honoring +only+/+except+, +skip_before_action+ followed by
#re-registration, +prepend_before_action+, and inheritance from parent
#controllers and concerns.
#
#This is a policy check: it only runs when the authentication callback
#names and/or the protected controller scope are explicitly configured
#via the +:authentication_callbacks+ and +:protected_controllers+ options.
#Fixed public actions can be exempted with +:public_actions+
#(entries like "Admin::DashboardController#overview").
#
#Callbacks with dynamic conditions (+if:+/+unless:+) are reported as
#"cannot prove protected" instead of treating the whole controller as
#protected just because the callback name appears somewhere.
class Brakeman::CheckUnprotectedActions < Brakeman::BaseCheck
  Brakeman::Checks.add_optional self

  @description = "Finds routable actions missing configured authentication callbacks"

  DEFAULT_AUTH_CALLBACKS = [:authenticate_user!, :require_user, :login_required].freeze

  def run_check
    return unless policy_configured?

    tracker.controllers.each do |_name, controller|
      next unless in_scope? controller

      routable_actions(controller).each do |action|
        next if exempt? controller, action

        check_action controller, action
      end
    end
  end

  private

  #This check requires an explicit policy: authentication callback
  #names and/or a protected controller scope. Without configuration
  #it stays silent.
  def policy_configured?
    configured? tracker.options[:authentication_callbacks] or
      configured? tracker.options[:protected_controllers]
  end

  def configured? value
    not (value.nil? or value.empty?)
  end

  def auth_callback_names
    @auth_callback_names ||= begin
      configured = tracker.options[:authentication_callbacks]

      if configured? configured
        configured.map(&:to_sym).to_set
      else
        DEFAULT_AUTH_CALLBACKS.to_set
      end
    end
  end

  #A controller is in the protected scope if its name matches or is
  #prefixed by any configured entry (e.g. "Admin::" covers
  #Admin::UsersController). Without a configured scope, all
  #controllers are in scope.
  def in_scope? controller
    scope = tracker.options[:protected_controllers]

    return true unless configured? scope

    name = controller.name.to_s

    scope.any? do |entry|
      name == entry.to_s or name.start_with? entry.to_s
    end
  end

  #Fixed public actions explicitly exempted via :public_actions,
  #e.g. "Admin::DashboardController#overview".
  def exempt? controller, action
    exemptions = tracker.options[:public_actions]

    return false unless configured? exemptions

    exemptions.any? { |entry| entry.to_s == "#{controller.name}##{action}" }
  end

  #Routable actions come from routes.rb when explicit routes are
  #known for the controller. Public methods not listed there are
  #non-routable helpers and are ignored. When no route information
  #exists, fall back to :assume_all_routes.
  def routable_actions controller
    routes = tracker.routes[controller.name]

    if routes.is_a? Array and routes.first == :allow_all_actions
      all_public_methods controller
    elsif routes.is_a? Set
      routes.to_a
    elsif tracker.options[:assume_all_routes]
      all_public_methods controller
    else
      []
    end
  end

  def all_public_methods controller
    methods = []
    current = controller

    while current
      current.methods_public.each_key do |name|
        methods << name unless name.to_s.include? "."
      end

      current = tracker.controllers[current.parent] || tracker.libs[current.parent]
    end

    methods.uniq
  end

  def check_action controller, action
    entries, removals = effective_chain controller, action

    covering = entries.select do |filter, _klass|
      auth_filter? filter and applies_to? filter, action
    end

    return if covering.any? { |filter, _| not filter[:conditions] }

    if covering.any?
      warn_unproven controller, action, covering.first
    else
      warn_unprotected controller, action, entries, removals
    end
  end

  #Compute the effective callback entries for +action+ by replaying
  #callback declarations in order, from the topmost ancestor down to
  #the controller itself. Returns [entries, removals] where entries
  #are [filter, klass] pairs still active and removals describe
  #authentication callbacks removed by skip declarations.
  def effective_chain controller, action
    entries = []
    removals = []

    each_declaration(controller) do |kind, exp, klass|
      filter = parse_filter exp

      case kind
      when :append
        entries << [filter, klass]
      when :prepend
        entries.unshift [filter, klass]
      when :skip
        next unless applies_to? filter, action

        matching, entries = entries.partition do |f, _|
          (f[:names] & filter[:names]).any?
        end

        removed = matching.select { |f, _| auth_filter? f }

        removals << [exp, klass, removed] unless removed.empty?
      end
    end

    [entries, removals]
  end

  def each_declaration controller
    chain = []
    current = controller

    while current
      chain.unshift current
      current = tracker.controllers[current.parent] || tracker.libs[current.parent]
    end

    chain.each do |klass|
      klass.callback_declarations.each do |kind, exp|
        yield kind, exp, klass
      end
    end
  end

  def parse_filter exp
    filter = { :names => [], :conditions => false, :exp => exp }

    exp.args.each do |arg|
      if symbol? arg
        filter[:names] << arg.value
      elsif hash? arg
        hash_iterate arg do |key, value|
          case key.value
          when :only, :except
            list = symbol_list value

            if list
              filter[key.value] = list
            else
              #Dynamic :only/:except cannot be resolved statically
              filter[:conditions] = true
            end
          when :if, :unless
            filter[:conditions] = true
          end
        end
      end
    end

    filter
  end

  def symbol_list value
    if symbol? value
      [value.value]
    elsif node_type? value, :array
      values = value.sexp_body

      if values.all? { |v| symbol? v }
        values.map(&:value)
      end
    end
  end

  def auth_filter? filter
    filter[:names].any? { |name| auth_callback_names.include? name }
  end

  def applies_to? filter, action
    only = filter[:only]
    except = filter[:except]

    if only
      only.include? action
    elsif except
      not except.include? action
    else
      true
    end
  end

  def auth_names_description
    auth_callback_names.to_a.map(&:to_s).join(", ")
  end

  def scope_description filter
    if filter[:only]
      msg_code("only: #{filter[:only].inspect}")
    elsif filter[:except]
      msg_code("except: #{filter[:except].inspect}")
    else
      "dynamic options"
    end
  end

  def warn_unprotected controller, action, entries, removals
    removal = removals.reverse.find do |_exp, _klass, removed|
      removed.any? { |filter, _| applies_to? filter, action }
    end

    if removal
      exp, klass, removed = removal
      removed_names = removed.map { |filter, _| filter[:names] }.flatten.uniq

      warn :controller => controller.name,
        :method => action,
        :warning_type => "Authentication",
        :warning_code => :unprotected_action,
        :message => msg(msg_code("#{controller.name}##{action}"), " is not protected: ",
          msg_code(exp.method), " ", msg_code(removed_names.join(", ")),
          " in ", msg_code(klass.name.to_s), " removed authentication for this action; ",
          "remove the skip or re-register ", msg_code("before_action :#{removed_names.first}"),
          " to restore protection"),
        :confidence => :high,
        :code => exp,
        :file => klass.file,
        :line => exp.line,
        :cwe_id => [306]
    else
      excluding = entries.reverse.find { |filter, _| auth_filter? filter }

      if excluding
        filter, klass = excluding
        exp = filter[:exp]

        warn :controller => controller.name,
          :method => action,
          :warning_type => "Authentication",
          :warning_code => :unprotected_action,
          :message => msg(msg_code("#{controller.name}##{action}"), " is not protected: ",
            msg_code("before_action :#{filter[:names].first}"), " in ", msg_code(klass.name.to_s),
            " does not cover this action (", scope_description(filter), "); ",
            "adjust the options or add a registration covering this action"),
          :confidence => :high,
          :code => exp,
          :file => klass.file,
          :line => exp ? exp.line : nil,
          :cwe_id => [306]
      else
        warn :controller => controller.name,
          :method => action,
          :warning_type => "Authentication",
          :warning_code => :unprotected_action,
          :message => msg(msg_code("#{controller.name}##{action}"), " is not protected: ",
            "no authentication callback (", auth_names_description,
            ") is registered in its callback chain; add ",
            msg_code("before_action :#{auth_callback_names.first}"),
            " to the controller or an ancestor to restore protection"),
          :confidence => :medium,
          :file => controller.file,
          :cwe_id => [306]
      end
    end
  end

  def warn_unproven controller, action, covering
    filter, klass = covering
    exp = filter[:exp]

    warn :controller => controller.name,
      :method => action,
      :warning_type => "Authentication",
      :warning_code => :unproven_authentication,
      :message => msg("Authentication callback ", msg_code(":#{filter[:names].first}"),
        " for ", msg_code("#{controller.name}##{action}"),
        " has dynamic conditions (", msg_code(":if"), "/", msg_code(":unless"),
        "); cannot prove the action is protected"),
      :confidence => :weak,
      :code => exp,
      :file => klass.file,
      :line => exp ? exp.line : nil,
      :cwe_id => [287]
  end
end
