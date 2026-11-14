require 'brakeman/checks/base_check'
require 'brakeman/checks/unscoped_find_chain'

# Checks for unscoped calls to models' #find and #find_by_id methods.
#
# In addition to the historical belongs_to heuristic, this check can
# follow a configured owner association from the accessor used by the
# caller to the final query. For example, with
#
#   unscoped_find_owners:
#     current_account:
#       model: Account
#       associations:
#         orders: Order
#
# a query like
#
#   current_account.orders.unscoped.find(params[:id])
#
# will be reported at #unscoped, while
#
#   current_account.orders.where(active: true).find(params[:id])
#
# will not be reported.
class Brakeman::CheckUnscopedFind < Brakeman::BaseCheck
  Brakeman::Checks.add_optional self

  @description = "Check for unscoped ActiveRecord queries"

  def run_check
    @reported = Set.new
    @scoped_calls = Set.new
    @owner_chain = Brakeman::UnscopedFindChain.new(tracker)

    run_owner_chain_check
    run_belongs_to_check
  end

  def run_belongs_to_check
    Brakeman.debug("Finding instances of #find on models with associations")

    associated_model_names = active_record_models.keys.select do |name|
      if belongs_to = active_record_models[name].associations[:belongs_to]
        not all_optional_belongs_to? belongs_to
      else
        false
      end
    end

    calls = tracker.find_call :method => [:find, :find_by_id, :find_by_id!],
                              :targets => associated_model_names

    calls.each do |call|
      process_result call
    end

    tracker.find_call(:methods => [:find_by, :find_by!], :targets => associated_model_names).each do |result|
      arg = result[:call].first_arg

      if hash? arg and hash_access(arg, :id)
        process_result result
      end
    end
  end

  def run_owner_chain_check
    return if @owner_chain.empty?

    Brakeman.debug("Finding calls scoped through configured owner associations")

    tracker.find_call(:methods => Brakeman::UnscopedFindChain::FIND_METHODS.to_a).each do |result|
      call = result[:call]

      next unless caller_location? result[:location]
      next if call.original_line
      next if @reported.include? call_key(result)

      decision = @owner_chain.analyze(call, result[:method])

      if decision and decision.status == :scoped
        @scoped_calls << call_key(result)
        next
      end

      next unless decision

      process_owner_decision result, decision
    end
  end

  def process_result result
    return if duplicate? result or result[:call].original_line
    return if @scoped_calls.include? call_key(result)

    # Not interested unless argument is user controlled.
    inputs = result[:call].args.map { |arg| include_user_input?(arg) }
    return unless input = inputs.compact.first

    add_result result
    @reported << call_key(result)

    warn :result => result,
      :warning_type => "Unscoped Find",
      :warning_code => :unscoped_find,
      :message      => msg("Unscoped call to ", msg_code("#{result[:target]}##{result[:method]}")),
      :code         => result[:call],
      :confidence   => :weak,
      :user_input   => input,
      :cwe_id => [285]
  end

  def process_owner_decision result, decision
    return unless decision.status == :lost or decision.status == :unknown

    call = result[:call]

    # Keep the source of the external ID from the final query.
    inputs = call.args.map { |arg| include_user_input?(arg) }
    return unless input = inputs.compact.first

    culprit = decision.culprit || call
    finding = { :call => culprit, :location => result[:location] }

    return if @reported.include? call_key(result)
    return if duplicate? finding

    add_result finding
    @reported << call_key(result)

    message = case decision.detail
              when :requery
                msg("Unscoped call to ", msg_code("#{owner_target(decision)}##{decision.method_name}"),
                    ": ", msg_code(decision.owner_scope), " scope was not applied")
              else
                if decision.status == :lost
                  msg("Unscoped call to ", msg_code("#{owner_target(decision)}##{decision.method_name}"),
                      " after ", msg_code(decision.owner_scope), " scope was removed")
                else
                  msg("Could not verify ", msg_code(decision.owner_scope), " scope before ",
                      msg_code("#{owner_target(decision)}##{decision.method_name}"))
                end
              end

    message << " in " << msg_code(format_output(call))

    warn :result => finding,
      :warning_type => "Unscoped Find",
      :warning_code => :unscoped_find,
      :message      => message,
      :code         => culprit,
      :line         => culprit.line || call.line,
      :confidence   => :weak,
      :user_input   => input,
      :cwe_id => [285]
  end

  def owner_target decision
    decision.target_model || decision.owner_scope.split(".").last.to_s.capitalize
  end

  def caller_location? location
    case location[:type]
    when :template
      true
    when :class
      tracker.controllers.key? location[:class]
    else
      false
    end
  end

  def call_key result
    location, line = get_location result
    [location, line]
  end

  def all_optional_belongs_to? exp
    return false unless exp.is_a? Array

    # Arguments from all belongs_to calls are in one array, so split on association names
    associations = exp.slice_before { |e| symbol? e }.select { |args| symbol? args.first }

    return false if associations.empty?

    associations.all? do |args|
      args.any? { |e| hash? e and true? hash_access(e, :optional) }
    end
  end
end
