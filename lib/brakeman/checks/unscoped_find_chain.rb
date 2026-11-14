require 'set'
require 'brakeman/util'

# Tracks the scope of an ActiveRecord relation from a configured
# owner accessor (for example, +current_account.orders+) to the final
# +find+ call.
#
# The mapping from accessor to model and association must be provided
# explicitly in the configuration:
#
#   unscoped_find_owners:
#     current_account:
#       model: Account
#       associations:
#         orders: Order
#
# This class only decides whether the relation still carries the
# owner restriction. It does not decide whether the final argument is
# user-controlled.
class Brakeman::UnscopedFindChain
  include Brakeman::Util

  FIND_METHODS = Set[:find, :find_by, :find_by_id, :find_by_id!, :find_by!].freeze

  # Methods which add restrictions and never remove the owner scope.
  RESTRICTING_METHODS = Set[
    :where, :where!, :not, :and, :joins, :left_joins, :left_outer_joins,
    :includes, :preload, :eager_load, :references, :order, :reorder,
    :reverse_order, :limit, :offset, :select, :reselect, :distinct,
    :group, :regroup, :having, :lock, :readonly, :strict_loading,
    :all, :scoped, :none, :annotate, :optimizer_hints, :extending,
    :create_with, :in_batches, :find_each, :find_in_batches
  ].freeze

  # Owned scope methods. #merge and #or need their argument inspected.
  MERGE_METHODS = Set[:merge].freeze
  COMBINE_METHODS = Set[:or].freeze

  Decision = Struct.new(
    :status,       # :lost or :unknown
    :culprit,      # call Sexp where the scope was removed or could not be verified
    :owner_scope,  # String like "current_account.orders"
    :target_model, # Symbol or nil
    :method_name,  # final find method
    :detail,       # Symbol or String explaining the decision
    keyword_init: true
  )

  def initialize tracker
    @tracker = tracker
  end

  def owner_mappings
    return @owner_mappings if defined?(@owner_mappings)

    raw = option_value(:unscoped_find_owners)

    @owner_mappings = {}

    case raw
    when Hash
      raw.each do |owner, spec|
        add_mapping(owner, spec)
      end
    when Array
      raw.each do |spec|
        next unless spec.is_a? Hash

        spec = symbolize_keys(spec)
        add_mapping(spec[:owner], spec)
      end
    end

    @owner_mappings
  end

  def empty?
    owner_mappings.empty?
  end

  # Returns a Decision when the relation lost the owner scope or when
  # it cannot be proven that it is still scoped. Returns nil when the
  # relation is still scoped (or when the call is not a configured
  # owner relation at all).
  def analyze call, method
    return unless FIND_METHODS.include?(method)

    steps, root = split_chain(call)
    return if steps.empty?

    if owner_name = accessor_root_name(steps, root)
      if spec = owner_mappings[normalize_owner(owner_name)]
        association, relation_steps = owner_relation_parts(steps, root)

        # The accessor is configured, but this association is not part of
        # the mapping. Do not assume it is authorized.
        unless association and spec[:associations].key?(association)
          return unless association

          return Decision.new(
            status: :unknown,
            culprit: steps.last,
            owner_scope: "#{owner_name}.#{association}",
            target_model: nil,
            method_name: method,
            detail: :association
          )
        end

        decision = analyze_owner_accessor(association, relation_steps, spec,
                                          normalize_owner(owner_name), method)

        return decision || scoped(owner_name, steps, root, method)
      end
    end

    if model = model_root(root)
      decision = analyze_model_root(steps, root, model, method)

      if decision
        return decision
      elsif owned_model?(model)
        return scoped(nil, steps, root, method)
      end
    end

    nil
  end

  private

  def option_value key
    @tracker.options[key] || @tracker.options[key.to_s]
  end

  def add_mapping owner, spec
    return if owner.nil?

    spec = symbolize_keys(spec) if spec.is_a? Hash
    return unless spec.is_a? Hash

    associations = {}

    if assoc_hash = (spec[:associations] || spec[:association])
      if assoc_hash.is_a? Hash
        assoc_hash.each do |association, target|
          associations[association.to_s.to_sym] = target.to_s.to_sym if target
        end
      end
    end

    if spec[:association] and spec[:target]
      associations[spec[:association].to_s.to_sym] = spec[:target].to_s.to_sym
    end

    # Support the compact form:
    #
    #   current_account:
    #     orders: Order
    #
    if associations.empty?
      spec.each do |key, value|
        next if [:owner, :model, :association, :target].include?(key)

        associations[key.to_s.to_sym] = value.to_s.to_sym
      end
    end

    owner = normalize_owner(owner)

    @owner_mappings[owner] = {
      model: spec[:model] && spec[:model].to_s.to_sym,
      associations: associations
    }
  end

  def symbolize_keys hash
    hash.each_with_object({}) do |(key, value), result|
      result[key.to_s.to_sym] = value
    end
  end

  def normalize_owner name
    name.to_s.sub(/\A@/, '').to_sym
  end

  # Returns [calls..., root]. The root is the non-call target of the
  # first call in the chain (often nil for an implicit receiver).
  def split_chain call
    steps = []
    node = call

    while call?(node)
      steps.unshift node
      node = node.target
    end

    [steps, node]
  end

  def accessor_root_name steps, root
    if root.nil?
      first = steps.first

      if first and first.target.nil? and first.method.is_a? Symbol
        return first.method
      end
    elsif node_type?(root, :ivar, :lvar)
      return root.value
    end

    nil
  end

  def model_root root
    if node_type?(root, :const, :colon2)
      class_name(root)
    else
      nil
    end
  end

  def owned_model? model
    owner_mappings.any? do |_owner, spec|
      spec[:associations].value?(model)
    end
  end

  def scoped owner_name, steps, root, method
    Decision.new(
      status: :scoped,
      culprit: nil,
      owner_scope: nil,
      target_model: model_root(root),
      method_name: method,
      detail: :scoped
    )
  end

  # Returns [association_name, relation_steps] for a configured owner
  # accessor, or nil if the chain does not start with an association.
  #
  #   current_account.orders.a.b.find
  #   steps: [current_account, orders, a, b, find]
  #   => [:orders, [a, b]]
  #
  #   @current_account.orders.a.b.find
  #   steps: [orders, a, b, find]
  #   => [:orders, [a, b]]
  def owner_relation_parts steps, root
    if root.nil?
      return nil if steps.length < 2

      accessor = steps[0]
      return nil unless accessor.target.nil?

      association_step = steps[1]
      relation_steps = steps[2...-1] || []
    else
      return nil if steps.length < 1

      association_step = steps[0]
      relation_steps = steps[1...-1] || []
    end

    # A final find directly on the owner is not a lookup of an
    # associated resource.
    return nil if association_step == steps.last

    [association_step.method, relation_steps]
  end

  def analyze_owner_accessor association, relation_steps, spec, owner_name, method
    target_model = spec[:associations][association]
    owner_scope = "#{owner_name}.#{association}"

    relation_steps.each do |step|
      case step.method
      when :unscoped
        return lost(step, owner_scope, target_model, method, :unscoped)
      when :unscope
        if unscope_removes_owner_condition?(step, spec)
          return lost(step, owner_scope, target_model, method, :unscope)
        end
      when :except
        if except_removes_where?(step)
          return lost(step, owner_scope, target_model, method, :except)
        end
      when :rewhere
        unless rewhere_keeps_owner_condition?(step, spec, owner_name)
          return lost(step, owner_scope, target_model, method, :rewhere)
        end
      when *MERGE_METHODS
        unless merge_keeps_owner_scope?(step.first_arg, spec, owner_name)
          return unknown(step, owner_scope, target_model, method, :merge)
        end
      when *COMBINE_METHODS
        unless same_owner_scope?(step.first_arg, spec, owner_name)
          return unknown(step, owner_scope, target_model, method, :or)
        end
      when *RESTRICTING_METHODS
        # Still restricted by the owner relation.
      else
        return unknown(step, owner_scope, target_model, method, step.method)
      end
    end

    nil
  end

  def analyze_model_root steps, root, model, method
    owner_model_mappings = owner_mappings.select do |_owner, spec|
      spec[:model] == model
    end

    owned_model_mappings = owner_mappings.select do |_owner, spec|
      spec[:associations].value?(model)
    end

    return if owner_model_mappings.empty? and owned_model_mappings.empty?

    # For example: Account.find(session[:id]).orders.find(...)
    # The receiver is the owner model, not the configured owner accessor,
    # so using the association does not prove the owner scope.
    if association_step = configured_association_step(steps, owner_model_mappings)
      step, owner, association, target = association_step

      return Decision.new(
        status: :unknown,
        culprit: steps.first,
        owner_scope: "#{owner}.#{association}",
        target_model: target,
        method_name: method,
        detail: :accessor
      )
    end

    # Plain owner lookup, e.g. Account.find(session[:id]).
    # Only owned resources (not the owner model itself) are relevant.
    if owned_model_mappings.empty?
      return nil
    end

    # Explicitly starting from the owned model is a re-query which does
    # not inherit the owner restriction, unless the query itself contains
    # a condition on the configured owner.
    return if explicit_owner_reference?(steps, owned_model_mappings)

    # A foreign key condition exists, but it is not tied to the
    # configured owner accessor.
    #
    #   Order.where(account_id: session[:account_id]).find(...)
    #
    if condition_step = owner_condition_step(steps, owned_model_mappings, model)
      step, owner, association = condition_step

      return Decision.new(
        status: :unknown,
        culprit: step,
        owner_scope: "#{owner}.#{association}",
        target_model: model,
        method_name: method,
        detail: :condition
      )
    end

    owner, spec = owned_model_mappings.first
    association = spec[:associations].key(model)

    Decision.new(
      status: :lost,
      culprit: steps.first,
      owner_scope: "#{owner}.#{association}",
      target_model: model,
      method_name: method,
      detail: :requery
    )
  end

  def configured_association_step steps, mappings
    steps[0...-1].each_with_index do |step, index|
      next if index == 0

      mappings.each do |owner, spec|
        if spec[:associations].key? step.method
          return [step, owner, step.method, spec[:associations][step.method]]
        end
      end
    end

    nil
  end

  def owner_condition_step steps, mappings, model
    steps[0...-1].each do |step|
      step.args.each do |arg|
        next unless hash?(arg)

        mappings.each do |owner, spec|
          owner_keys_for(spec).each do |key|
            next unless hash_access(arg, key)

            association = spec[:associations].key(model)

            return [step, owner, association]
          end
        end
      end
    end

    nil
  end

  # A model query only counts as explicitly scoped by the owner when it
  # contains a condition on the owner association (e.g. `account` or
  # `account_id`) whose value references the configured owner accessor.
  def explicit_owner_reference? steps, mappings
    steps.any? do |step|
      next false if FIND_METHODS.include?(step.method)
      next false if step.method == :not

      step.args.any? do |arg|
        mappings.any? do |owner, spec|
          owner_condition?(arg, owner, spec)
        end
      end
    end
  end

  def owner_condition? exp, owner_name, spec
    return false unless hash?(exp)

    owner_keys_for(spec).any? do |key|
      value = hash_access(exp, key)
      value && references_owner?(value, owner_name)
    end
  end

  def owner_keys_for spec
    return [] unless spec[:model]

    key = underscore(spec[:model].to_s).to_sym

    [key, :"#{key}_id"]
  end

  def references_owner? exp, owner_name
    return false unless sexp? exp

    if node_type?(exp, :ivar, :lvar)
      return normalize_owner(exp.value) == owner_name
    elsif call?(exp)
      return true if exp.target.nil? and exp.method.is_a?(Symbol) and normalize_owner(exp.method) == owner_name

      return true if references_owner?(exp.target, owner_name)

      exp.args.each do |arg|
        return true if references_owner?(arg, owner_name)
      end

      false
    else
      exp.each do |e|
        return true if references_owner?(e, owner_name)
      end

      false
    end
  end

  # rewhere(active: true) only replaces unrelated conditions, but
  # rewhere(account_id: params[:id]) replaces the owner condition.
  def rewhere_keeps_owner_condition? step, spec, owner_name
    step.args.all? do |arg|
      next true unless hash?(arg)

      hash_keeps_owner_condition?(arg, spec, owner_name)
    end
  end

  # merge(hash) adds conditions, unless it contains the owner key with
  # an untrusted value.
  def merge_keeps_owner_scope? exp, spec, owner_name
    return false unless sexp?(exp)

    if hash?(exp)
      hash_keeps_owner_condition?(exp, spec, owner_name)
    else
      same_owner_scope?(exp, spec, owner_name)
    end
  end

  def hash_keeps_owner_condition? hash, spec, owner_name
    owner_keys_for(spec).none? do |key|
      value = hash_access(hash, key)

      value and not references_owner?(value, owner_name)
    end
  end

  def same_owner_scope? exp, spec, owner_name
    return false unless sexp?(exp)

    steps, root = split_chain(exp)
    return false if steps.empty?

    name = accessor_root_name(steps, root)

    if name and normalize_owner(name) == owner_name
      association, _ = owner_relation_parts(steps, root)

      return false unless association

      return spec[:associations].key? association
    end

    # A merge argument may be built from a model query which explicitly
    # restricts itself to the configured owner:
    #
    #   Order.where(account: current_account)
    #
    if model = model_root(root)
      if model == spec[:model] or spec[:associations].value?(model)
        mappings = { owner_name => spec }

        return explicit_owner_reference?(steps, mappings)
      end
    end

    false
  end

  def unscope_removes_owner_condition? step, spec
    return true if step.args.empty?

    step.args.any? do |arg|
      case
      when hash?(arg)
        # unscope(where: :active)
        where = hash_access(arg, :where)
        where.nil? or owner_keys_for(spec).include?(literal_value(where))
      else
        value = literal_value(arg)
        value.nil? or value == :where or value == :all
      end
    end
  end

  def except_removes_where? step
    values = step.args.map { |arg| literal_value(arg) }
    values.empty? or values.include?(:where) or values.include?(:all)
  end

  def literal_value exp
    if symbol? exp or node_type?(exp, :str)
      exp.value
    else
      nil
    end
  end

  def lost culprit, owner_scope, target_model, method, detail
    Decision.new(
      status: :lost,
      culprit: culprit,
      owner_scope: owner_scope,
      target_model: target_model,
      method_name: method,
      detail: detail
    )
  end

  def unknown culprit, owner_scope, target_model, method, detail
    Decision.new(
      status: :unknown,
      culprit: culprit,
      owner_scope: owner_scope,
      target_model: target_model,
      method_name: method,
      detail: detail
    )
  end
end
