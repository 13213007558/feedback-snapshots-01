# frozen_string_literal: true

module CanCan
  module ModelAdapters
    # Builds a queryable Active Record relation when an ability is defined with one or more
    # Active Record relations (scopes) together with plain Hash conditions.
    #
    # The relations define a coverage domain with their own joins, grouping and ordering, which
    # cannot be turned into a flat SQL fragment. Instead every rule is expressed as the set of its
    # primary keys and the rules are combined with set algebra on the primary key:
    #
    #   (relation rules OR hash "can" rules) AND NOT hash "cannot" rules
    #
    # Each set becomes an `id IN (subquery)` Arel node, so rules that are structurally
    # incompatible for Active Record's `Relation#or` (for example a scoped join and a plain where)
    # can still be combined. Hash conditions keep working, including conditions that filter through
    # associations. A relation combined with raw SQL conditions cannot be expressed this way and
    # raises an Error, because the SQL fragment has no relation that could be combined.
    class ScopeMerger
      def initialize(model_class, rules)
        @model_class = model_class
        @rules = rules
      end

      # Returns the merged relation, or nil when none of the rules uses a scope.
      def merge
        scoped, others = @rules.partition { |rule| rule.conditions.is_a?(ActiveRecord::Relation) }
        return if scoped.empty?

        ensure_mergeable!(others)

        allowed = allowed_node(scoped, others)
        relation = @model_class.where(allowed)
        denial_nodes(others.reject(&:base_behavior)).each { |denial| relation = relation.where(denial.not) }
        relation
      end

      private

      def ensure_mergeable!(rules)
        incompatible = rules.detect { |rule| incompatible_conditions?(rule.conditions) }
        return unless incompatible

        raise Error,
              'Unable to merge an Active Record scope with other conditions. ' \
              "Instead use a hash or SQL for #{incompatible.actions.first} #{incompatible.subjects.first} ability."
      end

      # A relation can only be combined with a Hash of conditions (or an empty catch-all).
      # Strings and arrays of SQL fragments stay raw SQL and cannot be expressed as key sets.
      def incompatible_conditions?(conditions)
        !conditions.is_a?(Hash) && !conditions.empty?
      end

      def allowed_node(scoped_rules, other_rules)
        nodes = scope_nodes(scoped_rules) + hash_nodes(other_rules.select(&:base_behavior))
        nodes.reduce { |combined, node| combined.or(node) } || false_node
      end

      def denial_nodes(rules)
        rules.reject { |rule| rule.conditions.empty? }.map { |rule| hash_node(rule.conditions) }
      end

      def scope_nodes(rules)
        rules.reject { |rule| empty_scope?(rule.conditions) }.map { |rule| key_set_node(rule.conditions) }
      end

      def hash_nodes(rules)
        rules.reject { |rule| rule.conditions.empty? }.map { |rule| hash_node(rule.conditions) }
      end

      def hash_node(conditions)
        key_set_node(build_hash_relation(conditions))
      end

      # Wraps any relation in `primary_key IN (SELECT primary_key FROM (... the relation ...))`.
      def key_set_node(relation)
        arel_table[primary_key].in(relation.select(relation.primary_key).arel)
      end

      def build_hash_relation(conditions)
        relation = @model_class.where(nil)
        joins = joins_for(conditions)
        relation = relation.joins(joins) if joins.present?
        relation.where(conditions)
      end

      def joins_for(conditions)
        joins_hash = {}
        deep_merge(joins_hash, associations_hash(conditions))
        deep_clean(joins_hash) unless joins_hash.empty?
      end

      def empty_scope?(relation)
        relation.where_clause.empty?
      end

      def false_node
        arel_table[primary_key].eq(nil)
      end

      def arel_table
        @model_class.arel_table
      end

      def primary_key
        @model_class.primary_key
      end

      def associations_hash(conditions)
        hash = {}
        if conditions.is_a?(Hash)
          conditions.each do |name, value|
            hash[name] = associations_hash(value) if value.is_a?(Hash)
          end
        end
        hash
      end

      def deep_clean(joins_hash)
        joins_hash.map { |name, nested| nested.empty? ? name : { name => deep_clean(nested) } }
      end

      def deep_merge(base_hash, added_hash)
        added_hash.each do |key, value|
          if base_hash[key].is_a?(Hash)
            deep_merge(base_hash[key], value) unless value.empty?
          else
            base_hash[key] = value
          end
        end
      end
    end
  end
end
