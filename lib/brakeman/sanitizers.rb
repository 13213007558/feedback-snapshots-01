module Brakeman
  # Registry of custom sanitizer descriptions from the scan configuration
  # (for example, `sanitizers:` in config/brakeman.yml).
  #
  # Each description is deliberately limited. It binds a method's cleaning
  # effect to
  #
  #   * a single input argument (`argument`, default 0),
  #   * the return value (`returns: true`, explicit propagation), and
  #   * the dangerous contexts it applies to (`for`: :html, :sql, :path).
  #
  # Descriptions are declarative: user code is never executed, and a
  # description for one context never applies to another context.
  #
  # Descriptions that conflict or cannot be modeled are skipped and
  # recorded in #problems with a reason.
  class Sanitizers
    CONTEXTS = [:html, :sql, :path].freeze

    Entry = Struct.new(:method_name, :target, :argument, :contexts)

    attr_reader :problems

    def initialize descriptions = nil
      @index = CONTEXTS.map { |context| [context, {}] }.to_h
      @problems = []

      load descriptions if descriptions
    end

    def empty?
      @index.each_value.all?(&:empty?)
    end

    # Find the description for the given method name and context,
    # or nil if there is none.
    def find method_name, context
      context_index = @index[context]
      return nil unless context_index

      context_index[method_name]
    end

    private

    def load descriptions
      descriptions.each do |description|
        add description
      end
    end

    def add description
      unless description.is_a? Hash
        problem "Ignoring sanitizer description #{description.inspect}: expected a Hash"
        return
      end

      description = description.each_with_object({}) do |(key, value), result|
        result[key.to_sym] = value
      end

      method_name = description[:method]

      unless method_name.is_a? Symbol or method_name.is_a? String
        problem "Ignoring sanitizer description #{description.inspect}: missing :method name"
        return
      end

      method_name = method_name.to_sym

      unless description[:returns] == true
        problem "Ignoring sanitizer for `#{method_name}`: does not declare return value propagation (`returns: true`), so its effect cannot be modeled"
        return
      end

      contexts = Array(description[:for]).map do |context|
        context.to_sym if context.is_a? Symbol or context.is_a? String
      end

      unknown = contexts.compact - CONTEXTS

      if contexts.empty? or contexts.any?(&:nil?) or not unknown.empty?
        problem "Ignoring sanitizer for `#{method_name}`: unknown or missing context in #{Array(description[:for]).inspect}, expected any of #{CONTEXTS.map(&:inspect).join(', ')}"
        return
      end

      argument = description.fetch(:argument, 0)

      unless argument.is_a? Integer and argument >= 0
        problem "Ignoring sanitizer for `#{method_name}`: invalid :argument #{argument.inspect}, expected a non-negative Integer"
        return
      end

      target = description[:target]
      target = target.to_sym if target.is_a? String

      contexts.uniq.each do |context|
        register method_name, target, argument, context
      end
    end

    def register method_name, target, argument, context
      existing = @index[context][method_name]

      if existing
        if existing.argument == argument and existing.target == target
          # Identical description, nothing to do
          return
        end

        problem "Ignoring conflicting sanitizer for `#{method_name}` in #{context} context: already registered for argument #{existing.argument}, cannot also clean argument #{argument}"
        return
      end

      @index[context][method_name] = Entry.new(method_name, target, argument, [context])
    end

    def problem message
      @problems << message
      Brakeman.alert message
    end
  end
end
