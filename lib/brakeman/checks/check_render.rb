require 'brakeman/checks/base_check'
require 'brakeman/checks/renderable_classifier'

#Check calls to +render()+ for dangerous values
class Brakeman::CheckRender < Brakeman::BaseCheck
  Brakeman::Checks.add self

  @description = "Finds calls to render that might allow file access or code execution"

  def run_check
    tracker.find_call(:target => nil, :method => :render).each do |result|
      process_render_result result
    end
  end

  def process_render_result result
    return unless node_type? result[:call], :render

    case result[:call].render_type
    when :partial, :template, :action, :file
      check_for_dynamic_path(result)
    when :inline
    when :js
    when :json
    when :text
    when :update
    when :xml
    end
  end

  #Check if path to action or file is determined dynamically
  def check_for_dynamic_path result
    view = result[:call][2]

    if sexp? view and original? result
      # A value shaped like an object render is classified separately from an
      # ordinary template name. Only a confirmed renderable component is
      # exempt; an unresolvable object keeps the warning and records why.
      classification = renderable_classifier.classify(view)
      return if classification&.confirmed?

      input = if classification&.unknown?
        # The user input reaches the render through the constructor arguments
        # (e.g. UnknownComponent.new(params[:x])), which has_immediate_user_input?
        # does not descend into for method-call arguments.
        user_input_in_renderable_arguments(view)
      else
        has_immediate_user_input?(view)
      end

      if input
        if string_interp? view
          confidence = :medium
        else
          confidence = :high
        end
      else
        return
      end

      return if input.type == :model #skip models
      return if safe_param? input.match

      message = msg("Render path contains ", msg_input(input))

      if classification&.unknown?
        label = classification.class_name || "value"
        message << msg("; ", msg_code(label),
          " is not a confirmed renderable: #{classification.evidence}")
      end

      warn :result => result,
        :warning_type => "Dynamic Render Path",
        :warning_code => :dynamic_render_path,
        :message => message,
        :user_input => input,
        :confidence => confidence,
        :cwe_id => [22],
        :renderable => classification
    end
  end

  # Finds immediate user input passed into the renderable object construction,
  # including nested builder calls such as +with_content+.
  def user_input_in_renderable_arguments exp
    return false unless call? exp

    exp.each_arg do |arg|
      next unless sexp? arg

      if input = has_immediate_user_input?(arg)
        return input
      end
    end

    if call?(exp.target)
      user_input_in_renderable_arguments(exp.target)
    else
      false
    end
  end

  def safe_param? exp
    if params? exp and call? exp
      method_name = exp.method

      if method_name == :[]
        arg = exp.first_arg
        symbol? arg and [:controller, :action].include? arg.value
      else
        boolean_method? method_name
      end
    end
  end

  def renderable_classifier
    @renderable_classifier ||= Brakeman::RenderableClassifier.new(tracker)
  end
end
