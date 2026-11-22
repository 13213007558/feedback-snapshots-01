# frozen_string_literal: true

class Controller
  attr_accessor :current_user
  attr_reader :action_name, :params, :handled, :restricted

  class View
    def initialize(controller)
      @controller = controller
    end

    attr_reader :controller
  end

  class << self
    def helper(mod)
      View.include(mod)
    end

    def helper_method(method)
      View.class_eval <<-RUBY, __FILE__, __LINE__ + 1
        def #{method}(*args, **kwargs, &block)
          controller.send(:#{method}, *args, **kwargs, &block)
        end
      RUBY
    end
  end

  include Pundit::Authorization

  # Mark protected methods public so they may be called in test
  public(*Pundit::Authorization.protected_instance_methods)

  def initialize(current_user, action_name, params)
    @current_user = current_user
    @action_name = action_name
    @params = params
  end

  # Simulates dispatching a controller action. A NotAuthorizedError the action
  # does not handle is caught here, standing in for a rescue_from hook that
  # renders a restricted page.
  def dispatch(action, record)
    @handled = :full_page
    public_send(action, record)
    @handled
  rescue Pundit::NotAuthorizedError
    @restricted = true
    @handled = :restricted_page
  end

  # A request that is denied first and retried with a permission that passes.
  def deny_then_authorize(record)
    authorize(record, :destroy?)
  rescue Pundit::NotAuthorizedError
    authorize(record, :show?)
  end

  # A request that is denied and catches it to render a restricted page.
  def capture_denial(record)
    authorize(record, :destroy?)
  rescue Pundit::NotAuthorizedError
    @restricted = true
    @handled = :restricted_page
  end

  # A request that deliberately bypasses authorization.
  def explicit_skip(_record)
    skip_authorization
    @handled = :skipped_page
  end
end
