class RestrictedDispatchController < ApplicationController
  ADMIN_ACTIONS = {
    "summary" => :summary_report,
    "detail" => :detail_report
  }.freeze

  REPORT_SCOPES = [:summary_report, :detail_report].freeze

  # Safe: provable literal hash mapping, request key -> fixed method name.
  def mapped_action
    operation = ADMIN_ACTIONS[params[:operation]]
    ReportService.public_send(operation)
  end

  # Safe: case/when where every branch picks a fixed method and the default
  # branch rejects the request.
  def cased_action
    operation = params[:operation]

    method_name =
      case operation
      when "summary"
        :summary_report
      when "detail"
        :detail_report
      else
        raise ActiveRecord::RecordNotFound
      end

    ReportService.send(method_name)
  end

  # Safe: early-reject allow list of harmless method names.
  def guarded_action
    operation = params[:operation]

    unless REPORT_SCOPES.include?(operation)
      raise ActiveRecord::RecordNotFound
    end

    ReportService.public_send(operation)
  end

  # Safe: method reflection with a fixed symbol.
  def reflected_fixed_action
    runner = ReportService.method(:summary_report)
    runner.call
  end

  # Bypass: the allow list is mutated before the guard, so the whitelist
  # proof must not be reused.
  def mutated_allow_list_action
    allowed = [:summary_report, :detail_report]
    allowed << params[:extra].to_sym

    operation = params[:operation]
    raise ActiveRecord::RecordNotFound unless allowed.include?(operation)

    ReportService.public_send(operation)
  end

  # Bypass: case default falls back to the original request value.
  def default_fallback_action
    operation = params[:operation]

    method_name =
      case operation
      when "summary"
        :summary_report
      else
        operation
      end

    ReportService.send(method_name)
  end

  # Bypass: reassigned after an initially safe value.
  def reassigned_action
    method_name = :summary_report
    method_name = params[:operation]

    ReportService.public_send(method_name)
  end

  # Bypass: method reflection driven directly by request input.
  def reflected_request_action
    runner = method(params[:operation])
    runner.call
  end

  # Bypass: to_proc driven directly by request input.
  def proc_request_action
    runner = params[:operation].to_proc
    runner.call
  end
end
