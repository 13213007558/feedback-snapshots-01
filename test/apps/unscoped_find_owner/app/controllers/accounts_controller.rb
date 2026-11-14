class AccountsController < ApplicationController
  def scoped
    @order = current_account.orders.find(params[:order_id])
  end

  def scoped_with_condition
    @order = current_account.orders.where(active: true).find(params[:order_id])
  end

  def scoped_by_owner_condition
    @order = Order.where(account: current_account).find(params[:order_id])
  end

  def scoped_find_by
    @order = current_account.orders.find_by(id: params[:order_id])
  end

  def scope_removed
    @order = current_account.orders.unscoped.find(params[:order_id])
  end

  def scope_removed_unscope
    @order = current_account.orders.unscope(:where).find(params[:order_id])
  end

  def scope_removed_unscope_named
    @order = current_account.orders.unscope(where: :active).find(params[:order_id])
  end

  def scope_removed_unscope_owner
    @order = current_account.orders.unscope(where: :account_id).find(params[:order_id])
  end

  def scope_removed_rewhere
    @order = current_account.orders.rewhere(account_id: params[:account_id]).find(params[:order_id])
  end

  def scope_kept_rewhere
    @order = current_account.orders.rewhere(active: true).find(params[:order_id])
  end

  def recreated_relation
    @order = Order.find(params[:order_id])
  end

  def merged_untrusted_relation
    @order = current_account.orders.merge(Order.where(name: params[:name])).find(params[:order_id])
  end

  def scope_condition_from_untrusted_input
    @order = Order.where(account_id: params[:account_id]).find(params[:order_id])
  end

  def scope_from_owner_lookup
    @order = Account.find(session[:account_id]).orders.find(params[:order_id])
  end

  def ivar_owner
    @current_account ||= Account.find(session[:account_id])
    @order = @current_account.orders.unscoped.find(params[:order_id])
  end

  def other_account
    @order = other_account.orders.find(params[:order_id])
  end

  def unconfigured_accessor
    @order = account_scope.orders.find(params[:order_id])
  end

  def unrelated
    @user = User.find_by(id: params[:user_id])
  end

  def current_account
    @current_account ||= Account.find(session[:account_id])
  end

  def other_account
    Account.find(session[:other_account_id])
  end
end
