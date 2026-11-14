require_relative '../test'
require 'brakeman/checks/unscoped_find_chain'

class UnscopedFindOwnerTests < Minitest::Test
  include BrakemanTester::FindWarning

  def report
    @@report ||= BrakemanTester.run_scan "unscoped_find_owner", "Unscoped Find Owner",
      :run_checks => ["CheckUnscopedFind"]
  end

  def warnings
    report[:generic_warnings]
  end

  def sexp code
    RubyParser.new.parse(code)
  end

  def warning_at line
    found = warnings.select { |w| w.line == line }
    assert_equal 1, found.length, "Expected one Unscoped Find warning on line #{line}, found #{found.length}:\n#{warnings.map { |w| "#{w.line}: #{w.message}" }.join("\n")}"
    found.first
  end

  def refute_warning_at line
    found = warnings.select { |w| w.line == line }
    assert_equal 0, found.length, "Expected no Unscoped Find warning on line #{line}, found:\n#{found.map(&:message).join("\n")}"
  end

  def test_relation_remains_scoped
    refute_warning_at 3
    refute_warning_at 7
    refute_warning_at 11
    refute_warning_at 15
  end

  def test_scope_removed_by_unscoped
    warning = warning_at 19

    assert_equal "Unscoped Find", warning.warning_type
    assert_equal 82, warning.warning_code
    assert_equal 2, warning.confidence
    assert_match(/scope was removed/, warning.message)
    assert_match(/current_account\.orders/, warning.message)
    assert_equal sexp("current_account.orders.unscoped"), warning.code
    assert_equal s(:call, s(:params), :[], s(:lit, :order_id)), warning.user_input
  end

  def test_scope_removed_by_unscope
    warning = warning_at 23

    assert_match(/scope was removed/, warning.message)
    assert_equal sexp("current_account.orders.unscope(:where)"), warning.code
    assert_equal s(:call, s(:params), :[], s(:lit, :order_id)), warning.user_input
  end

  def test_unrelated_unscope_is_ignored
    refute_warning_at 27
    refute_warning_at 39
  end

  def test_unscope_owner_column_loses_scope
    warning = warning_at 31

    assert_match(/scope was removed/, warning.message)
    assert_equal sexp("current_account.orders.unscope(where: :account_id)"), warning.code
  end

  def test_rewhere_owner_column_loses_scope
    warning = warning_at 35

    assert_match(/scope was removed/, warning.message)
    assert_equal s(:call, s(:call, s(:call, nil, :current_account), :orders), :rewhere,
      s(:hash, s(:lit, :account_id), s(:call, s(:params), :[], s(:lit, :account_id)))), warning.code
    assert_equal s(:call, s(:params), :[], s(:lit, :order_id)), warning.user_input
  end

  def test_scope_lost_by_recreating_relation
    warning = warning_at 43

    assert_match(/scope was not applied/, warning.message)
    assert_equal s(:call, s(:const, :Order), :find, s(:call, s(:params), :[], s(:lit, :order_id))), warning.code
    assert_equal s(:call, s(:params), :[], s(:lit, :order_id)), warning.user_input
  end

  def test_scope_cannot_be_proven_after_merge
    warning = warning_at 47

    assert_match(/Could not verify/, warning.message)
    assert_match(/merge/, warning.message)
    assert_equal s(:call, s(:call, s(:call, nil, :current_account), :orders), :merge,
      s(:call, s(:const, :Order), :where, s(:hash, s(:lit, :name), s(:call, s(:params), :[], s(:lit, :name))))), warning.code
    assert_equal s(:call, s(:params), :[], s(:lit, :order_id)), warning.user_input
  end

  def test_unconfigured_accessor_is_not_assumed_to_be_authorized
    refute_warning_at 64
    refute_warning_at 68
  end

  def test_recreated_relation_without_configured_owner_is_not_reported
    refute_warning_at 72
  end

  def test_owner_condition_from_untrusted_input_cannot_be_proven
    warning = warning_at 51

    assert_match(/Could not verify/, warning.message)
    assert_equal s(:call, s(:const, :Order), :where,
      s(:hash, s(:lit, :account_id), s(:call, s(:params), :[], s(:lit, :account_id)))), warning.code
  end

  def test_relation_from_owner_lookup_cannot_be_proven
    warning = warning_at 55

    assert_match(/Could not verify/, warning.message)
    assert_match(/current_account\.orders/, warning.message)
  end

  def test_ivar_owner_cannot_be_proven_after_inlining
    warning = warning_at 60

    assert_match(/Could not verify/, warning.message)
    assert_match(/current_account\.orders/, warning.message)
    assert_equal s(:call, s(:params), :[], s(:lit, :order_id)), warning.user_input
  end

  def test_message_contains_final_query
    warning = warning_at 19

    assert_match(/current_account\.orders\.unscoped\.find\(params\[:order_id\]\)/, warning.message)
  end
end

class UnscopedFindChainTests < Minitest::Test
  def setup
    @tracker = Brakeman::Tracker.new(
      Brakeman::AppTree.new("/tmp/FAKE_UNSCOPED_FIND_#{rand(10000)}"),
      nil,
      :unscoped_find_owners => {
        :current_account => {
          :model => "Account",
          :associations => { :orders => "Order" }
        }
      }
    )

    @chain = Brakeman::UnscopedFindChain.new(@tracker)
  end

  def decision code
    call = RubyParser.new.parse(code)
    @chain.analyze(call, :find)
  end

  def test_scoped_relation
    assert_equal :scoped, decision("current_account.orders.find(params[:id])").status
  end

  def test_scoped_with_additional_conditions
    assert_equal :scoped, decision("current_account.orders.where(active: true).find(params[:id])").status
    assert_equal :scoped, decision("current_account.orders.where.not(active: true).find(params[:id])").status
  end

  def test_unscoped_loses_scope
    result = decision("current_account.orders.unscoped.find(params[:id])")

    assert_equal :lost, result.status
    assert_equal :unscoped, result.culprit.method
    assert_equal :Order, result.target_model
  end

  def test_unscope_where_loses_scope
    assert_equal :lost, decision("current_account.orders.unscope(:where).find(params[:id])").status
  end

  def test_unscope_unrelated_column_keeps_scope
    assert_equal :scoped, decision("current_account.orders.unscope(where: :active).find(params[:id])").status
  end

  def test_except_loses_scope
    assert_equal :lost, decision("current_account.orders.except(:where).find(params[:id])").status
  end

  def test_merge_with_owner_condition_keeps_scope
    assert_equal :scoped, decision("current_account.orders.merge(Order.where(account: current_account)).find(params[:id])").status
  end

  def test_merge_with_unknown_relation_cannot_be_proven
    result = decision("current_account.orders.merge(other_orders).find(params[:id])")

    assert_equal :unknown, result.status
    assert_equal :merge, result.culprit.method
  end

  def test_rewhere_unrelated_condition_keeps_scope
    assert_equal :scoped, decision("current_account.orders.rewhere(active: true).find(params[:id])").status
  end

  def test_rewhere_owner_condition_loses_scope
    result = decision("current_account.orders.rewhere(account_id: params[:account_id]).find(params[:id])")

    assert_equal :lost, result.status
    assert_equal :rewhere, result.culprit.method
  end

  def test_rewhere_owner_condition_with_owner_value_keeps_scope
    assert_equal :scoped, decision("current_account.orders.rewhere(account_id: current_account.id).find(params[:id])").status
  end

  def test_merge_owner_key_with_owner_value_keeps_scope
    assert_equal :scoped, decision("current_account.orders.merge(account_id: current_account.id).find(params[:id])").status
  end

  def test_merge_owner_key_with_untrusted_value_cannot_be_proven
    result = decision("current_account.orders.merge(account_id: params[:account_id]).find(params[:id])")

    assert_equal :unknown, result.status
    assert_equal :merge, result.culprit.method
  end

  def test_unknown_relation_method_cannot_be_proven
    result = decision("current_account.orders.only(:where).find(params[:id])")

    assert_equal :unknown, result.status
    assert_equal :only, result.culprit.method
  end

  def test_unscope_owner_column_loses_scope
    result = decision("current_account.orders.unscope(where: :account_id).find(params[:id])")

    assert_equal :lost, result.status
    assert_equal :unscope, result.culprit.method
  end

  def test_or_with_unknown_relation_cannot_be_proven
    result = decision("current_account.orders.or(Order.where(name: params[:name])).find(params[:id])")

    assert_equal :unknown, result.status
    assert_equal :or, result.culprit.method
  end

  def test_recreated_relation_loses_scope
    result = decision("Order.find(params[:id])")

    assert_equal :lost, result.status
    assert_equal :requery, result.detail
  end

  def test_relation_from_model_lookup_cannot_be_proven
    result = decision("Account.find(session[:id]).orders.find(params[:id])")

    assert_equal :unknown, result.status
    assert_equal :accessor, result.detail
  end

  def test_owner_lookup_itself_is_not_a_scoped_query
    assert_nil decision("Account.find(session[:id])")
  end

  def test_owner_condition_from_user_input_is_not_scoped
    assert_equal :unknown, decision("Order.where(account_id: params[:account_id]).find(params[:id])").status
  end

  def test_unconfigured_owner_is_ignored
    assert_nil decision("other_account.orders.find(params[:id])")
  end

  def test_empty_configuration_disables_mapping
    tracker = Brakeman::Tracker.new(
      Brakeman::AppTree.new("/tmp/FAKE_UNSCOPED_FIND_#{rand(10000)}"),
      nil,
      {}
    )

    chain = Brakeman::UnscopedFindChain.new(tracker)
    call = RubyParser.new.parse("current_account.orders.unscoped.find(params[:id])")

    assert chain.empty?
    assert_nil chain.analyze(call, :find)
  end
end
