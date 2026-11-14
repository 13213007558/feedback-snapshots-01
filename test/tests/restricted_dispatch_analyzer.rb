require_relative '../test'
require 'brakeman/processors/lib/restricted_dispatch_analyzer'

class RestrictedDispatchAnalyzerTests < Minitest::Test
  include Brakeman::Util

  def analyze_method ruby
    ast = RubyParser.new.parse("def dispatch\n#{ruby}\nend")
    target = find_dispatch(ast)
    Brakeman::RestrictedDispatchAnalyzer.analyze(ast, target)
  end

  def find_dispatch exp
    candidates = []
    collect_dispatch(exp, candidates)
    # Prefer an outer #call (the actual invocation), matching how CheckSend
    # indexes method(...).call and to_proc.call.
    candidates.find { |c| c.method == :call } || candidates.first
  end

  def collect_dispatch exp, acc
    return unless sexp? exp

    if call?(exp) and dispatch_method?(exp)
      acc << exp
    end

    exp.each_sexp { |child| collect_dispatch(child, acc) }
  end

  def dispatch_method? exp
    Brakeman::RestrictedDispatchAnalyzer::DISPATCH_METHODS.include?(exp.method) or
      exp.method == :call or exp.method == :to_proc
  end

  def assert_proven ruby, expected_methods
    proof = analyze_method(ruby)
    assert proof.proven?, "expected a proof, got: #{proof.inspect}"
    assert_equal expected_methods.sort, proof.methods.map { |m| m.value }.sort
  end

  def refute_proven ruby
    proof = analyze_method(ruby)
    refute proof.proven?, "expected no proof, got: #{proof.inspect}"
    proof
  end

  # Literal mapping

  def test_literal_hash_mapping_is_proven
    assert_proven(
      "op = params[:op]\nname = { 'summary' => :summary_report, 'detail' => :detail_report }[op]\nobj.public_send(name)",
      [:summary_report, :detail_report]
    )
  end

  def test_constant_hash_mapping_is_proven
    known = { ACTIONS: s(:hash, s(:str, "summary"), s(:lit, :summary_report), s(:str, "detail"), s(:lit, :detail_report)) }
    ast = RubyParser.new.parse("def dispatch\nop = params[:op]\nname = ACTIONS[op]\nobj.send(name)\nend")
    target = find_dispatch(ast)
    proof = Brakeman::RestrictedDispatchAnalyzer.analyze(ast, target, known)

    assert proof.proven?
    assert_equal [:detail_report, :summary_report], proof.methods.map(&:value).sort
  end

  def test_hash_fetch_with_literal_default_includes_default
    assert_proven(
      "op = params[:op]\nname = { 'summary' => :summary_report }.fetch(op, :fallback_report)\nobj.send(name)",
      [:summary_report, :fallback_report]
    )
  end

  # Case / when

  def test_case_with_literal_branches_and_terminating_else_is_proven
    assert_proven(
      "op = params[:op]\nname = case op\nwhen 'summary' then :summary_report\nwhen 'detail' then :detail_report\nelse raise\nend\nobj.send(name)",
      [:summary_report, :detail_report]
    )
  end

  def test_case_without_else_is_proven_for_literal_assignment
    assert_proven(
      "op = params[:op]\nname = case op\nwhen 'summary' then :summary_report\nwhen 'detail' then :detail_report\nend\nobj.send(name)",
      [:summary_report, :detail_report]
    )
  end

  def test_case_default_falling_back_to_request_is_not_proven
    refute_proven(
      "op = params[:op]\nname = case op\nwhen 'summary' then :summary_report\nelse op\nend\nobj.send(name)"
    )
  end

  # Early-reject allow list

  def test_allow_list_guard_with_raise_is_proven
    assert_proven(
      "op = params[:op]\nraise unless [:summary_report, :detail_report].include? op\nobj.public_send(op)",
      [:summary_report, :detail_report]
    )
  end

  def test_allow_list_guard_with_return_is_proven
    assert_proven(
      "op = params[:op]\nunless [:summary_report].include?(op)\nflash[:error] = 'bad'\nreturn\nend\nobj.send(op)",
      [:summary_report]
    )
  end

  def test_in_guard_is_proven
    assert_proven(
      "op = params[:op]\nraise unless op.in?([:summary_report, :detail_report])\nobj.send(op)",
      [:summary_report, :detail_report]
    )
  end

  # Reassignment and mutation invalidate the proof

  def test_reassignment_to_request_value_is_not_proven
    proof = refute_proven(
      "name = :summary_report\nname = params[:op]\nobj.send(name)"
    )
    assert_equal :send, proof.entry
  end

  def test_mutated_allow_list_is_not_proven
    refute_proven(
      "allowed = [:summary_report]\nallowed << params[:extra].to_sym\nop = params[:op]\nraise unless allowed.include?(op)\nobj.public_send(op)"
    )
  end

  def test_mutated_constant_allow_list_is_not_proven
    known = { ALLOWED: s(:array, s(:lit, :summary_report)) }
    ast = RubyParser.new.parse("def dispatch\nALLOWED << params[:extra].to_sym\nop = params[:op]\nraise unless ALLOWED.include?(op)\nobj.send(op)\nend")
    target = find_dispatch(ast)
    proof = Brakeman::RestrictedDispatchAnalyzer.analyze(ast, target, known)

    refute proof.proven?
  end

  # Equivalent dangerous entry points

  def test_method_reflection_with_literal_is_proven
    proof = analyze_method("runner = method(:summary_report)\nrunner.call")
    assert proof.proven?
    assert_equal [:summary_report], proof.methods.map(&:value)
    assert_equal :method_call, proof.entry
  end

  def test_method_reflection_with_request_is_not_proven
    proof = refute_proven("runner = method(params[:op])\nrunner.call")
    assert_equal :method_call, proof.entry
  end

  def test_to_proc_with_literal_is_proven
    proof = analyze_method("runner = :summary_report.to_proc\nrunner.call")
    assert proof.proven?
    assert_equal [:summary_report], proof.methods.map(&:value)
    assert_equal :to_proc, proof.entry
  end

  def test_to_proc_with_request_is_not_proven
    proof = refute_proven("runner = params[:op].to_proc\nrunner.call")
    assert_equal :to_proc, proof.entry
  end

  # Out-of-scope patterns reduce certainty rather than claiming safety

  def test_unknown_call_producing_name_is_not_proven
    refute_proven("name = something_unpredictable\nobj.send(name)")
  end

  def test_plain_request_driven_send_is_not_proven
    proof = refute_proven("obj.send(params[:op])")
    assert_equal :send, proof.entry
    refute_nil proof.lost_at
  end

  def test_proof_records_loss_location
    proof = refute_proven("obj.send(params[:op])")
    assert_kind_of Integer, proof.lost_at
  end
end
