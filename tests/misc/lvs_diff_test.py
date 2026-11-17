# -----------------------------------------------------------------------------
# Copyright (C) 2026 The python-ndn authors
#
# This file is part of python-ndn.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# -----------------------------------------------------------------------------
import sys
from pathlib import Path

import pytest

from ndn.app_support.light_versec import (
    Checker,
    DiffBounds,
    FnContract,
    LvsDiffError,
    compile_lvs,
    compare_lvs_models,
)
from ndn.bin.tools import cmd_diff_lvs


OLD = '''
#KEY: "KEY"/"v"
#root: "site"/"root"/#KEY
#post: "site"/"post"/owner/"post" & { owner: "alice" } <= #author
#author: "site"/"author"/owner/#KEY & { owner: "alice"|"bob" } <= #root
'''

NEW = OLD.replace(
    '& { owner: "alice" } <= #author',
    '& { owner: "alice"|"bob" } <= #author',
)

EQUIVALENT = '''
#KEY: "KEY"/"v"
#root: "site"/"root"/#KEY
#post_alice: "site"/"post"/owner/"post" & { owner: "alice" } <= #author
#post_bob: "site"/"post"/owner/"post" & { owner: "bob" } <= #author
#author: "site"/"author"/owner/#KEY & { owner: "alice"|"bob" } <= #root
'''

COMPONENTS = ('site', 'root', 'post', 'author', 'KEY', 'v', 'alice', 'bob', 'carol')


def bounds(**kwargs):
    params = dict(
        components=COMPONENTS,
        max_name_len=5,
        max_cert_depth=3,
        max_evaluations=50_000,
        max_names=2_000,
        max_examples=5,
        data_rules=('#post',),
    )
    params.update(kwargs)
    return DiffBounds(**params)


def test_shortest_new_relation_and_real_checker():
    report = compare_lvs_models(OLD, NEW, bounds())
    assert report.outcome == 'NEW_RELATION_FOUND'
    assert report.search_complete
    assert not report.budget_exhausted
    assert report.new_allowed_count == 1
    assert report.removed_count == 0

    witness = report.new_allowed[0]
    assert witness.data_name == '/site/post/bob/post'
    assert witness.signer_name == '/site/author/bob/KEY/v'
    assert witness.certificate_path == (
        '/site/author/bob/KEY/v',
        '/site/root/KEY/v',
    )
    assert witness.cert_depth == 1
    assert witness.old_check is False
    assert witness.new_check is True
    assert witness.verified

    # Independently re-run the real Checker over every hop.
    old_checker = Checker(compile_lvs(OLD), {})
    new_checker = Checker(compile_lvs(NEW), {})
    assert not old_checker.check(witness.data_name, witness.signer_name)
    assert new_checker.check(witness.data_name, witness.signer_name)
    for current, issuer in zip(
        witness.certificate_path, witness.certificate_path[1:]
    ):
        assert new_checker.check(current, issuer)


def test_equivalent_syntax_has_no_difference_in_scope():
    report = compare_lvs_models(
        NEW,
        EQUIVALENT,
        bounds(data_rules=('#post_alice', '#post_bob')),
    )
    assert report.outcome == 'NO_NEW_RELATION_IN_SCOPE'
    assert report.search_complete
    assert report.new_allowed_count == 0
    assert report.removed_count == 0
    assert report.unknown_new_count == 0
    assert any('scope exhaustion' in note for note in report.notes)
    assert any('not a proof' in note for note in report.notes)


def test_budget_exhaustion_is_not_absence():
    report = compare_lvs_models(
        OLD,
        NEW,
        bounds(max_evaluations=1),
    )
    assert report.outcome == 'BUDGET_EXHAUSTED'
    assert report.budget_exhausted
    assert not report.search_complete
    assert report.budget_reason
    assert any('NOT established' in note for note in report.notes)


def test_name_limit_is_not_absence():
    report = compare_lvs_models(OLD, NEW, bounds(max_names=2))
    assert report.outcome == 'BUDGET_EXHAUSTED'
    assert not report.search_complete
    assert report.budget_reason == 'name limit reached'


def test_unknown_user_function_is_reported_as_unknown():
    old = OLD.replace('& { owner: "alice" } <= #author', '& { owner: $is_alice() } <= #author')
    new = old.replace('$is_alice()', '$is_alice()|$is_bob()')

    def is_alice(component, args):
        return bytes(component).endswith(b'alice')

    def is_bob(component, args):
        return bytes(component).endswith(b'bob')

    fns = {'$is_alice': is_alice, '$is_bob': is_bob}
    report = compare_lvs_models(
        old, new, bounds(), old_checker_fns=fns, new_checker_fns=fns,
    )
    assert report.outcome == 'UNKNOWN'
    assert report.new_allowed_count == 0
    assert set(report.unknown_functions) == {'$is_alice', '$is_bob'}
    assert report.unknown_new_count > 0
    assert any('no universal absence claim' in note for note in report.notes)


def test_explicit_contract_enables_analysis():
    old = OLD.replace('& { owner: "alice" } <= #author', '& { owner: $is_alice() } <= #author')
    new = old.replace('$is_alice()', '$is_alice()|$is_bob()')
    contracts = [
        FnContract(
            '$is_alice', 'value ends with alice',
            lambda value, args: bytes(value).endswith(b'alice'),
        ),
        FnContract(
            '$is_bob', 'value ends with bob',
            lambda value, args: bytes(value).endswith(b'bob'),
        ),
    ]
    fns = {
        '$is_alice': lambda component, args: bytes(component).endswith(b'alice'),
        '$is_bob': lambda component, args: bytes(component).endswith(b'bob'),
    }
    report = compare_lvs_models(
        old,
        new,
        bounds(),
        old_contracts=contracts,
        new_contracts=contracts,
        old_checker_fns=fns,
        new_checker_fns=fns,
    )
    assert report.outcome == 'NEW_RELATION_FOUND'
    assert report.new_allowed[0].data_name == '/site/post/bob/post'
    assert report.new_allowed[0].verified


def test_one_checker_success_does_not_generalise():
    # The real Checker knows is_alice, but there is no contract.  A witness
    # that happens to be true under the implementation must not be reported
    # as a proven new relation, nor may its sibling be assumed false.
    old = OLD.replace('& { owner: "alice" } <= #author', '& { owner: $is_alice() } <= #author')
    new = old.replace('$is_alice()', '$is_alice()|$is_bob()')
    fns = {
        '$is_alice': lambda component, args: True,
        '$is_bob': lambda component, args: False,
    }
    report = compare_lvs_models(
        old, new, bounds(), old_checker_fns=fns, new_checker_fns=fns,
    )
    assert report.outcome == 'UNKNOWN'
    assert report.new_allowed_count == 0


def test_no_anchor_in_scope_is_distinct_from_no_difference():
    report = compare_lvs_models(
        OLD,
        NEW,
        bounds(),
        check_trust_anchor=lambda name: False,
    )
    assert report.outcome == 'NO_TRUST_ANCHOR_IN_SCOPE'
    assert report.search_complete is False
    assert any('Increase the bounds' in note for note in report.notes)


def test_contract_key_mismatch_rejected():
    with pytest.raises(LvsDiffError):
        compare_lvs_models(
            OLD, NEW,
            bounds(),
            old_contracts={'$x': FnContract('$y', 'mismatch', lambda v, a: True)},
        )


def test_cli_exit_codes(tmp_path, capsys):
    old_path = tmp_path / 'old.lvs'
    new_path = tmp_path / 'new.lvs'
    old_path.write_text(OLD)
    new_path.write_text(NEW)
    args = [
        'diff-lvs', str(old_path), str(new_path),
        '--component', 'site', '--component', 'root',
        '--component', 'post', '--component', 'author',
        '--component', 'KEY', '--component', 'v',
        '--component', 'alice', '--component', 'bob',
        '--component', 'carol',
        '--max-name-len', '5', '--max-cert-depth', '3',
        '--data-rule', '#post',
    ]

    from ndn.bin.tools import main
    old_argv = sys.argv
    try:
        sys.argv = ['pyname', *args]
        code = main()
    finally:
        sys.argv = old_argv
    assert code == cmd_diff_lvs.EXIT_NEW
    out = capsys.readouterr().out
    assert 'SHORTEST_NEW_ALLOWED' in out
    assert '/site/post/bob/post' in out
    assert 'verified=True' in out


def test_cross_name_variable_binding_is_not_over_approximated():
    # The data rule and the signer rule share the pattern "owner".  A naive
    # per-name analysis would allow bob's key to sign alice's post.
    schema = '''
    #KEY: "KEY"/"v"
    #root: "site"/"root"/#KEY
    #post: "site"/"post"/owner/"post" <= #author
    #author: "site"/"author"/owner/#KEY & { owner: "alice"|"bob" } <= #root
    '''
    report = compare_lvs_models(
        schema,
        schema,
        DiffBounds(
            components=COMPONENTS,
            max_name_len=5,
            max_cert_depth=3,
            max_evaluations=50_000,
            max_names=2_000,
            data_rules=('#post',),
        ),
    )
    assert report.outcome == 'NO_NEW_RELATION_IN_SCOPE'
    assert report.new_allowed_count == 0

    checker = Checker(compile_lvs(schema), {})
    assert checker.check('/site/post/alice/post', '/site/author/alice/KEY/v')
    assert not checker.check('/site/post/alice/post', '/site/author/bob/KEY/v')


def test_cert_depth_bound_changes_effective_relation():
    # The signer cannot reach the root within the declared depth, so the
    # direct Checker relation exists but is not an effective relation.
    shallow = compare_lvs_models(
        OLD,
        NEW,
        bounds(max_cert_depth=0),
    )
    assert shallow.outcome == 'NO_NEW_RELATION_IN_SCOPE'
    assert shallow.new_allowed_count == 0

    deep = compare_lvs_models(
        OLD,
        NEW,
        bounds(max_cert_depth=1),
    )
    assert deep.outcome == 'NEW_RELATION_FOUND'
    assert deep.new_allowed[0].cert_depth == 1


def test_removed_relation_direction():
    report = compare_lvs_models(NEW, OLD, bounds())
    assert report.outcome == 'REMOVED_RELATION_FOUND'
    assert report.new_allowed_count == 0
    assert report.removed_count == 1
    assert report.removed[0].data_name == '/site/post/bob/post'
    assert report.removed[0].verified


def test_anchor_callback_can_narrow_scope():
    report = compare_lvs_models(
        OLD,
        NEW,
        bounds(),
        check_trust_anchor=lambda name: name.startswith('/site/root/'),
    )
    assert report.outcome == 'NEW_RELATION_FOUND'
    assert report.new_allowed[0].verified

    report = compare_lvs_models(
        OLD,
        NEW,
        bounds(),
        check_trust_anchor=lambda name: False,
    )
    assert report.outcome == 'NO_TRUST_ANCHOR_IN_SCOPE'


@pytest.mark.parametrize('schema', [
    '''
    #KEY: "KEY"/_/_/_
    #root: /"a"/"blog"/#KEY
    #post: /"a"/"blog"/"post"/author/topic <= #author
    #author: /"a"/"blog"/"author"/author/#KEY <= #root
    ''',
    '''
    #r1: a/b & { a: "a" } | { b: "b" }
    #r2: #r1/c & { c: "c" }
    ''',
    '''
    #r1: /a/b/c & { c: b, c: a, a: "a"|"x" } | { b: "b"|"y" }
    #r2: x/y/z & { x: "xxx" }
    ''',
])
def test_abstract_matching_agrees_with_real_checker(schema):
    from ndn.app_support.light_versec.diff import (
        _Budget, _ModelAnalysis, _generate_names,
    )

    model = compile_lvs(schema)
    checker = Checker(model, {})
    bounds = DiffBounds(
        components=COMPONENTS + ('x', 'y', 'z', 'xxx'),
        max_name_len=3,
        max_cert_depth=2,
        max_names=20_000,
        max_evaluations=1_000_000,
    )
    names, truncated = _generate_names(model, bounds, _Budget(1_000_000))
    assert not truncated
    # A bounded slice keeps the property check fast while still covering all
    # generated shapes for these small schemas.
    names = names[:120]
    analysis = _ModelAnalysis(model, {}, _Budget(5_000_000))
    for data in names:
        for signer in names:
            expected = checker.check(list(data), list(signer))
            actual = analysis.check(data, signer)
            # Without contracts, unknown is a superset of false by design.
            assert (actual is None) or (actual is expected), (
                f'{schema!r}: {data} <- {signer} abstract={actual} '
                f'real={expected}'
            )
