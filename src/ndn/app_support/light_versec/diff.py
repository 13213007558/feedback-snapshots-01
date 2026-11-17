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
"""
Bounded policy differencing for Light VerSec models.

The comparer enumerates candidate names only inside a caller supplied finite
scope, evaluates the signing relation in three-valued logic, and follows
certificate chains to an LVS trust root.  It deliberately does not claim that
two models are equivalent over all names, and it does not infer the behaviour
of a user function from concrete executions.  A user function is either
described by an explicit :class:`FnContract`, or every constraint that calls it
is reported as unknown.
"""
from __future__ import annotations

import dataclasses as dc
from collections import defaultdict
from collections.abc import Callable, Iterable
from typing import Any

import lark

from ...encoding import BinaryStr, Component, Name
from . import binary as bny
from .checker import Checker, LvsModelError
from .compiler import SemanticError, compile_lvs


__all__ = [
    'FnContract',
    'EQ_CONTRACT',
    'EQ_TYPE_CONTRACT',
    'DiffBounds',
    'Witness',
    'DiffReport',
    'LvsDiffError',
    'compare_lvs_models',
]


Truth = bool | None
"""Three-valued truth: ``True``, ``False``, or ``None`` for unknown."""


class LvsDiffError(Exception):
    """Raised when the input or the requested analysis scope is invalid."""


@dc.dataclass(frozen=True)
class FnContract:
    """
    A static contract for one LVS user function.

    ``evaluate`` receives the constrained component value and the resolved
    arguments (``None`` for an unbound pattern).  It must return ``True``,
    ``False`` or ``None``.  Any exception is treated as unknown.

    The contract is the *only* source of user-function knowledge used by the
    search.  The function object used by a real :class:`Checker` is never
    consulted to generalise an observed result.
    """

    fn_id: str
    description: str
    evaluate: Callable[[bytes, tuple[bytes | None, ...]], Truth]


def _eq_contract(value: bytes, args: tuple[bytes | None, ...]) -> Truth:
    return all(arg == value for arg in args)


def _eq_type_contract(value: bytes, args: tuple[bytes | None, ...]) -> Truth:
    if any(arg is None for arg in args):
        return None
    try:
        typ = Component.get_type(value)
        return all(Component.get_type(arg) == typ for arg in args)
    except (IndexError, ValueError):
        return None


EQ_CONTRACT = FnContract(
    '$eq',
    'Python-ndn documented $eq: every argument component equals the value',
    _eq_contract,
)
EQ_TYPE_CONTRACT = FnContract(
    '$eq_type',
    'Python-ndn documented $eq_type: every argument has the value\'s TLV type',
    _eq_type_contract,
)


@dc.dataclass(frozen=True)
class DiffBounds:
    """
    Finite search scope.

    :param components: candidate component values used for pattern variables.
    :param max_name_len: maximum number of components in any candidate name.
    :param max_cert_depth: maximum number of certificate links from the data
        signer to a trust anchor.  Zero means the signer must be the anchor.
    :param max_evaluations: abstract match/check evaluation budget.
    :param max_names: maximum number of candidate names generated per model.
    :param max_examples: maximum number of witnesses retained per direction.
    :param data_rules: if non-empty, only names matching these LVS rule names
        are considered as data names.
    """

    components: tuple[str, ...]
    max_name_len: int
    max_cert_depth: int = 4
    max_evaluations: int = 200_000
    max_names: int = 5_000
    max_examples: int = 5
    data_rules: tuple[str, ...] = ()

    def __post_init__(self):
        if not self.components:
            raise LvsDiffError('At least one component candidate is required')
        if self.max_name_len <= 0:
            raise LvsDiffError('max_name_len must be positive')
        if self.max_cert_depth < 0:
            raise LvsDiffError('max_cert_depth must not be negative')
        if self.max_evaluations <= 0:
            raise LvsDiffError('max_evaluations must be positive')
        if self.max_names <= 0:
            raise LvsDiffError('max_names must be positive')
        if self.max_examples <= 0:
            raise LvsDiffError('max_examples must be positive')

    @property
    def component_bytes(self) -> tuple[bytes, ...]:
        values = []
        for text in self.components:
            try:
                values.append(bytes(Component.from_str(text)))
            except (ValueError, IndexError) as exc:
                raise LvsDiffError(f'Invalid component candidate {text!r}: {exc}') from exc
        return tuple(sorted(set(values)))

    def describe(self) -> str:
        rules = ', '.join(self.data_rules) if self.data_rules else '<all rules>'
        return (
            f'components={list(self.components)}, '
            f'max_name_len={self.max_name_len}, '
            f'max_cert_depth={self.max_cert_depth}, '
            f'max_evaluations={self.max_evaluations}, '
            f'max_names={self.max_names}, data_rules={rules}'
        )


def _t_and(left: Truth, right: Truth) -> Truth:
    if left is False or right is False:
        return False
    if left is None or right is None:
        return None
    return True


def _t_or(left: Truth, right: Truth) -> Truth:
    if left is True or right is True:
        return True
    if left is None or right is None:
        return None
    return False


def _shortlex(name: tuple[bytes, ...]) -> tuple[int, tuple[bytes, ...]]:
    return len(name), name


def _name_text(name: tuple[bytes, ...]) -> str:
    return Name.to_str(list(name))


def _strip_implicit(name: tuple[bytes, ...]) -> tuple[bytes, ...]:
    """Mirror Checker: a trailing implicit SHA-256 is not part of the name."""
    if name and Component.get_type(name[-1]) == Component.TYPE_IMPLICIT_SHA256:
        return name[:-1]
    return name


def _truth_text(value: Truth) -> str:
    if value is None:
        return 'unknown'
    return 'true' if value else 'false'


class _Budget:
    def __init__(self, maximum: int):
        self.maximum = maximum
        self.used = 0
        self.exhausted = False
        self.reason: str | None = None

    def spend(self, reason: str) -> bool:
        if self.used >= self.maximum:
            self.exhausted = True
            if self.reason is None:
                self.reason = reason
            return False
        self.used += 1
        return True

    def stop(self, reason: str):
        self.exhausted = True
        if self.reason is None:
            self.reason = reason


def _generate_names(
    model: bny.LvsModel,
    bounds: DiffBounds,
    budget: _Budget,
) -> tuple[list[tuple[bytes, ...]], bool]:
    """Generate names that can reach any node of the compiled tree.

    The result is an over-approximation of all names that some rule can match;
    the real Checker still decides validity.  Truncation is reported
    separately so that it can never be mistaken for scope exhaustion.
    """
    domain = bounds.component_bytes
    found: set[tuple[bytes, ...]] = set()
    truncated = False

    def visit(node_id: int, depth: int, context: dict[int, bytes],
              components: list[bytes]):
        nonlocal truncated
        if truncated:
            return
        if len(found) >= bounds.max_names:
            truncated = True
            budget.stop('name limit reached')
            return
        node = model.nodes[node_id]
        if depth > 0:
            found.add(tuple(components))
        if depth >= bounds.max_name_len:
            return
        for edge in sorted(node.v_edges, key=lambda item: item.value or b''):
            visit(edge.dest, depth + 1, context, components + [bytes(edge.value)])
        for edge in sorted(node.p_edges, key=lambda item: item.tag or 0):
            if edge.tag in context:
                choices = (context[edge.tag],)
            elif edge.tag is not None and edge.tag <= model.named_pattern_cnt:
                choices = domain
            else:
                # Temporary patterns are independent at every occurrence.
                choices = domain
            for value in choices:
                new_context = context
                if edge.tag is not None and edge.tag <= model.named_pattern_cnt:
                    new_context = context.copy()
                    new_context[edge.tag] = value
                visit(edge.dest, depth + 1, new_context, components + [value])

    visit(model.start_id, 0, {}, [])
    return sorted(found, key=_shortlex), truncated


class _ModelAnalysis:
    def __init__(self, model: bny.LvsModel, contracts: dict[str, FnContract],
                 budget: _Budget):
        self.model = model
        self.contracts = contracts
        self.budget = budget
        self._match_cache: dict[
            tuple[tuple[bytes, ...], tuple[tuple[int, bytes], ...]],
            list[tuple[int, dict[int, bytes], Truth]],
        ] = {}
        self._struct_cache: dict[tuple[bytes, ...], frozenset[int]] = {}
        self._pair_cache: dict[tuple[tuple[bytes, ...], tuple[bytes, ...]], Truth] = {}
        self._exhausted = False
        self._in_degree: dict[int, set[int]] = defaultdict(set)
        for node in model.nodes:
            for key_node in node.sign_cons:
                self._in_degree[key_node].add(node.id)
        self.trust_roots: set[int] = {
            node.id for node in model.nodes
            if not node.sign_cons and node.id in self._in_degree
        }
        self.rule_nodes: dict[str, set[int]] = defaultdict(set)
        for node in model.nodes:
            for rule in node.rule_name:
                self.rule_nodes[rule].add(node.id)

    # ----- matching -----------------------------------------------------
    def _eval_option(self, option: bny.ConstraintOption, value: bytes,
                     context: dict[int, bytes]) -> Truth:
        if option.value is not None:
            return bytes(option.value) == value
        if option.tag is not None:
            bound = context.get(option.tag)
            return bound is not None and bound == value
        call = option.fn
        contract = self.contracts.get(call.fn_id)
        if contract is None:
            return None
        args: list[bytes | None] = []
        for arg in call.args:
            if arg.tag is not None:
                bound = context.get(arg.tag)
                args.append(bound)
            else:
                args.append(bytes(arg.value) if arg.value is not None else None)
        try:
            return contract.evaluate(value, tuple(args))
        except Exception:
            return None

    def _eval_cons(self, constraint: bny.PatternConstraint, value: bytes,
                   context: dict[int, bytes]) -> Truth:
        result: Truth = False
        for option in constraint.options:
            result = _t_or(result, self._eval_option(option, value, context))
            if result is True:
                break
        return result

    def _eval_cons_sets(self, constraints: Iterable[bny.PatternConstraint],
                        value: bytes, context: dict[int, bytes]) -> Truth:
        result: Truth = True
        for constraint in constraints:
            result = _t_and(result, self._eval_cons(constraint, value, context))
            if result is False:
                break
        return result

    def match(
        self,
        name: tuple[bytes, ...],
        initial: dict[int, bytes] | None = None,
    ) -> list[tuple[int, dict[int, bytes], Truth]]:
        name = _strip_implicit(name)
        initial = initial or {}
        cache_key = (name, tuple(sorted(initial.items())))
        cached = self._match_cache.get(cache_key)
        if cached is not None:
            return cached
        if not self.budget.spend('name matching'):
            self._exhausted = True
            return []
        results: list[tuple[int, dict[int, bytes], Truth]] = []

        def walk(node_id: int, depth: int, context: dict[int, bytes], truth: Truth):
            node = self.model.nodes[node_id]
            if depth == len(name):
                results.append((node_id, context.copy(), truth))
                return
            value = name[depth]
            # The Checker tries value edges first, then backtracks into
            # pattern edges if the value subtree cannot finish the match.
            for edge in node.v_edges:
                if bytes(edge.value) == value:
                    walk(edge.dest, depth + 1, context, truth)
            for edge in node.p_edges:
                if edge.tag in context:
                    if context[edge.tag] == value:
                        walk(edge.dest, depth + 1, context, truth)
                    continue
                edge_truth = self._eval_cons_sets(edge.cons_sets, value, context)
                if edge_truth is False:
                    continue
                new_context = context
                if edge.tag is not None and edge.tag <= self.model.named_pattern_cnt:
                    new_context = context.copy()
                    new_context[edge.tag] = value
                walk(edge.dest, depth + 1, new_context, _t_and(truth, edge_truth))

        walk(self.model.start_id, 0, initial.copy(), True)
        self._match_cache[cache_key] = results
        return results

    def structural_nodes(self, name: tuple[bytes, ...]) -> frozenset[int]:
        """Nodes reachable by the name tree, ignoring all constraints."""
        name = _strip_implicit(name)
        cached = self._struct_cache.get(name)
        if cached is not None:
            return cached
        result: set[int] = set()

        def walk(node_id: int, depth: int, context: dict[int, bytes]):
            node = self.model.nodes[node_id]
            if depth == len(name):
                result.add(node_id)
                return
            value = name[depth]
            for edge in node.v_edges:
                if bytes(edge.value) == value:
                    walk(edge.dest, depth + 1, context)
            for edge in node.p_edges:
                if edge.tag in context:
                    if context[edge.tag] == value:
                        walk(edge.dest, depth + 1, context)
                    continue
                new_context = context
                if edge.tag is not None and edge.tag <= self.model.named_pattern_cnt:
                    new_context = context.copy()
                    new_context[edge.tag] = value
                walk(edge.dest, depth + 1, new_context)

        walk(self.model.start_id, 0, {})
        frozen = frozenset(result)
        self._struct_cache[name] = frozen
        return frozen

    def check(self, pkt: tuple[bytes, ...], key: tuple[bytes, ...]) -> Truth:
        pkt = _strip_implicit(pkt)
        key = _strip_implicit(key)
        cache_key = (pkt, key)
        if cache_key in self._pair_cache:
            return self._pair_cache[cache_key]
        if not self.budget.spend('relation check'):
            self._exhausted = True
            return None
        unknown = False
        for pkt_node, pkt_context, pkt_truth in self.match(pkt):
            node = self.model.nodes[pkt_node]
            if not node.sign_cons:
                continue
            for key_node, _, key_truth in self.match(key, pkt_context):
                if key_node in node.sign_cons:
                    combined = _t_and(pkt_truth, key_truth)
                    if combined is True:
                        self._pair_cache[cache_key] = True
                        return True
                    if combined is None:
                        unknown = True
        result: Truth = None if unknown else False
        self._pair_cache[cache_key] = result
        return result

    # ----- certificate chains ------------------------------------------
    def build_name_index(self, names: list[tuple[bytes, ...]]):
        self.names = names
        self.by_struct_node: dict[int, list[tuple[bytes, ...]]] = defaultdict(list)
        for name in names:
            for node_id in self.structural_nodes(name):
                self.by_struct_node[node_id].append(name)
        for bucket in self.by_struct_node.values():
            bucket.sort(key=_shortlex)
        self.anchor_nodes = set(self.trust_roots)

    def signing_targets(self, data: tuple[bytes, ...]) -> frozenset[int]:
        targets: set[int] = set()
        for node_id in self.structural_nodes(data):
            targets.update(self.model.nodes[node_id].sign_cons)
        return frozenset(targets)

    def certify(self, max_depth: int):
        """Compute names that can chain to a trust root within ``max_depth``."""
        status: dict[tuple[bytes, ...], Truth] = {}
        depth: dict[tuple[bytes, ...], int] = {}
        pred: dict[tuple[bytes, ...], tuple[bytes, ...]] = {}
        for name in self.names:
            anchor_truth: Truth = False
            for node_id, _, truth in self.match(name):
                if node_id in self.anchor_nodes:
                    anchor_truth = _t_or(anchor_truth, truth)
            if anchor_truth is not False:
                status[name] = anchor_truth
                depth[name] = 0
        for level in range(1, max_depth + 1):
            parents = [
                name for name, value in status.items()
                if value is not False and depth.get(name, max_depth + 1) < level
            ]
            for name in self.names:
                if status.get(name) is True:
                    continue
                better: Truth = False
                chosen: tuple[bytes, ...] | None = None
                candidates: set[tuple[bytes, ...]] = set()
                for node_id in self.structural_nodes(name):
                    for target in self.model.nodes[node_id].sign_cons:
                        candidates.update(self.by_struct_node.get(target, ()))
                for parent in sorted(candidates, key=_shortlex):
                    if parent == name or parent not in parents:
                        continue
                    parent_truth = status[parent]
                    if parent_truth is False:
                        continue
                    link = self.check(name, parent)
                    combined = _t_and(link, parent_truth)
                    if combined is True:
                        better = True
                        chosen = parent
                        break
                    if combined is None:
                        better = None
                if better is True:
                    status[name] = True
                    depth[name] = level
                    assert chosen is not None
                    pred[name] = chosen
                elif better is None and status.get(name) is not True:
                    status[name] = None
                    depth.setdefault(name, level)
        # Pairs whose value is unknown must not be presented as absent.
        self.uncertain = any(value is None for value in status.values())
        self.cert_status = status
        self.cert_depth = depth
        self.cert_pred = pred

    def certificate_path(self, name: tuple[bytes, ...]) -> tuple[tuple[bytes, ...], ...] | None:
        if self.cert_status.get(name) is not True:
            return None
        path = [name]
        seen = {name}
        current = name
        while current in self.cert_pred:
            current = self.cert_pred[current]
            if current in seen:
                return None
            seen.add(current)
            path.append(current)
        if self.cert_depth.get(path[-1], None) != 0:
            return None
        return tuple(path)


@dc.dataclass(frozen=True)
class Witness:
    """One concrete relation with a candidate certificate chain."""

    data_name: str
    signer_name: str
    certificate_path: tuple[str, ...]
    cert_depth: int
    old_check: Truth
    new_check: Truth
    old_certified: Truth
    new_certified: Truth
    verified: bool
    verification: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            'data': self.data_name,
            'signer': self.signer_name,
            'certificate_path': list(self.certificate_path),
            'cert_depth': self.cert_depth,
            'old_check': _truth_text(self.old_check),
            'new_check': _truth_text(self.new_check),
            'old_certified': _truth_text(self.old_certified),
            'new_certified': _truth_text(self.new_certified),
            'verified': self.verified,
            'verification': list(self.verification),
        }


@dc.dataclass
class DiffReport:
    """Result of one bounded comparison."""

    outcome: str
    scope: DiffBounds
    search_complete: bool
    budget_exhausted: bool
    budget_reason: str | None
    evaluations: int
    names_considered: int
    old_roots: tuple[str, ...]
    new_roots: tuple[str, ...]
    old_anchor_candidates: int
    new_anchor_candidates: int
    new_allowed_count: int
    removed_count: int
    new_allowed: list[Witness]
    removed: list[Witness]
    examples_truncated: bool
    unknown_functions: tuple[str, ...]
    unknown_new_count: int
    unknown_examples: tuple[tuple[str, str, str], ...]
    notes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            'outcome': self.outcome,
            'scope': {
                'components': list(self.scope.components),
                'max_name_len': self.scope.max_name_len,
                'max_cert_depth': self.scope.max_cert_depth,
                'max_evaluations': self.scope.max_evaluations,
                'max_names': self.scope.max_names,
                'data_rules': list(self.scope.data_rules),
                'description': self.scope.describe(),
            },
            'search_complete': self.search_complete,
            'budget_exhausted': self.budget_exhausted,
            'budget_reason': self.budget_reason,
            'evaluations': self.evaluations,
            'names_considered': self.names_considered,
            'old_roots': list(self.old_roots),
            'new_roots': list(self.new_roots),
            'old_anchor_candidates': self.old_anchor_candidates,
            'new_anchor_candidates': self.new_anchor_candidates,
            'new_allowed_count': self.new_allowed_count,
            'removed_count': self.removed_count,
            'new_allowed': [w.to_dict() for w in self.new_allowed],
            'removed': [w.to_dict() for w in self.removed],
            'examples_truncated': self.examples_truncated,
            'unknown_functions': list(self.unknown_functions),
            'unknown_new_count': self.unknown_new_count,
            'unknown_examples': [
                {'data': d, 'signer': s, 'reason': r}
                for d, s, r in self.unknown_examples
            ],
            'notes': list(self.notes),
        }

    def format_text(self) -> str:
        lines = [
            f'OUTCOME: {self.outcome}',
            f'SCOPE: {self.scope.describe()}',
            f'SEARCH: complete={self.search_complete} '
            f'budget_exhausted={self.budget_exhausted} '
            f'evaluations={self.evaluations}/{self.scope.max_evaluations} '
            f'names={self.names_considered}',
        ]
        if self.budget_reason:
            lines.append(f'BUDGET_REASON: {self.budget_reason}')
        lines.append(
            f'ANCHOR_CANDIDATES: old={self.old_anchor_candidates} '
            f'new={self.new_anchor_candidates} '
            f'roots old={list(self.old_roots)} new={list(self.new_roots)}'
        )
        if self.examples_truncated:
            lines.append(
                'EXAMPLES: truncated; counts cover all examined pairs, but '
                'only the first examples are shown'
            )
        if self.new_allowed:
            first = self.new_allowed[0]
            lines.append('SHORTEST_NEW_ALLOWED:')
            lines.append(f'  data:   {first.data_name}')
            lines.append(f'  signer: {first.signer_name}')
            lines.append('  path:   ' + ' <- '.join(first.certificate_path))
            lines.append(
                f'  checker: old={_truth_text(first.old_check)} '
                f'new={_truth_text(first.new_check)} '
                f'verified={first.verified}'
            )
        else:
            lines.append('SHORTEST_NEW_ALLOWED: none')
        lines.append(
            f'COUNTS: new_allowed={self.new_allowed_count} '
            f'removed={self.removed_count} unknown_new={self.unknown_new_count}'
        )
        if self.unknown_functions:
            lines.append(f'UNKNOWN_FUNCTIONS: {list(self.unknown_functions)}')
        for note in self.notes:
            lines.append(f'NOTE: {note}')
        return '\n'.join(lines)


def _normalize_contracts(
    contracts: Iterable[FnContract] | dict[str, FnContract],
) -> dict[str, FnContract]:
    if isinstance(contracts, dict):
        result = dict(contracts)
    else:
        result = {contract.fn_id: contract for contract in contracts}
    for fn_id, contract in result.items():
        if fn_id != contract.fn_id:
            raise LvsDiffError(
                f'Contract key {fn_id!r} does not match fn_id {contract.fn_id!r}'
            )
    return result


def _load_model(text_or_model: str | bny.LvsModel) -> bny.LvsModel:
    if isinstance(text_or_model, bny.LvsModel):
        return text_or_model
    try:
        return compile_lvs(text_or_model)
    except (SemanticError, lark.UnexpectedInput) as exc:
        raise LvsDiffError(f'Unable to compile LVS model: {exc}') from exc


def _used_functions(model: bny.LvsModel) -> set[str]:
    used = set()
    for node in model.nodes:
        for edge in node.p_edges:
            for constraint in edge.cons_sets:
                for option in constraint.options:
                    if option.fn is not None:
                        used.add(option.fn.fn_id)
    return used


def _real_check(checker: Checker, pkt: tuple[bytes, ...],
                key: tuple[bytes, ...]) -> Truth:
    try:
        return bool(checker.check(list(pkt), list(key)))
    except LvsModelError:
        return None
    except Exception:
        return None


def _verify_witness(
    checker: Checker,
    data: tuple[bytes, ...],
    signer: tuple[bytes, ...],
    path: tuple[tuple[bytes, ...], ...],
    root_rules: set[str],
) -> tuple[bool, tuple[str, ...]]:
    messages = []
    direct = _real_check(checker, data, signer)
    messages.append(f'check(data, signer)={_truth_text(direct)}')
    if direct is not True:
        return False, tuple(messages)
    for current, issuer in zip(path, path[1:]):
        link = _real_check(checker, current, issuer)
        messages.append(
            f'check({_name_text(current)}, {_name_text(issuer)})={_truth_text(link)}'
        )
        if link is not True:
            return False, tuple(messages)
    anchor = path[-1]
    try:
        matched_rules = {
            rule
            for rule_names, _ in checker.match(list(anchor))
            for rule in rule_names
        }
    except LvsModelError:
        messages.append('anchor match=unknown (user function missing)')
        return False, tuple(messages)
    messages.append(f'anchor={_name_text(anchor)}, rules={sorted(matched_rules)}')
    if not matched_rules.intersection(root_rules):
        return False, tuple(messages)
    return True, tuple(messages)


def compare_lvs_models(
    old_model: str | bny.LvsModel,
    new_model: str | bny.LvsModel,
    bounds: DiffBounds,
    *,
    old_contracts: Iterable[FnContract] | dict[str, FnContract] = (),
    new_contracts: Iterable[FnContract] | dict[str, FnContract] = (),
    old_checker_fns: dict[str, Callable[[BinaryStr, list[BinaryStr]], bool]] | None = None,
    new_checker_fns: dict[str, Callable[[BinaryStr, list[BinaryStr]], bool]] | None = None,
    check_trust_anchor: Callable[[str], bool] | None = None,
) -> DiffReport:
    """
    Compare the signing relations of two LVS models inside ``bounds``.

    A relation ``(data, signer)`` is *effective* when the model's Checker
    allows ``signer`` to sign ``data`` **and** the signer can be chained to an
    LVS trust root using at most ``bounds.max_cert_depth`` certificate links.
    Only effective relations participate in the difference.

    ``check_trust_anchor`` optionally says whether a matched LVS root name is
    actually configured as a trust anchor.  Without it, every generated name
    that matches a root rule is treated as an available anchor; the report
    therefore describes "anchored to a rule root", not a deployment.

    The search is finite and is not a proof of equivalence.  User functions
    without a :class:`FnContract` make the affected constraints unknown; a
    concrete true execution observed by a real Checker is used only to verify
    the emitted witness, never to generalise over other names.
    """
    old = _load_model(old_model)
    new = _load_model(new_model)
    old_contract_map = _normalize_contracts(old_contracts)
    new_contract_map = _normalize_contracts(new_contracts)
    budget = _Budget(bounds.max_evaluations)

    old_analysis = _ModelAnalysis(old, old_contract_map, budget)
    new_analysis = _ModelAnalysis(new, new_contract_map, budget)
    try:
        old_checker = Checker(old, old_checker_fns or {})
        new_checker = Checker(new, new_checker_fns or {})
    except LvsModelError as exc:
        raise LvsDiffError(f'Unable to initialize Checker: {exc}') from exc

    old_names, old_truncated = _generate_names(old, bounds, budget)
    new_names, new_truncated = _generate_names(new, bounds, budget)
    names = sorted(set(old_names) | set(new_names), key=_shortlex)
    old_analysis.build_name_index(names)
    new_analysis.build_name_index(names)

    old_had_root = bool(old_analysis.trust_roots)
    new_had_root = bool(new_analysis.trust_roots)
    if check_trust_anchor is not None:
        def filter_anchors(analysis: _ModelAnalysis):
            # A rule-root node is a usable anchor only if at least one name
            # reaching it is explicitly accepted by the caller.
            usable = set()
            for name in names:
                if not check_trust_anchor(_name_text(name)):
                    continue
                for node_id, _, truth in analysis.match(name):
                    if node_id in analysis.trust_roots and truth is not False:
                        usable.add(node_id)
            analysis.trust_roots &= usable
            analysis.anchor_nodes = set(analysis.trust_roots)
        filter_anchors(old_analysis)
        filter_anchors(new_analysis)

    old_analysis.certify(bounds.max_cert_depth)
    new_analysis.certify(bounds.max_cert_depth)

    old_roots = tuple(sorted(old_checker.root_of_trust()))
    new_roots = tuple(sorted(new_checker.root_of_trust()))
    # Whether some name in scope actually matched a trust root.  This is
    # distinct from "can be certified": it diagnoses a scope that simply never
    # reaches the anchor.
    def root_name_reached(analysis: _ModelAnalysis) -> bool:
        if not analysis.trust_roots:
            return False
        for name in names:
            for node_id, _, truth in analysis.match(name):
                if node_id in analysis.trust_roots and truth is not False:
                    return True
        return False

    old_root_reached = root_name_reached(old_analysis)
    new_root_reached = root_name_reached(new_analysis)
    old_anchor_candidates = sum(
        1 for name in names if old_analysis.cert_status.get(name, False) is not False
    )
    new_anchor_candidates = sum(
        1 for name in names if new_analysis.cert_status.get(name, False) is not False
    )

    notes: list[str] = []
    old_used = _used_functions(old)
    new_used = _used_functions(new)
    unknown_functions = tuple(sorted(
        fn for fn in (old_used | new_used)
        if fn not in old_contract_map or fn not in new_contract_map
    ))
    if unknown_functions:
        notes.append(
            'No static contract for these user functions; constraints using '
            'them are reported as unknown: ' + ', '.join(unknown_functions)
        )
    if old_truncated or new_truncated:
        notes.append(
            'Candidate name generation hit max_names; the search is incomplete.'
        )

    no_data_scope = False
    if bounds.data_rules:
        data_nodes: set[int] = set()
        missing = []
        for rule in bounds.data_rules:
            nodes = set(old_analysis.rule_nodes.get(rule, set())) | set(
                new_analysis.rule_nodes.get(rule, set())
            )
            if not nodes:
                missing.append(rule)
            data_nodes.update(nodes)
        if missing:
            notes.append(f'Data rule(s) not found: {missing}')
        data_candidates = [
            name for name in names
            if (old_analysis.structural_nodes(name) & data_nodes)
            or (new_analysis.structural_nodes(name) & data_nodes)
        ]
        if not data_candidates:
            no_data_scope = True
    else:
        data_candidates = names

    empty_report = DiffReport(
        outcome='NO_DATA_NAMES_IN_SCOPE' if no_data_scope else 'NO_TRUST_ANCHOR_IN_SCOPE',
        scope=bounds,
        search_complete=not budget.exhausted,
        budget_exhausted=budget.exhausted,
        budget_reason=budget.reason,
        evaluations=budget.used,
        names_considered=len(names),
        old_roots=old_roots,
        new_roots=new_roots,
        old_anchor_candidates=old_anchor_candidates,
        new_anchor_candidates=new_anchor_candidates,
        new_allowed_count=0,
        removed_count=0,
        new_allowed=[],
        removed=[],
        examples_truncated=False,
        unknown_functions=unknown_functions,
        unknown_new_count=0,
        unknown_examples=(),
        notes=tuple(notes),
    )

    if budget.exhausted:
        empty_report.outcome = 'BUDGET_EXHAUSTED'
        empty_report.search_complete = False
        empty_report.notes = tuple(notes + [
            'The search budget was exhausted before the relation space could '
            'be examined; absence of a counterexample was NOT established.'
        ])
        return empty_report

    if no_data_scope:
        empty_report.search_complete = False
        empty_report.notes = tuple(notes + [
            'The data-rule filter leaves no candidate data names in scope.'
        ])
        return empty_report

    if not old_had_root or not new_had_root:
        empty_report.outcome = 'NO_TRUST_ROOT'
        empty_report.search_complete = False
        empty_report.notes = tuple(notes + [
            'At least one model has no trust root; no effective relation can be certified.'
        ])
        return empty_report

    if not old_root_reached or not new_root_reached:
        empty_report.outcome = 'NO_TRUST_ANCHOR_IN_SCOPE'
        empty_report.search_complete = False
        empty_report.notes = tuple(notes + [
            'No trust-anchor name was generated inside the component/length '
            'bounds; effective relations cannot be assessed. Increase the '
            'bounds or include the anchor components.'
        ])
        return empty_report

    # Pre-filter: a data name can only form a relation with a name that
    # structurally matches one of its signing targets.  This avoids the full
    # quadratic pair scan without changing the declared scope.
    signer_by_target: dict[int, list[tuple[bytes, ...]]] = {}
    for analysis in (old_analysis, new_analysis):
        for target, bucket in analysis.by_struct_node.items():
            if target not in signer_by_target:
                signer_by_target[target] = bucket
    target_cache: dict[frozenset[int], dict[int, list[tuple[bytes, ...]]]] = {}
    signer_index: dict[tuple[bytes, ...], dict[int, list[tuple[bytes, ...]]]] = {}
    for data in data_candidates:
        targets = (
            old_analysis.signing_targets(data)
            | new_analysis.signing_targets(data)
        )
        buckets = target_cache.get(targets)
        if buckets is None:
            candidates: set[tuple[bytes, ...]] = set()
            for target in targets:
                candidates.update(signer_by_target.get(target, ()))
            candidates.discard(data)
            buckets = defaultdict(list)
            for signer in candidates:
                buckets[len(signer)].append(signer)
            for bucket in buckets.values():
                bucket.sort(key=_shortlex)
            buckets = dict(buckets)
            target_cache[targets] = buckets
        signer_index[data] = buckets
    data_candidates = [
        data for data in data_candidates
        if any(signer_index[data].values())
    ]

    by_len: dict[int, list[tuple[bytes, ...]]] = defaultdict(list)
    for name in data_candidates:
        by_len[len(name)].append(name)
    for bucket in by_len.values():
        bucket.sort(key=_shortlex)

    data_set = set(data_candidates)
    new_allowed: list[Witness] = []
    removed: list[Witness] = []
    new_allowed_count = 0
    removed_count = 0
    unknown_new_count = 0
    unknown_examples: list[tuple[str, str, str]] = []
    examples_truncated = False

    def effective(analysis: _ModelAnalysis, data, signer):
        direct = analysis.check(data, signer)
        certified = analysis.cert_status.get(signer, False)
        return _t_and(direct, certified), direct, certified

    # Shortlex order: total length first, then the data name, then the signer
    # name.  This makes the first reported witness the shortest one.
    ordered_pairs: list[tuple[tuple[bytes, ...], tuple[bytes, ...]]] = []
    for total in range(2, 2 * bounds.max_name_len + 1):
        level: list[tuple[tuple[bytes, ...], tuple[bytes, ...]]] = []
        for data_len in range(1, bounds.max_name_len + 1):
            signer_len = total - data_len
            if signer_len < 1 or signer_len > bounds.max_name_len:
                continue
            for data in by_len.get(data_len, ()):
                for signer in signer_index[data].get(signer_len, ()):
                    level.append((data, signer))
        level.sort(key=lambda pair: _shortlex(pair[0] + pair[1]))
        ordered_pairs.extend(level)
    for data, signer in ordered_pairs:
        old_eff, old_direct, old_cert = effective(old_analysis, data, signer)
        new_eff, new_direct, new_cert = effective(new_analysis, data, signer)
        if budget.exhausted:
            break
        if new_eff is True and old_eff is not True:
            if old_eff is False:
                path = new_analysis.certificate_path(signer)
                if path is not None:
                    verified, messages = _verify_witness(
                        new_checker, data, signer, path, set(new_roots)
                    )
                    if not verified:
                        unknown_new_count += 1
                        if len(unknown_examples) < bounds.max_examples:
                            unknown_examples.append((
                                _name_text(data), _name_text(signer),
                                'new=True could not be confirmed by '
                                'the real Checker: ' + '; '.join(messages),
                            ))
                        else:
                            examples_truncated = True
                        continue
                    new_allowed_count += 1
                    if len(new_allowed) < bounds.max_examples:
                        new_allowed.append(Witness(
                            data_name=_name_text(data),
                            signer_name=_name_text(signer),
                            certificate_path=tuple(
                                _name_text(item) for item in path
                            ),
                            cert_depth=len(path) - 1,
                            old_check=old_direct,
                            new_check=new_direct,
                            old_certified=old_cert,
                            new_certified=new_cert,
                            verified=verified,
                            verification=messages,
                        ))
                    else:
                        examples_truncated = True
            else:
                unknown_new_count += 1
                if len(unknown_examples) < bounds.max_examples:
                    unknown_examples.append((
                        _name_text(data), _name_text(signer),
                        f'old={_truth_text(old_eff)} new={_truth_text(new_eff)}',
                    ))
        elif old_eff is True and new_eff is False:
            path = old_analysis.certificate_path(signer)
            if path is not None:
                verified, messages = _verify_witness(
                    old_checker, data, signer, path, set(old_roots)
                )
                if not verified:
                    unknown_new_count += 1
                    if len(unknown_examples) < bounds.max_examples:
                        unknown_examples.append((
                            _name_text(data), _name_text(signer),
                            'old=True could not be confirmed by '
                            'the real Checker: ' + '; '.join(messages),
                        ))
                    else:
                        examples_truncated = True
                    continue
                removed_count += 1
                if len(removed) < bounds.max_examples:
                    removed.append(Witness(
                        data_name=_name_text(data),
                        signer_name=_name_text(signer),
                        certificate_path=tuple(
                            _name_text(item) for item in path
                        ),
                        cert_depth=len(path) - 1,
                        old_check=old_direct,
                        new_check=new_direct,
                        old_certified=old_cert,
                        new_certified=new_cert,
                        verified=verified,
                        verification=messages,
                    ))
                else:
                    examples_truncated = True
        elif unknown_functions and (new_eff is None or old_eff is None):
            unknown_new_count += 1
            if len(unknown_examples) < bounds.max_examples:
                unknown_examples.append((
                    _name_text(data), _name_text(signer),
                    f'old={_truth_text(old_eff)} '
                    f'new={_truth_text(new_eff)}',
                ))
            else:
                examples_truncated = True
    if bounds.data_rules:
        missing = [
            rule for rule in bounds.data_rules
            if not old_analysis.rule_nodes.get(rule)
            and not new_analysis.rule_nodes.get(rule)
        ]
        if missing:
            notes.append(f'Data rule(s) not found in either model: {missing}')

    if new_allowed_count:
        outcome = 'NEW_RELATION_FOUND'
    elif removed_count:
        outcome = 'REMOVED_RELATION_FOUND'
    elif budget.exhausted or old_truncated or new_truncated:
        outcome = 'BUDGET_EXHAUSTED'
    elif (
        unknown_new_count
        or old_analysis.uncertain
        or new_analysis.uncertain
        or old_analysis._exhausted
        or new_analysis._exhausted
    ):
        outcome = 'UNKNOWN'
        notes.append(
            'Some pairs are unknown because a constraint has no analysable '
            'contract or a real Checker call could not confirm the abstract '
            'result; no universal absence claim is made.'
        )
    else:
        outcome = 'NO_NEW_RELATION_IN_SCOPE'

    if old_analysis._exhausted or new_analysis._exhausted:
        budget.exhausted = True
        if budget.reason is None:
            budget.reason = 'analysis evaluation budget'
    search_complete = not (budget.exhausted or old_truncated or new_truncated)
    if old_truncated or new_truncated:
        budget.exhausted = True
        if budget.reason is None:
            budget.reason = 'name limit reached'

    notes.append(
        'Coverage is finite: the result says nothing about names outside the '
        'component candidates and length bound, nor about values of user '
        'functions without contracts. Witnesses are point-checked with Checker.'
    )
    if outcome == 'BUDGET_EXHAUSTED':
        notes.append(
            'The search budget or name limit was exhausted; absence of a '
            'counterexample was NOT established.'
        )
    elif search_complete:
        notes.append(
            'All candidate pairs in the declared scope were examined; this is '
            'scope exhaustion, not a proof over all NDN names.'
        )

    return DiffReport(
        outcome=outcome,
        scope=bounds,
        search_complete=search_complete,
        budget_exhausted=budget.exhausted,
        budget_reason=budget.reason,
        evaluations=budget.used,
        names_considered=len(names),
        old_roots=old_roots,
        new_roots=new_roots,
        old_anchor_candidates=old_anchor_candidates,
        new_anchor_candidates=new_anchor_candidates,
        new_allowed_count=new_allowed_count,
        removed_count=removed_count,
        new_allowed=new_allowed,
        removed=removed,
        unknown_functions=unknown_functions,
        unknown_new_count=unknown_new_count,
        unknown_examples=tuple(unknown_examples),
        notes=tuple(notes),
        examples_truncated=examples_truncated,
    )
