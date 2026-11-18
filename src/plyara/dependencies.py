# Copyright 2025 plyara Maintainers
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
"""Effective dependency analysis for YARA rulesets.

The analyzer answers a release-time question that a text search cannot:
which detections are actually affected when a rule (in particular a
``global`` rule acting as a gate) is changed or removed.

Two structurally different relations are kept separate:

* ``explicit`` edges — rule names referenced from a condition expression.
* ``gate`` edges — the implicit AND that every ``global`` rule imposes on
  every other rule within the same file namespace.

Name-only matches inside string contents, comments, module member
expressions and external variables are never treated as rule references.
Bare identifiers that cannot be resolved to a rule, a module or a declared
external variable stay open as unresolved symbols instead of being guessed.
"""
import dataclasses
import enum
import pathlib
import re
from collections import defaultdict

from plyara.core import Plyara


class EdgeKind(enum.Enum):
    """Classify the relation represented by a dependency edge."""

    EXPLICIT = 'explicit'
    WILDCARD = 'wildcard'
    GATE = 'gate'


class SymbolKind(enum.Enum):
    """Classify the fate of an unresolvable bare identifier."""

    UNRESOLVED = 'unresolved'
    EXTERNAL = 'external'
    LOOP_VAR = 'loop_var'


# YARA condition operators and punctuation, longest alternatives first.
_TOKEN_RE = re.compile(
    r"""
    (?P<string>"(?:\\.|[^"\\])*")           # double quoted string literal
    | (?P<regex>/[^/\n]+/[a-z]*)            # regular expression literal
    | (?P<bytestring>\{(?:[^\n}]*)\})       # inline byte sequence literal
    | (?P<stringref>[$#@!][A-Za-z0-9_*]+)   # string identifier / count / offset
    | (?P<hex>0[xX][0-9A-Fa-f]+)            # hexadecimal number
    | (?P<size>\d+[KM]B)                     # size constant such as 100MB
    | (?P<number>\d+(?:\.\d+)?)             # decimal number
    | (?P<dotname>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)  # module.member
    | (?P<identifier>[A-Za-z_][A-Za-z0-9_]*)
    | (?P<operator>\.\.|==|!=|<=|>=|>>|<<|&&|\|\||[(){}[\],.+\-*/%<>=!&|^~?:])
    """,
    re.VERBOSE,
)

# Built-in condition keywords, functions and constants (Plyara.KEYWORDS plus
# the built-in functions that lex as bare identifiers).
_BUILTIN_IDENTIFIERS = set(Plyara.KEYWORDS) | {
    'defined',
    'matches',
    'contains',
    'icontains',
    'startswith',
    'istartswith',
    'endswith',
    'iendswith',
    'iequals',
}


@dataclasses.dataclass(frozen=True)
class RuleRef:
    """A rule node, qualified by its file namespace."""

    namespace: str
    name: str

    def __str__(self):
        """Render the qualified rule reference as ``namespace::name``."""
        return f'{self.namespace}::{self.name}'


@dataclasses.dataclass(frozen=True)
class Edge:
    """One dependency relation between two rules.

    Attributes:
        source: The rule whose condition establishes the relation.
        target: The referenced or gating rule.
        kind: Explicit reference, wildcard reference or implicit global gate.
        line: 1-based line of the referencing condition within its file.
        snippet: The exact condition text fragment that produced the edge.
    """

    source: RuleRef
    target: RuleRef
    kind: EdgeKind
    line: int
    snippet: str


@dataclasses.dataclass(frozen=True)
class UnresolvedSymbol:
    """A bare identifier that could not be resolved to a known rule."""

    rule: RuleRef
    symbol: str
    line: int
    kind: SymbolKind
    detail: str


@dataclasses.dataclass
class RuleInfo:
    """Metadata and parsed condition for a single rule."""

    ref: RuleRef
    path: pathlib.Path
    scopes: frozenset
    start_line: int
    stop_line: int
    condition_line: int
    condition_text: str
    terms: tuple
    imports: frozenset
    includes: tuple


@dataclasses.dataclass
class DependencyGraph:
    """The full analysis result for a set of rule files."""

    rules: dict
    edges: list
    unresolved: list
    namespaces: dict

    def edges_from(self, rule):
        """Return every edge originating at ``rule``."""
        return [edge for edge in self.edges if edge.source == rule]

    def edges_to(self, rule):
        """Return every edge terminating at ``rule``."""
        return [edge for edge in self.edges if edge.target == rule]

    def cycles(self):
        """List explicit-reference cycles as paths of :class:`RuleRef`.

        Gate edges are excluded: they connect a global to every same-namespace
        rule and would create structural noise rather than real condition
        cycles.
        """
        adjacency = defaultdict(set)
        for edge in self.edges:
            if edge.kind in (EdgeKind.EXPLICIT, EdgeKind.WILDCARD):
                adjacency[edge.source].add(edge.target)

        cycles = []
        seen_cycles = set()
        stack = []
        on_stack = set()

        def canonical(cycle_nodes):
            # Rotate so the lexicographically smallest node starts the cycle;
            # the same loop entered at different nodes is one reported path.
            body = cycle_nodes[:-1]
            start = min(range(len(body)), key=lambda idx: str(body[idx]))
            rotated = body[start:] + body[:start]
            return tuple(str(item) for item in rotated + [rotated[0]])

        def visit(node):
            stack.append(node)
            on_stack.add(node)
            for neighbor in sorted(adjacency[node], key=str):
                if neighbor in on_stack:
                    cycle = stack[stack.index(neighbor):] + [neighbor]
                    key = canonical(cycle)
                    if key not in seen_cycles:
                        seen_cycles.add(key)
                        cycles.append(cycle)
                else:
                    visit(neighbor)
            stack.pop()
            on_stack.discard(node)

        for node in sorted(self.rules, key=str):
            visit(node)
        return cycles

    def impact(self, rule):
        """Return every rule effectively affected if ``rule`` is changed.

        For a global gate the affected set contains every non-global rule in
        the same namespace, not only rules naming it explicitly, plus every
        rule reachable from them through explicit or wildcard references.
        For a non-global rule the set is the explicit reverse reachability
        closure. The changed rule itself is excluded.
        """
        if rule not in self.rules:
            raise KeyError(f'Unknown rule: {rule}')

        seeds = set()
        info = self.rules[rule]
        if 'global' in info.scopes:
            for other_ref, other in self.rules.items():
                if other_ref.namespace != rule.namespace or other_ref == rule:
                    continue
                if 'global' not in other.scopes:
                    seeds.add(other_ref)
        seeds.update(
            edge.source for edge in self.edges_to(rule)
            if edge.kind in (EdgeKind.EXPLICIT, EdgeKind.WILDCARD)
        )

        reverse = defaultdict(set)
        for edge in self.edges:
            if edge.kind in (EdgeKind.EXPLICIT, EdgeKind.WILDCARD):
                reverse[edge.target].add(edge.source)

        affected = set()
        pending = list(seeds)
        while pending:
            current = pending.pop()
            if current in affected:
                continue
            affected.add(current)
            pending.extend(reverse[current])
        affected.discard(rule)
        return affected

    def explain_impact(self, rule):
        """Pair each impacted rule with the edge path proving the impact."""
        info = self.rules[rule]
        reverse = defaultdict(list)
        for edge in self.edges:
            if edge.kind in (EdgeKind.EXPLICIT, EdgeKind.WILDCARD):
                reverse[edge.target].append(edge)

        result = {}
        if 'global' in info.scopes:
            for other_ref, other in self.rules.items():
                if other_ref.namespace == rule.namespace and other_ref != rule \
                        and 'global' not in other.scopes:
                    gate_edges = [
                        edge for edge in self.edges
                        if edge.kind == EdgeKind.GATE and edge.source == other_ref and edge.target == rule
                    ]
                    result[other_ref] = gate_edges

        for edge in self.edges_to(rule):
            if edge.kind in (EdgeKind.EXPLICIT, EdgeKind.WILDCARD):
                result.setdefault(edge.source, [edge])

        pending = list(result)
        seen = set(pending)
        while pending:
            current = pending.pop()
            for edge in reverse[current]:
                path = result[current] + [edge]
                if edge.source not in result or len(path) < len(result[edge.source]):
                    result[edge.source] = path
                if edge.source not in seen:
                    seen.add(edge.source)
                    pending.append(edge.source)
        result.pop(rule, None)
        return result


def _tokenize_condition(condition_text, condition_line):
    """Tokenize a condition expression, preserving source line numbers.

    Returns tuples of ``(kind, value, line)`` where kind is one of the
    ``_TOKEN_RE`` group names. The tokenizer ignores comments and string
    contents because both are handled as opaque literals.
    """
    tokens = []
    pos = 0
    line_offsets = [0]
    for char in condition_text:
        if char == '\n':
            line_offsets.append(pos + 1)
        pos += 1

    def line_for(offset):
        """Map a condition character offset to a 1-based source line."""
        line_index = 0
        for index, line_offset in enumerate(line_offsets):
            if line_offset <= offset:
                line_index = index
            else:
                break
        return condition_line + line_index

    for match in _TOKEN_RE.finditer(condition_text):
        kind = match.lastgroup
        value = match.group()
        tokens.append((kind, value, line_for(match.start())))
    return tokens


def _strip_condition(raw_condition):
    """Remove the leading ``condition:`` marker from a Plyara raw condition."""
    text = raw_condition
    marker = 'condition'
    if text.lstrip().startswith(marker):
        index = text.index(marker) + len(marker)
        text = text[index:]
        if text.startswith(':'):
            text = text[1:]
    return text


def _collect_loop_variables(tokens):
    """Extract loop variables introduced by ``for ... in`` expressions."""
    loop_vars = set()
    index = 0
    while index < len(tokens):
        kind, value, _ = tokens[index]
        if kind == 'identifier' and value == 'for':
            cursor = index + 1
            if cursor < len(tokens) and tokens[cursor][0] == 'identifier' \
                    and tokens[cursor][1] in ('all', 'any', 'none'):
                cursor += 1
            while cursor < len(tokens):
                kind2, value2, _ = tokens[cursor]
                if kind2 == 'identifier' and value2 == 'in':
                    break
                if kind2 == 'identifier':
                    loop_vars.add(value2)
                cursor += 1
        index += 1
    return loop_vars


class DependencyAnalyzer:
    """Build an effective dependency graph from YARA rule files."""

    def __init__(self, external_variables=None):
        """Create an analyzer.

        Args:
            external_variables: Optional iterable of external variable names
                declared through the scanner API. Same-named rules take
                precedence; otherwise matching identifiers are reported as
                external-variable uses rather than unresolved symbols.
        """
        self.external_variables = set(external_variables or ())
        self.parser = Plyara()

    def analyze_paths(self, paths):
        """Parse the given file paths and build the dependency graph."""
        parsed_files = []
        for path in (pathlib.Path(item) for item in paths):
            text = path.read_text(encoding='utf-8')
            namespace = self._namespace_for(path)
            parsed_files.append(self._parse(text, path, namespace))
        return self._build(parsed_files)

    def analyze_strings(self, sources):
        """Parse ``{name: text}`` mappings, each mapping one file namespace."""
        parsed_files = []
        for name, text in sources.items():
            path = pathlib.Path(name)
            parsed_files.append(self._parse(text, path, self._namespace_for(path)))
        return self._build(parsed_files)

    @staticmethod
    def _namespace_for(path):
        """Return the YARA namespace implied by a file path.

        Each file is compiled as its own namespace by default, mirroring
        ``yara.compile(filepath=...)`` where the namespace is the file stem.
        """
        return path.stem

    def _parse(self, text, path, namespace):
        """Parse one file's text into :class:`RuleInfo` entries."""
        self.parser.clear()
        rules = self.parser.parse_string(text)
        entries = []
        for rule in rules:
            scopes = frozenset(rule.get('scopes', ()))
            raw_condition = rule.get('raw_condition', '')
            condition_text = _strip_condition(raw_condition)
            condition_line = self._condition_start_line(rule, raw_condition)
            ref = RuleRef(namespace, rule['rule_name'])
            entries.append(RuleInfo(
                ref=ref,
                path=path,
                scopes=scopes,
                start_line=int(rule['start_line']),
                stop_line=int(rule['stop_line']),
                condition_line=condition_line,
                condition_text=condition_text,
                terms=tuple(rule.get('condition_terms', ())),
                imports=frozenset(rule.get('imports', ())),
                includes=tuple(rule.get('includes', ())),
            ))
        return namespace, entries

    @staticmethod
    def _condition_start_line(rule, raw_condition):
        """Locate the 1-based line of the first condition term."""
        prefix_lines = raw_condition.count('\n', 0, raw_condition.index('condition') + 1) \
            if 'condition' in raw_condition else 0
        return int(rule['start_line']) + prefix_lines

    def _build(self, parsed_files):
        """Assemble the graph from parsed namespace rule lists."""
        rules = {}
        namespaces = defaultdict(list)
        duplicates = []
        for namespace, entries in parsed_files:
            for info in entries:
                if info.ref in rules:
                    duplicates.append(info.ref)
                rules[info.ref] = info
                namespaces[namespace].append(info.ref)

        edges = []
        unresolved = []
        for info in rules.values():
            file_edges, file_unresolved = self._analyze_rule(info, rules)
            edges.extend(file_edges)
            unresolved.extend(file_unresolved)

        graph = DependencyGraph(
            rules=rules,
            edges=edges,
            unresolved=unresolved,
            namespaces=dict(namespaces),
        )
        if duplicates:
            raise ValueError(
                'Duplicate rule names within namespace: '
                + ', '.join(str(ref) for ref in duplicates)
            )
        return graph

    def _analyze_rule(self, info, all_rules):
        """Extract explicit, wildcard and gate edges for one rule."""
        tokens = _tokenize_condition(info.condition_text, info.condition_line)
        loop_vars = _collect_loop_variables(tokens)
        rules_by_ns = defaultdict(dict)
        for ref in all_rules:
            rules_by_ns[ref.namespace][ref.name] = ref

        edges = []
        unresolved = []
        index = 0
        while index < len(tokens):
            kind, value, line = tokens[index]
            index += 1
            if kind != 'identifier':
                continue

            if value in _BUILTIN_IDENTIFIERS:
                continue
            if value in loop_vars:
                unresolved.append(UnresolvedSymbol(
                    info.ref, value, line, SymbolKind.LOOP_VAR,
                    'loop variable of a for-expression',
                ))
                continue
            if value in info.imports or self._is_module_member_context(tokens, index - 1):
                continue

            next_kind, next_value, _ = tokens[index] if index < len(tokens) else (None, None, None)
            if next_kind == 'operator' and next_value == '*':
                index += 1
                matched = self._resolve_wildcard(info, value, line, all_rules, edges)
                if not matched:
                    unresolved.append(UnresolvedSymbol(
                        info.ref, f'{value}*', line, SymbolKind.UNRESOLVED,
                        'wildcard prefix matches no rule in namespace',
                    ))
                continue

            target = rules_by_ns[info.ref.namespace].get(value)
            if target is not None:
                edges.append(Edge(
                    info.ref, target, EdgeKind.EXPLICIT, line, value,
                ))
                continue

            if value in self.external_variables:
                unresolved.append(UnresolvedSymbol(
                    info.ref, value, line, SymbolKind.EXTERNAL,
                    'external variable',
                ))
            else:
                unresolved.append(UnresolvedSymbol(
                    info.ref, value, line, SymbolKind.UNRESOLVED,
                    'not a rule, module member, loop variable or external variable',
                ))

        edges.extend(self._gate_edges(info, all_rules))
        return edges, unresolved

    @staticmethod
    def _is_module_member_context(tokens, position):
        """Return whether the identifier at ``position`` belongs to a module."""
        _, value, _ = tokens[position]
        if '.' in value:
            return True
        if position + 1 < len(tokens):
            kind, next_value, _ = tokens[position + 1]
            if kind == 'operator' and next_value == '.':
                return True
        if position > 0:
            kind, prev_value, _ = tokens[position - 1]
            if kind == 'operator' and prev_value == '.':
                return True
        return False

    def _resolve_wildcard(self, info, prefix, line, all_rules, edges):
        """Expand a ``prefix*`` reference into concrete wildcard edges."""
        matched = False
        for ref, candidate in all_rules.items():
            if ref.namespace != info.ref.namespace:
                continue
            if ref == info.ref or not ref.name.startswith(prefix):
                continue
            edges.append(Edge(
                info.ref, ref, EdgeKind.WILDCARD, line, f'{prefix}*',
            ))
            matched = True
        return matched

    @staticmethod
    def _gate_edges(info, all_rules):
        """Build implicit gate edges from same-namespace global rules."""
        edges = []
        for ref, candidate in all_rules.items():
            if ref.namespace != info.ref.namespace:
                continue
            if ref == info.ref or 'global' not in candidate.scopes:
                continue
            if 'global' in info.scopes:
                continue
            edges.append(Edge(
                info.ref, ref, EdgeKind.GATE, info.condition_line,
                f'implicit global gate {ref.name}',
            ))
        return edges
