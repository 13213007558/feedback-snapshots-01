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
"""Command line interface for effective YARA dependency analysis."""
import argparse
import json
import pathlib
import sys

from plyara.dependencies import DependencyAnalyzer


class _GraphEncoder:
    """Serialize graph objects while keeping the file origin of each rule."""

    def __init__(self, graph):
        """Bind the encoder to a finished dependency graph."""
        self.graph = graph

    def edge(self, edge):
        """Serialize an edge with its originating file."""
        return {
            'source': str(edge.source),
            'target': str(edge.target),
            'kind': edge.kind.value,
            'line': edge.line,
            'snippet': edge.snippet,
            'source_file': str(self.graph.rules[edge.source].path),
        }

    def symbol(self, symbol):
        """Serialize an unresolved or external symbol."""
        return {
            'rule': str(symbol.rule),
            'symbol': symbol.symbol,
            'line': symbol.line,
            'kind': symbol.kind.value,
            'detail': symbol.detail,
            'file': str(self.graph.rules[symbol.rule].path),
        }

    def rule(self, ref):
        """Serialize a rule node and its metadata."""
        info = self.graph.rules[ref]
        return {
            'rule': str(ref),
            'name': ref.name,
            'namespace': ref.namespace,
            'file': str(info.path),
            'scopes': sorted(info.scopes),
            'start_line': info.start_line,
            'stop_line': info.stop_line,
        }


def _build_parser():
    """Construct the command line argument parser."""
    parser = argparse.ArgumentParser(
        description='Analyze effective YARA rule dependencies and global-gate impact.',
    )
    parser.add_argument(
        '--external', action='append', default=[], metavar='NAME',
        help='Declare an external variable name. Repeatable.',
    )
    parser.add_argument(
        '--externals-file', metavar='FILE',
        help='JSON file mapping external variable names to values.',
    )
    parser.add_argument('--json', action='store_true', help='Emit machine-readable JSON.')
    subcommands = parser.add_subparsers(dest='command', required=True)

    graph_cmd = subcommands.add_parser('graph', help='List every dependency edge with its source.')
    graph_cmd.add_argument('files', nargs='+', metavar='FILE', help='YARA rule files to analyze.')

    impact = subcommands.add_parser(
        'impact', help='List all rules effectively affected by changing a rule.',
    )
    impact.add_argument('rule', help='Rule name or namespace::name being changed.')
    impact.add_argument('files', nargs='+', metavar='FILE', help='YARA rule files to analyze.')

    cycles_cmd = subcommands.add_parser('cycles', help='List explicit-reference cycles with paths.')
    cycles_cmd.add_argument('files', nargs='+', metavar='FILE', help='YARA rule files to analyze.')

    unresolved_cmd = subcommands.add_parser(
        'unresolved', help='List unresolved identifiers and external variable uses.',
    )
    unresolved_cmd.add_argument('files', nargs='+', metavar='FILE', help='YARA rule files to analyze.')
    return parser


def _load_externals(args):
    """Collect external variable names from flags and optional JSON."""
    names = set(args.external)
    if args.externals_file:
        data = json.loads(pathlib.Path(args.externals_file).read_text(encoding='utf-8'))
        if not isinstance(data, dict):
            parser_error('--externals-file must contain a JSON object')
        names.update(data.keys())
    return names


def parser_error(message):
    """Terminate the CLI with a readable error message."""
    raise SystemExit(f'error: {message}')


def _resolve_rule(graph, text):
    """Resolve a plain or namespace-qualified rule name to a node."""
    if '::' in text:
        namespace, name = text.split('::', 1)
        from plyara.dependencies import RuleRef
        ref = RuleRef(namespace, name)
    else:
        matches = [ref for ref in graph.rules if ref.name == text]
        if not matches:
            parser_error(f'unknown rule: {text}')
        if len(matches) > 1:
            options = ', '.join(str(ref) for ref in matches)
            parser_error(f'ambiguous rule name {text}; choose one of: {options}')
        ref = matches[0]
    if ref not in graph.rules:
        parser_error(f'unknown rule: {text}')
    return ref


def _print_graph(graph, encoder, as_json):
    """Render the full edge list."""
    if as_json:
        payload = {
            'rules': [encoder.rule(ref) for ref in sorted(graph.rules, key=str)],
            'edges': [encoder.edge(edge) for edge in graph.edges],
            'unresolved': [encoder.symbol(item) for item in graph.unresolved],
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    for edge in graph.edges:
        info = graph.rules[edge.source]
        print(
            f'{edge.kind.value:8s} {edge.source} -> {edge.target}  '
            f'[{info.path}:{edge.line}] {edge.snippet}',
        )


def _print_impact(graph, encoder, ref, as_json):
    """Render the impacted rule set with evidence paths."""
    impacted = graph.impact(ref)
    explanations = graph.explain_impact(ref)
    if as_json:
        payload = {
            'changed_rule': encoder.rule(ref),
            'is_global_gate': 'global' in graph.rules[ref].scopes,
            'impacted_rules': [encoder.rule(item) for item in sorted(impacted, key=str)],
            'evidence': {
                str(rule): [encoder.edge(edge) for edge in path]
                for rule, path in sorted(explanations.items(), key=lambda item: str(item[0]))
            },
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    scope = sorted(graph.rules[ref].scopes) or ['(plain)']
    print(f'Changed rule: {ref}  scopes={scope}')
    print(f'Effectively impacted rules ({len(impacted)}):')
    for item in sorted(impacted, key=str):
        path = explanations.get(item, [])
        chain = ' | '.join(
            f'{edge.kind.value}:{edge.source.name}->{edge.target.name}'
            f'@{graph.rules[edge.source].path}:{edge.line}'
            for edge in path
        )
        print(f'  - {item}  [{chain}]')


def _print_cycles(graph, as_json):
    """Render explicit-reference cycles."""
    cycles = graph.cycles()
    if as_json:
        print(json.dumps([[str(ref) for ref in cycle] for cycle in cycles], indent=2, ensure_ascii=False))
        return
    if not cycles:
        print('No explicit-reference cycles.')
        return
    for cycle in cycles:
        print(' -> '.join(str(ref) for ref in cycle))


def _print_unresolved(graph, encoder, as_json):
    """Render unresolved identifiers and external variables."""
    if as_json:
        print(json.dumps(
            [encoder.symbol(item) for item in graph.unresolved], indent=2, ensure_ascii=False,
        ))
        return
    if not graph.unresolved:
        print('No unresolved identifiers.')
        return
    for item in graph.unresolved:
        info = graph.rules[item.rule]
        marker = item.kind.value
        print(f'{marker:10s} {item.rule}:{info.path}:{item.line}  {item.symbol}  ({item.detail})')


def main(argv=None):
    """Run the dependency analysis command line interface."""
    args = _build_parser().parse_args(argv)
    analyzer = DependencyAnalyzer(external_variables=_load_externals(args))
    try:
        graph = analyzer.analyze_paths(args.files)
    except Exception as exc:  # noqa: BLE001 - surface parse failures cleanly
        sys.exit(f'error: {exc}')

    encoder = _GraphEncoder(graph)
    if args.command == 'graph':
        _print_graph(graph, encoder, args.json)
    elif args.command == 'impact':
        ref = _resolve_rule(graph, args.rule)
        _print_impact(graph, encoder, ref, args.json)
    elif args.command == 'cycles':
        _print_cycles(graph, args.json)
    elif args.command == 'unresolved':
        _print_unresolved(graph, encoder, args.json)


if __name__ == '__main__':
    main()
