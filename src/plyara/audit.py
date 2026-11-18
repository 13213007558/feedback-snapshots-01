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
"""Read-only auditing of YARA module usage against a caller supplied policy.

A scanning service may only publish rules that use a limited set of YARA
modules and module members. The presence of an ``import`` statement is not
enough evidence to accept a rule: a rule can import a module without using
it, reference a module it never imported, or reference a member that the
service does not allow. Names that look like module accesses can also appear
inside string definitions, regular expressions and quoted strings, and some
accesses use dynamic indexes that cannot be resolved statically.

This module performs a lexical, static cross-check between the ``import``
declarations and the identifiers actually used in each condition section. It
is deliberately conservative:

* It never rewrites or mutates the input rule text or the parsed rule
  dictionaries.
* It does not assume that importing a module makes every member of that
  module acceptable. Membership is checked against an explicit allowlist.
* Accesses whose target cannot be determined statically are reported instead
  of guessed.
* It does not perform YARA engine level semantic validation. Type checking,
  evaluation of expressions and rule execution behavior are out of scope.
"""
import enum
import re
from dataclasses import dataclass, field

from plyara.core import Plyara


class AuditCategory(enum.Enum):
    """Categories of findings produced by a module access audit."""

    UNUSED_IMPORT = 'unused_import'
    UNDECLARED_MODULE_USE = 'undeclared_module_use'
    UNALLOWED_MODULE = 'unallowed_module'
    UNKNOWN_MEMBER = 'unknown_member'
    AMBIGUOUS_IDENTIFIER = 'ambiguous_identifier'
    INDETERMINATE_ACCESS = 'indeterminate_access'
    PSEUDO_NAME = 'pseudo_name'


# Tokens that refer to named strings and their offsets, counts or lengths.
_STRING_REFERENCE_PREFIXES = ('$', '#', '@', '!')

# A dotted identifier, e.g. pe.number_of_sections.
_DOTTED_IDENTIFIER = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$')

# A module-looking name embedded inside a string definition or regex body.
_EMBEDDED_DOTTED_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_.]*')


@dataclass(frozen=True)
class AuditFinding:
    """A single observation about module usage in a ruleset.

    Attributes:
        rule_name: Name of the rule the finding belongs to. Unused imports
            are reported at ruleset scope with ``None``.
        category: An :class:`AuditCategory` describing the observation.
        reference: The module, member or expression the finding concerns.
        line: One based line number in the input text, or ``None`` when no
            single source location applies.
        column: One based column number for the referenced token, or ``None``.
        term: The exact condition term or import value involved.
        message: Human readable explanation of the observation.
        exempt: True when a caller supplied rule level exception covers the
            finding. Exempt findings are reported but never block.
    """

    rule_name: str | None
    category: AuditCategory
    reference: str
    line: int | None
    column: int | None
    term: str
    message: str
    exempt: bool = False

    def as_dict(self):
        """Return a plain dictionary representation suitable for JSON output."""
        return {
            'rule_name': self.rule_name,
            'category': self.category.value,
            'reference': self.reference,
            'line': self.line,
            'column': self.column,
            'term': self.term,
            'message': self.message,
            'exempt': self.exempt,
        }


@dataclass
class RuleAudit:
    """Audit results for one parsed rule.

    Attributes:
        rule_name: Name of the audited rule.
        start_line: Line where the rule declaration begins.
        stop_line: Line where the rule declaration ends.
        declared_imports: Modules imported by the ruleset that apply to the
            rule.
        used_modules: Module roots referenced from the condition, including
            references that are later rejected or exempted.
        findings: Findings scoped to this rule.
    """

    rule_name: str
    start_line: int
    stop_line: int
    declared_imports: list
    used_modules: list = field(default_factory=list)
    findings: list = field(default_factory=list)

    @property
    def blocking_findings(self):
        """Findings that are not exempt and are not informational pseudo names."""
        return [
            finding for finding in self.findings
            if not finding.exempt and finding.category is not AuditCategory.PSEUDO_NAME
        ]

    def as_dict(self):
        """Return a plain dictionary representation suitable for JSON output."""
        return {
            'rule_name': self.rule_name,
            'start_line': self.start_line,
            'stop_line': self.stop_line,
            'declared_imports': list(self.declared_imports),
            'used_modules': list(self.used_modules),
            'findings': [finding.as_dict() for finding in self.findings],
        }


@dataclass
class AuditReport:
    """The complete result of auditing a ruleset.

    Attributes:
        rule_audits: One :class:`RuleAudit` per parsed rule, in source order.
        findings: All rule scoped and ruleset scoped findings.
    """

    rule_audits: list = field(default_factory=list)
    findings: list = field(default_factory=list)

    @property
    def blocking_findings(self):
        """All findings that a publisher should reject the ruleset for."""
        return [
            finding for finding in self.findings
            if not finding.exempt and finding.category is not AuditCategory.PSEUDO_NAME
        ]

    @property
    def passed(self):
        """True when there are no blocking findings."""
        return not self.blocking_findings

    def as_dict(self):
        """Return a plain dictionary representation suitable for JSON output."""
        return {
            'passed': self.passed,
            'findings': [finding.as_dict() for finding in self.findings],
            'rules': [audit.as_dict() for audit in self.rule_audits],
        }


class ModuleAccessAuditor:
    """Audit condition identifiers against an explicit module member policy.

    Args:
        allowed_modules: Mapping of module name to the set of member names the
            caller allows. A module being present does not allow any member
            that is absent from its set.
        rule_exceptions: Mapping of rule name to a set of exact references
            that the caller explicitly accepts for that rule. References use
            the same dotted form reported in findings, for example
            ``pe.forbidden_member`` or ``pe.sections[i]``.
    """

    def __init__(self, allowed_modules=None, rule_exceptions=None):
        """Initialize the auditor with a caller supplied publishing policy.

        Args:
            allowed_modules: Mapping of module name to the set of member
                names the caller allows.
            rule_exceptions: Mapping of rule name to a set of exact
                references the caller explicitly accepts for that rule.
        """
        self.allowed_modules = {
            module: set(members)
            for module, members in (allowed_modules or {}).items()
        }
        self.rule_exceptions = {
            rule: set(references)
            for rule, references in (rule_exceptions or {}).items()
        }

    def audit(self, input_string):
        """Audit a YARA ruleset without modifying any of its contents.

        Args:
            input_string: Text containing one or more YARA rules.

        Returns:
            AuditReport: Every detected relationship between imports and
                condition identifiers, including accesses that cannot be
                resolved statically.
        """
        snapshot = input_string
        parser = Plyara(import_effects=True)
        rules = parser.parse_string(input_string)

        locations = self._collect_locations(input_string)
        report = AuditReport()
        ruleset_imports = sorted(locations['imports'])

        for rule in rules:
            audit = self._audit_rule(rule, locations)
            report.rule_audits.append(audit)
            report.findings.extend(audit.findings)

        for module in ruleset_imports:
            used_by_any = any(module in rule_audit.used_modules for rule_audit in report.rule_audits)
            if not used_by_any:
                line, column = locations['imports'][module]
                report.findings.append(AuditFinding(
                    rule_name=None,
                    category=AuditCategory.UNUSED_IMPORT,
                    reference=module,
                    line=line,
                    column=column,
                    term=module,
                    message=f'Module "{module}" is imported but never referenced in any condition.',
                ))

        if input_string != snapshot:
            raise RuntimeError('Audit unexpectedly mutated the input text')

        return report

    def _audit_rule(self, rule, locations):
        rule_name = rule['rule_name']
        audit = RuleAudit(
            rule_name=rule_name,
            start_line=rule['start_line'],
            stop_line=rule['stop_line'],
            declared_imports=list(rule.get('imports', [])),
        )

        terms = rule['condition_terms']
        term_locations = self._align_term_locations(rule_name, terms, locations)

        self._collect_pseudo_names(rule, audit, term_locations)

        consumed = set()
        used_modules = set()

        for index, term in enumerate(terms):
            if index in consumed:
                continue

            if self._is_string_reference(term):
                continue

            if term.startswith('"') or term.startswith('/'):
                continue

            if not _DOTTED_IDENTIFIER.match(term):
                continue

            root, member = term.split('.', 1)
            if root in audit.declared_imports:
                used_modules.add(root)

            next_term = terms[index + 1] if index + 1 < len(terms) else None

            if next_term == '[':
                close_index = self._find_matching_bracket(terms, index + 1)
                index_terms = terms[index + 2:close_index]
                for marker in range(index + 1, close_index + 1):
                    consumed.add(marker)

                if self._is_dynamic_index(index_terms):
                    reference = f'{term}[{" ".join(index_terms)}]'
                    self._emit(
                        audit,
                        index,
                        term_locations,
                        AuditCategory.INDETERMINATE_ACCESS,
                        reference,
                        term,
                        f'Dynamic index in "{reference}" cannot be resolved statically; '
                        'the accessed member cannot be verified.',
                    )
                    self._consume_nested_member(terms, close_index, consumed)
                    continue

                nested_index = close_index + 1
                if nested_index < len(terms) and terms[nested_index] == '.':
                    nested_member = terms[nested_index + 1]
                    consumed.add(nested_index)
                    consumed.add(nested_index + 1)
                    reference = f'{term}[{" ".join(index_terms)}].{nested_member}'
                    self._emit(
                        audit,
                        index,
                        term_locations,
                        AuditCategory.INDETERMINATE_ACCESS,
                        reference,
                        term,
                        f'Statically indexed access "{reference}" reaches a nested member that '
                        'the flat member allowlist cannot verify.',
                    )
                    continue

                self._classify_dotted(audit, index, term_locations, root, member, term, used_modules)
                continue

            if '.' in member:
                self._emit(
                    audit,
                    index,
                    term_locations,
                    AuditCategory.INDETERMINATE_ACCESS,
                    term,
                    term,
                    f'Nested access "{term}" cannot be reduced to a single allowlisted member.',
                )
                continue

            self._classify_dotted(audit, index, term_locations, root, member, term, used_modules)

        audit.used_modules = sorted(used_modules)
        return audit

    def _classify_dotted(self, audit, term_index, term_locations, root, member, term, used_modules):
        if root in audit.declared_imports:
            used_modules.add(root)

        if root not in self.allowed_modules:
            if root in audit.declared_imports:
                category = AuditCategory.UNALLOWED_MODULE
                message = f'Module "{root}" is imported but is not part of the publishing policy.'
            else:
                category = AuditCategory.AMBIGUOUS_IDENTIFIER
                message = (
                    f'Identifier "{term}" uses an unknown module root "{root}" that '
                    'cannot be matched to an imported or allowlisted module.'
                )
            self._emit(audit, term_index, term_locations, category, term, term, message)
            return

        if root not in audit.declared_imports:
            self._emit(
                audit,
                term_index,
                term_locations,
                AuditCategory.UNDECLARED_MODULE_USE,
                term,
                term,
                f'Allowlisted module "{root}" is referenced without a matching import declaration.',
            )

        used_modules.add(root)
        allowed_members = self.allowed_modules[root]
        if member not in allowed_members:
            self._emit(
                audit,
                term_index,
                term_locations,
                AuditCategory.UNKNOWN_MEMBER,
                term,
                term,
                f'Member "{member}" is not an allowed member of module "{root}".',
            )

    def _emit(self, audit, term_index, term_locations, category, reference, term, message):
        line, column = term_locations.get(term_index, (None, None))
        exempt = reference in self.rule_exceptions.get(audit.rule_name, set())
        if exempt:
            message = f'{message} Covered by a caller supplied rule exception.'
        audit.findings.append(AuditFinding(
            rule_name=audit.rule_name,
            category=category,
            reference=reference,
            line=line,
            column=column,
            term=term,
            message=message,
            exempt=exempt,
        ))

    def _collect_pseudo_names(self, rule, audit, term_locations):
        for index, term in enumerate(rule['condition_terms']):
            if self._is_string_reference(term):
                line, column = term_locations.get(index, (None, None))
                audit.findings.append(AuditFinding(
                    rule_name=audit.rule_name,
                    category=AuditCategory.PSEUDO_NAME,
                    reference=term,
                    line=line,
                    column=column,
                    term=term,
                    message=(
                        f'String reference "{term}" is a rule string identifier, not a module '
                        'access, and is excluded from member checks.'
                    ),
                ))

        for entry in rule.get('strings', []):
            for match in _EMBEDDED_DOTTED_NAME.finditer(entry['value']):
                name = match.group(0)
                root = name.split('.', 1)[0]
                if root not in self.allowed_modules and root not in audit.declared_imports:
                    continue
                audit.findings.append(AuditFinding(
                    rule_name=audit.rule_name,
                    category=AuditCategory.PSEUDO_NAME,
                    reference=name,
                    line=None,
                    column=None,
                    term=entry['name'],
                    message=(
                        f'Module looking name "{name}" occurs inside {entry["name"]} '
                        f'({entry["type"]} string content), not in the condition.'
                    ),
                ))

    def _align_term_locations(self, rule_name, terms, locations):
        """Map each condition term index to its source location by order.

        The lexer and the parser emit condition tokens in the same order. A
        value keyed map would collapse repeated identifiers, so alignment is
        performed positionally instead.
        """
        ordered_tokens = locations['conditions'].get(rule_name, [])
        aligned = {}
        token_index = 0
        for term_index, term in enumerate(terms):
            while token_index < len(ordered_tokens) and ordered_tokens[token_index][0] != term:
                token_index += 1
            if token_index < len(ordered_tokens):
                aligned[term_index] = ordered_tokens[token_index][1]
                token_index += 1
        return aligned

    def _collect_locations(self, input_string):
        lexer = Plyara().lexer
        lexer.input(input_string)

        imports = {}
        conditions = {}
        current_rule = None
        in_condition = False
        pending_import_module = False
        expect_rule_name = False

        while True:
            token = lexer.token()
            if token is None:
                break

            if token.type == 'IMPORT':
                pending_import_module = True
            elif token.type == 'STRING' and pending_import_module:
                module = token.value.strip('"')
                imports[module] = (token.lineno, self._column(input_string, token.lexpos))
                pending_import_module = False
            elif token.type == 'RULE':
                expect_rule_name = True
                in_condition = False
            elif token.type == 'ID' and expect_rule_name:
                current_rule = token.value
                expect_rule_name = False
            elif token.type == 'SECTIONCONDITION':
                in_condition = True
            elif token.type in ('SECTIONSTRINGS', 'SECTIONMETA'):
                in_condition = False
            elif token.type == 'RBRACE':
                current_rule = None
                in_condition = False
            elif in_condition and current_rule is not None:
                if token.type in ('COMMENT', 'MCOMMENT'):
                    continue
                conditions.setdefault(current_rule, []).append((
                    token.value,
                    (token.lineno, self._column(input_string, token.lexpos)),
                ))

        return {'imports': imports, 'conditions': conditions}

    @staticmethod
    def _column(input_string, lexpos):
        line_start = input_string.rfind('\n', 0, lexpos) + 1
        return lexpos - line_start + 1

    @staticmethod
    def _is_string_reference(term):
        return term.startswith(_STRING_REFERENCE_PREFIXES)

    @staticmethod
    def _is_dynamic_index(index_terms):
        for term in index_terms:
            if term.isdigit() or term.startswith('0x'):
                continue
            return True
        return False

    @staticmethod
    def _find_matching_bracket(terms, open_index):
        depth = 0
        for index in range(open_index, len(terms)):
            if terms[index] == '[':
                depth += 1
            elif terms[index] == ']':
                depth -= 1
                if depth == 0:
                    return index
        return len(terms) - 1

    @staticmethod
    def _consume_nested_member(terms, close_index, consumed):
        nested_index = close_index + 1
        if nested_index < len(terms) and terms[nested_index] == '.':
            consumed.add(nested_index)
            consumed.add(nested_index + 1)


def audit_module_access(input_string, allowed_modules, rule_exceptions=None):
    """Convenience wrapper for auditing one ruleset with a given policy.

    Args:
        input_string: Text containing one or more YARA rules.
        allowed_modules: Mapping of module name to allowed member names.
        rule_exceptions: Optional mapping of rule name to explicitly accepted
            references.

    Returns:
        AuditReport: The read-only audit result.
    """
    return ModuleAccessAuditor(
        allowed_modules=allowed_modules,
        rule_exceptions=rule_exceptions,
    ).audit(input_string)
