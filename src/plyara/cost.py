# Copyright 2026 plyara Maintainers
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
"""Conservative cost analysis for YARA rule conditions.

This module implements a limited static cost analysis on top of plyara's
parsed condition terms. It exists so that a rule scanning service can reject
rules whose condition work grows super-linearly with the scanned file size
before those rules are published, instead of relying on the length of the
rule text as a proxy for execution cost.

The analysis is deliberately limited in scope:

* integer intervals over constants, ``filesize``, string occurrence counts
  (``#a``), loop variables, and external variables whose bounds are supplied
  by trusted configuration,
* ``for`` loops over such intervals, including nested loops with correlated
  bounds,
* string match predicates (``$a``, ``$a at i``, ``$a in (lo..hi)``) and
  boolean combinations of them.

Work is measured in abstract predicate evaluations. The result is a
conservative upper bound expressed as a polynomial in ``filesize`` and is
classified as constant, linear, higher-order, or undeterminable. Boolean
short-circuiting is reported as a conditional observation only: both
operands of ``and``/``or`` are always counted, because a branch that happens
not to execute once is not a branch without cost. Anything outside the
supported subset is reported as undeterminable and is never marked safe to
publish. This analysis does not claim to model the internal overhead of any
particular YARA engine.
"""
import enum
from dataclasses import dataclass
from dataclasses import field

from plyara.core import Plyara

_COMPARISON_OPS = {'==', '!=', '<', '<=', '>', '>='}
_ARITH_OPS = {'+', '-', '*'}


class CostClass(enum.Enum):
    """Classification of a condition work bound as a function of filesize."""

    CONSTANT = 'constant'
    LINEAR = 'linear'
    POLYNOMIAL = 'polynomial'
    UNKNOWN = 'unknown'


class Poly:
    """Polynomial in ``filesize`` with integer coefficients.

    Attributes:
        terms: Mapping of exponent to coefficient.
    """

    def __init__(self, terms=None):
        """Initialize polynomial, dropping zero coefficients."""
        self.terms = {degree: coeff for degree, coeff in (terms or {}).items() if coeff != 0}

    @staticmethod
    def zero():
        """Return the zero polynomial."""
        return Poly({})

    @staticmethod
    def constant(value):
        """Return a constant polynomial."""
        return Poly({0: value})

    @staticmethod
    def filesize():
        """Return the polynomial ``filesize``."""
        return Poly({1: 1})

    @property
    def degree(self):
        """Return the highest exponent with a non-zero coefficient."""
        return max(self.terms) if self.terms else 0

    def add(self, other):
        """Return the sum of this polynomial and another."""
        terms = dict(self.terms)
        for degree, coeff in other.terms.items():
            terms[degree] = terms.get(degree, 0) + coeff
        return Poly(terms)

    def sub(self, other):
        """Return this polynomial minus another."""
        return self.add(other.scale(-1))

    def scale(self, factor):
        """Return this polynomial multiplied by an integer."""
        return Poly({degree: coeff * factor for degree, coeff in self.terms.items()})

    def mul(self, other):
        """Return the product of this polynomial and another."""
        terms = {}
        for left_degree, left_coeff in self.terms.items():
            for right_degree, right_coeff in other.terms.items():
                degree = left_degree + right_degree
                terms[degree] = terms.get(degree, 0) + left_coeff * right_coeff
        return Poly(terms)

    def evaluate(self, filesize):
        """Evaluate the polynomial at a concrete filesize."""
        return sum(coeff * filesize ** degree for degree, coeff in self.terms.items())

    def __eq__(self, other):
        """Compare polynomials by their terms."""
        return isinstance(other, Poly) and self.terms == other.terms

    def __hash__(self):
        """Hash polynomial by its terms."""
        return hash(tuple(sorted(self.terms.items())))

    def __str__(self):
        """Render the polynomial in a human readable form."""
        if not self.terms:
            return '0'
        parts = []
        for degree in sorted(self.terms, reverse=True):
            coeff = self.terms[degree]
            if degree == 0:
                parts.append(str(coeff))
            elif degree == 1:
                parts.append('filesize' if coeff == 1 else '{}*filesize'.format(coeff))
            else:
                term = 'filesize^{}'.format(degree)
                parts.append(term if coeff == 1 else '{}*{}'.format(coeff, term))
        return ' + '.join(parts)


@dataclass
class IntBound:
    """Inclusive integer interval with polynomial endpoints.

    Attributes:
        lo: Lower bound as a polynomial in filesize.
        hi: Upper bound as a polynomial in filesize.
    """

    lo: Poly
    hi: Poly


@dataclass
class CostConfig:
    """Trusted configuration for cost analysis and publish decisions.

    Attributes:
        external_bounds: Bounds for external variables, name to (min, max).
        max_degree: Highest acceptable polynomial degree of the work bound.
        max_work: Highest acceptable work bound at the reference filesize.
        reference_filesize: Filesize at which the work budget is evaluated.
    """

    external_bounds: dict = field(default_factory=dict)
    max_degree: int = 1
    max_work: int = 100000
    reference_filesize: int = 1000000


@dataclass
class CostItem:
    """A single derivation step of the work bound.

    Attributes:
        construct: The condition construct the item describes.
        bound: Work contribution as a polynomial in filesize, or None.
        source: Explanation of how the contribution was derived.
    """

    construct: str
    bound: Poly
    source: str


@dataclass
class CostReport:
    """Result of analyzing one rule condition.

    Attributes:
        rule_name: Name of the analyzed rule.
        supported: Whether the condition stayed within the supported subset.
        bound: Conservative work upper bound, or None if undeterminable.
        cost_class: Classification of the bound.
        items: Derivation steps, one per analyzed construct.
        reasons: Human readable reasons for the publish decision.
        safe_to_publish: Whether the rule may be accepted for publishing.
    """

    rule_name: str
    supported: bool
    bound: Poly
    cost_class: CostClass
    items: list
    reasons: list
    safe_to_publish: bool

    def to_dict(self):
        """Render the report as a JSON serializable dictionary."""
        return {
            'rule_name': self.rule_name,
            'supported': self.supported,
            'cost_class': self.cost_class.value,
            'bound': None if self.bound is None else str(self.bound),
            'safe_to_publish': self.safe_to_publish,
            'reasons': list(self.reasons),
            'items': [
                {
                    'construct': item.construct,
                    'bound': None if item.bound is None else str(item.bound),
                    'source': item.source,
                }
                for item in self.items
            ],
        }


# Condition AST nodes. These are internal to the analysis; the parsed rule
# dictionaries produced by plyara are never modified.

@dataclass
class _IntLit:
    value: int


@dataclass
class _Filesize:
    pass


@dataclass
class _Extern:
    name: str


@dataclass
class _Count:
    name: str


@dataclass
class _Arith:
    op: str
    left: object
    right: object


@dataclass
class _Unsupported:
    reason: str


@dataclass
class _BoolLit:
    value: bool


@dataclass
class _StrRef:
    name: str


@dataclass
class _StrAt:
    name: str
    index: object


@dataclass
class _StrIn:
    name: str
    lo: object
    hi: object


@dataclass
class _Compare:
    op: str
    left: object
    right: object


@dataclass
class _Not:
    operand: object


@dataclass
class _And:
    left: object
    right: object


@dataclass
class _Or:
    left: object
    right: object


@dataclass
class _ForLoop:
    quantifier: object
    var: str
    lo: object
    hi: object
    body: object


class ConditionParseError(Exception):
    """Raised when condition terms fall outside the supported subset."""


def _split_range_tokens(terms):
    """Split fused range tokens such as ``i..filesize`` into parts."""
    tokens = []
    for term in terms:
        term = str(term)
        if '..' in term and term != '..':
            parts = term.split('..')
            for index, part in enumerate(parts):
                if index:
                    tokens.append('..')
                if part:
                    tokens.append(part)
        else:
            tokens.append(term)
    return tokens


class _ConditionParser:
    """Recursive descent parser over plyara condition terms."""

    def __init__(self, terms):
        """Initialize parser with preprocessed condition terms."""
        self.tokens = _split_range_tokens(terms)
        self.pos = 0

    def peek(self):
        """Return the current token or None at the end of input."""
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def next(self):
        """Consume and return the current token."""
        token = self.peek()
        if token is None:
            raise ConditionParseError('unexpected end of condition')
        self.pos += 1
        return token

    def expect(self, token):
        """Consume a specific token or raise a parse error."""
        actual = self.next()
        if actual != token:
            raise ConditionParseError('expected {!r}, got {!r}'.format(token, actual))

    def parse(self):
        """Parse the full condition and require all tokens to be consumed."""
        node = self.parse_or()
        if self.peek() is not None:
            raise ConditionParseError('unexpected trailing token {!r}'.format(self.peek()))
        return node

    def parse_or(self):
        """Parse an ``or`` expression."""
        node = self.parse_and()
        while self.peek() == 'or':
            self.next()
            node = _Or(node, self.parse_and())
        return node

    def parse_and(self):
        """Parse an ``and`` expression."""
        node = self.parse_not()
        while self.peek() == 'and':
            self.next()
            node = _And(node, self.parse_not())
        return node

    def parse_not(self):
        """Parse a ``not`` expression."""
        if self.peek() == 'not':
            self.next()
            return _Not(self.parse_not())
        return self.parse_atom()

    def parse_atom(self):
        """Parse a parenthesized, loop, string, or comparison expression."""
        token = self.peek()
        if token == '(':
            self.next()
            node = self.parse_or()
            self.expect(')')
            return node
        if token == 'for':
            return self.parse_for()
        if token in ('true', 'false'):
            self.next()
            return _BoolLit(token == 'true')
        if isinstance(token, str) and token.startswith('$'):
            return self.parse_string_predicate()
        left = self.parse_arith()
        if self.peek() in _COMPARISON_OPS:
            op = self.next()
            right = self.parse_arith()
            return _Compare(op, left, right)
        if isinstance(left, _Unsupported):
            return left
        raise ConditionParseError('bare arithmetic expression is not a boolean condition')

    def parse_string_predicate(self):
        """Parse a string identifier predicate such as ``$a at i``."""
        name = self.next()
        if name.endswith('*'):
            raise ConditionParseError('wildcard string sets are not supported: {!r}'.format(name))
        token = self.peek()
        if token == 'at':
            self.next()
            return _StrAt(name, self.parse_arith())
        if token == 'in':
            self.next()
            self.expect('(')
            lo = self.parse_arith()
            self.expect('..')
            hi = self.parse_arith()
            self.expect(')')
            return _StrIn(name, lo, hi)
        return _StrRef(name)

    def parse_for(self):
        """Parse a ``for`` loop over an integer range."""
        self.expect('for')
        token = self.next()
        if token in ('any', 'all'):
            quantifier = token
        elif token.isdigit():
            quantifier = int(token)
        else:
            raise ConditionParseError('unsupported for quantifier {!r}'.format(token))
        if self.peek() == 'of':
            raise ConditionParseError('for ... of string set loops are not supported')
        var = self.next()
        self.expect('in')
        self.expect('(')
        lo = self.parse_arith()
        self.expect('..')
        hi = self.parse_arith()
        self.expect(')')
        self.expect(':')
        self.expect('(')
        body = self.parse_or()
        self.expect(')')
        return _ForLoop(quantifier, var, lo, hi, body)

    def parse_arith(self):
        """Parse an additive arithmetic expression."""
        node = self.parse_term()
        while self.peek() in ('+', '-'):
            op = self.next()
            node = _Arith(op, node, self.parse_term())
        return node

    def parse_term(self):
        """Parse a multiplicative arithmetic expression."""
        node = self.parse_factor()
        while self.peek() == '*':
            self.next()
            node = _Arith('*', node, self.parse_factor())
        return node

    def parse_factor(self):
        """Parse an arithmetic operand."""
        token = self.next()
        if token == '(':
            node = self.parse_arith()
            self.expect(')')
            return node
        if token == 'filesize':
            return _Filesize()
        if isinstance(token, str) and token.startswith('#'):
            return _Count('$' + token[1:])
        if isinstance(token, str) and token.startswith(('!', '@')):
            return _Unsupported('string length/offset references are not supported: {!r}'.format(token))
        if isinstance(token, str) and token.startswith('0x'):
            return _IntLit(int(token, 16))
        if isinstance(token, str) and token.isdigit():
            return _IntLit(int(token))
        if isinstance(token, str) and token.isidentifier():
            if self.peek() == '(':
                return _Unsupported('function calls are not supported: {!r}'.format(token))
            return _Extern(token)
        return _Unsupported('unsupported term {!r}'.format(token))


def parse_condition(condition_terms):
    """Parse plyara condition terms into a condition AST.

    Args:
        condition_terms: The ``condition_terms`` list of a parsed rule.

    Returns:
        The root node of the condition AST.

    Raises:
        ConditionParseError: If the terms use unsupported constructs.
    """
    return _ConditionParser(condition_terms).parse()


class _Analyzer:
    """Derive conservative work bounds from a condition AST."""

    def __init__(self, config):
        """Initialize the analyzer with a trusted configuration."""
        self.config = config
        self.items = []
        self.unsupported = []
        self.scopes = []

    def lookup_var(self, name):
        """Return the integer bound of a loop variable, if in scope."""
        for scope in reversed(self.scopes):
            if name in scope:
                return scope[name]
        return None

    def eval_int(self, node):
        """Bound an integer expression, or return None if not boundable."""
        if isinstance(node, _IntLit):
            return IntBound(Poly.constant(node.value), Poly.constant(node.value))
        if isinstance(node, _Filesize):
            return IntBound(Poly.zero(), Poly.filesize())
        if isinstance(node, _Count):
            return IntBound(Poly.zero(), Poly.filesize())
        if isinstance(node, _Extern):
            bound = self.lookup_var(node.name)
            if bound is not None:
                return bound
            if node.name in self.config.external_bounds:
                lo, hi = self.config.external_bounds[node.name]
                return IntBound(Poly.constant(lo), Poly.constant(hi))
            self.unsupported.append('external variable {!r} has no configured bound'.format(node.name))
            return None
        if isinstance(node, _Arith):
            left = self.eval_int(node.left)
            right = self.eval_int(node.right)
            if left is None or right is None:
                return None
            if node.op == '+':
                return IntBound(left.lo.add(right.lo), left.hi.add(right.hi))
            if node.op == '-':
                return IntBound(left.lo.sub(right.hi), left.hi.sub(right.lo))
            if node.op == '*':
                return IntBound(left.lo.mul(right.lo), left.hi.mul(right.hi))
            self.unsupported.append('arithmetic operator {!r} is not supported'.format(node.op))
            return None
        if isinstance(node, _Unsupported):
            self.unsupported.append(node.reason)
            return None
        self.unsupported.append('unsupported integer expression: {!r}'.format(node))
        return None

    def analyze(self, node):
        """Return the work bound of a boolean expression, or None."""
        if isinstance(node, _BoolLit):
            bound = Poly.zero()
            self.items.append(CostItem(
                construct='boolean literal',
                bound=bound,
                source='constant {!r} requires no predicate evaluations'.format(node.value),
            ))
            return bound
        if isinstance(node, _StrRef):
            bound = Poly.constant(1)
            self.items.append(CostItem(
                construct='string match {}'.format(node.name),
                bound=bound,
                source='single string match check {}'.format(node.name),
            ))
            return bound
        if isinstance(node, (_StrAt, _StrIn)):
            return self.analyze_string_position(node)
        if isinstance(node, _Compare):
            return self.analyze_compare(node)
        if isinstance(node, _Not):
            return self.analyze(node.operand)
        if isinstance(node, (_And, _Or)):
            return self.analyze_boolean(node)
        if isinstance(node, _ForLoop):
            return self.analyze_for(node)
        if isinstance(node, _Unsupported):
            self.unsupported.append(node.reason)
            return None
        self.unsupported.append('unsupported condition expression: {!r}'.format(node))
        return None

    def analyze_string_position(self, node):
        """Bound a positional string predicate such as ``$a at i``."""
        if isinstance(node, _StrAt):
            index = self.eval_int(node.index)
            if index is None:
                return None
            detail = 'index within [{}, {}]'.format(index.lo, index.hi)
            construct = 'string match {} at offset'.format(node.name)
        else:
            lo = self.eval_int(node.lo)
            hi = self.eval_int(node.hi)
            if lo is None or hi is None:
                return None
            detail = 'range [{}, {}]'.format(lo.lo, hi.hi)
            construct = 'string match {} in range'.format(node.name)
        bound = Poly.constant(1)
        self.items.append(CostItem(
            construct=construct,
            bound=bound,
            source='single positional string match check; {}'.format(detail),
        ))
        return bound

    def analyze_compare(self, node):
        """Bound a comparison between two integer expressions."""
        left = self.eval_int(node.left)
        right = self.eval_int(node.right)
        if left is None or right is None:
            return None
        bound = Poly.constant(1)
        self.items.append(CostItem(
            construct='comparison {}'.format(node.op),
            bound=bound,
            source='single comparison of integers within [{}, {}] and [{}, {}]'.format(
                left.lo, left.hi, right.lo, right.hi),
        ))
        return bound

    def analyze_boolean(self, node):
        """Bound an ``and``/``or`` expression by summing both operands."""
        op = 'and' if isinstance(node, _And) else 'or'
        left = self.analyze(node.left)
        right = self.analyze(node.right)
        if left is None or right is None:
            return None
        bound = left.add(right)
        self.items.append(CostItem(
            construct='boolean {}'.format(op),
            bound=bound,
            source=(
                'both operands of {!r} are counted ({} + {}); short-circuit evaluation may reduce '
                'actual work, but an unexecuted branch is not treated as free'
            ).format(op, left, right),
        ))
        return bound

    def analyze_for(self, node):
        """Bound a ``for`` loop by multiplying iterations by body work."""
        lo = self.eval_int(node.lo)
        hi = self.eval_int(node.hi)
        if lo is None or hi is None:
            return None
        iterations = hi.hi.sub(lo.lo).add(Poly.constant(1))
        var_bound = IntBound(lo.lo, hi.hi)
        self.scopes.append({node.var: var_bound})
        try:
            body = self.analyze(node.body)
        finally:
            self.scopes.pop()
        if body is None:
            return None
        bound = iterations.mul(body)
        self.items.append(CostItem(
            construct='for {} {} in range'.format(node.quantifier, node.var),
            bound=bound,
            source=(
                'iteration count <= {} (from range upper bound {} minus lower bound {} plus 1); '
                'body work {} per iteration; quantifier {!r} may exit early but the full range '
                'is counted'
            ).format(iterations, hi.hi, lo.lo, body, node.quantifier),
        ))
        return bound


def _classify(bound):
    """Classify a work bound polynomial."""
    if bound.degree == 0:
        return CostClass.CONSTANT
    if bound.degree == 1:
        return CostClass.LINEAR
    return CostClass.POLYNOMIAL


def analyze_condition(condition_terms, config=None, rule_name=''):
    """Analyze plyara condition terms and produce a cost report.

    Args:
        condition_terms: The ``condition_terms`` list of a parsed rule.
        config: Trusted analysis configuration; defaults are used if None.
        rule_name: Rule name recorded in the report.

    Returns:
        A CostReport with the work bound and the publish decision.
    """
    config = config or CostConfig()
    analyzer = _Analyzer(config)
    reasons = []
    try:
        node = parse_condition(condition_terms)
    except ConditionParseError as exc:
        analyzer.unsupported.append(str(exc))
        node = None
    bound = analyzer.analyze(node) if node is not None else None
    if bound is None:
        reasons.extend(sorted(set(analyzer.unsupported)) or ['unsupported condition'])
        reasons.append('undeterminable cost is never safe to publish')
        return CostReport(rule_name, False, None, CostClass.UNKNOWN, analyzer.items, reasons, False)
    cost_class = _classify(bound)
    if bound.degree > config.max_degree:
        reasons.append('bound degree {} exceeds configured maximum {}'.format(bound.degree, config.max_degree))
    work_at_reference = bound.evaluate(config.reference_filesize)
    if work_at_reference > config.max_work:
        reasons.append(
            'work bound {} at filesize {} exceeds budget {}'.format(
                work_at_reference, config.reference_filesize, config.max_work)
        )
    safe = not reasons
    if safe:
        reasons.append('bound {} is within the configured budget'.format(bound))
    return CostReport(rule_name, True, bound, cost_class, analyzer.items, reasons, safe)


def analyze_rule(entry, config=None):
    """Analyze one parsed rule dictionary without modifying it.

    Args:
        entry: A rule dictionary produced by plyara.
        config: Trusted analysis configuration; defaults are used if None.

    Returns:
        A CostReport for the rule condition.
    """
    return analyze_condition(entry.get('condition_terms', []), config, entry.get('rule_name', ''))


def analyze_source(source, config=None):
    """Parse YARA source text and analyze every rule it contains.

    The source text is only read; it is never modified.

    Args:
        source: String containing one or more YARA rules.
        config: Trusted analysis configuration; defaults are used if None.

    Returns:
        A list of CostReport objects, one per rule.
    """
    parser = Plyara()
    return [analyze_rule(entry, config) for entry in parser.parse_string(source)]


@dataclass
class SampleEnv:
    """A concrete small input for the independent counting interpreter.

    Attributes:
        filesize: Simulated file size.
        matches: Map of string identifier (``$a``) to match offsets.
        externals: Map of external variable name to value.
    """

    filesize: int
    matches: dict = field(default_factory=dict)
    externals: dict = field(default_factory=dict)


@dataclass
class SampleCheck:
    """Comparison of measured work against the derived bound for one sample.

    Attributes:
        filesize: File size of the sample.
        measured: Work units counted by the interpreter.
        bound: Bound evaluated at the sample filesize, or None.
        within_bound: Whether the measured work is within the bound.
    """

    filesize: int
    measured: int
    bound: int
    within_bound: bool


class _Interpreter:
    """Evaluate a condition AST on concrete inputs while counting work."""

    def __init__(self, env):
        """Initialize the interpreter with a sample environment."""
        self.env = env
        self.count = 0
        self.scopes = []

    def lookup_var(self, name):
        """Return the concrete value of a loop variable."""
        for scope in reversed(self.scopes):
            if name in scope:
                return scope[name]
        raise ConditionParseError('unbound variable {!r}'.format(name))

    def eval_int(self, node):
        """Evaluate an integer expression on the sample input."""
        if isinstance(node, _IntLit):
            return node.value
        if isinstance(node, _Filesize):
            return self.env.filesize
        if isinstance(node, _Count):
            return len(self.env.matches.get(node.name, []))
        if isinstance(node, _Extern):
            if node.name in self.env.externals:
                return self.env.externals[node.name]
            return self.lookup_var(node.name)
        if isinstance(node, _Arith):
            left = self.eval_int(node.left)
            right = self.eval_int(node.right)
            if node.op == '+':
                return left + right
            if node.op == '-':
                return left - right
            if node.op == '*':
                return left * right
        raise ConditionParseError('cannot evaluate integer expression {!r}'.format(node))

    def eval_bool(self, node):
        """Evaluate a boolean expression, counting predicate evaluations."""
        if isinstance(node, _BoolLit):
            return node.value
        if isinstance(node, _StrRef):
            self.count += 1
            return bool(self.env.matches.get(node.name))
        if isinstance(node, _StrAt):
            self.count += 1
            return self.eval_int(node.index) in self.env.matches.get(node.name, [])
        if isinstance(node, _StrIn):
            self.count += 1
            lo = self.eval_int(node.lo)
            hi = self.eval_int(node.hi)
            return any(lo <= offset <= hi for offset in self.env.matches.get(node.name, []))
        if isinstance(node, _Compare):
            self.count += 1
            left = self.eval_int(node.left)
            right = self.eval_int(node.right)
            if node.op == '==':
                return left == right
            if node.op == '!=':
                return left != right
            if node.op == '<':
                return left < right
            if node.op == '<=':
                return left <= right
            if node.op == '>':
                return left > right
            return left >= right
        if isinstance(node, _Not):
            return not self.eval_bool(node.operand)
        if isinstance(node, _And):
            return self.eval_bool(node.left) and self.eval_bool(node.right)
        if isinstance(node, _Or):
            return self.eval_bool(node.left) or self.eval_bool(node.right)
        if isinstance(node, _ForLoop):
            return self.eval_for(node)
        raise ConditionParseError('cannot evaluate condition {!r}'.format(node))

    def eval_for(self, node):
        """Evaluate a ``for`` loop with quantifier semantics and early exit."""
        lo = self.eval_int(node.lo)
        hi = self.eval_int(node.hi)
        values = range(lo, hi + 1)
        total = hi - lo + 1
        if node.quantifier == 'any':
            threshold = 1
        elif node.quantifier == 'all':
            threshold = total
        else:
            threshold = node.quantifier
        hits = 0
        for value in values:
            self.scopes.append({node.var: value})
            try:
                if self.eval_bool(node.body):
                    hits += 1
            finally:
                self.scopes.pop()
            if hits >= threshold:
                return True
            if total - (value - lo + 1) + hits < threshold:
                return False
        return hits >= threshold


def interpret_condition(node, env):
    """Evaluate a condition AST on a sample input and count the work.

    Args:
        node: Root of the condition AST.
        env: A SampleEnv describing the concrete input.

    Returns:
        A tuple of the boolean result and the counted work units.
    """
    interpreter = _Interpreter(env)
    result = interpreter.eval_bool(node)
    return result, interpreter.count


def verify_with_samples(condition_terms, samples, config=None):
    """Cross-check the derived bound against an independent interpreter.

    The condition is evaluated on each small sample input by a counting
    interpreter, and the measured work is compared against the statically
    derived bound evaluated at the sample filesize.

    Args:
        condition_terms: The ``condition_terms`` list of a parsed rule.
        samples: Iterable of SampleEnv inputs.
        config: Trusted analysis configuration; defaults are used if None.

    Returns:
        A list of SampleCheck results, one per sample.
    """
    node = parse_condition(condition_terms)
    report = analyze_condition(condition_terms, config)
    checks = []
    for env in samples:
        _, measured = interpret_condition(node, env)
        bound = report.bound.evaluate(env.filesize) if report.bound is not None else None
        checks.append(SampleCheck(
            filesize=env.filesize,
            measured=measured,
            bound=bound,
            within_bound=bound is not None and measured <= bound,
        ))
    return checks
