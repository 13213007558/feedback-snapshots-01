"""
Shared work budget for a single Bleach pass.

A :class:`Budget` is a *single-run* meter shared by every stage of
processing one piece of content:

* :data:`STAGE_PARSE` -- HTML tokenizing / tree construction
* :data:`STAGE_CLEAN` -- the sanitizer filter stream
* :data:`STAGE_LINKIFY` -- optional link/email transformation

The budget is opt-in: passing ``budget=None`` (the default) keeps the
historical, unlimited behaviour.  Pass an integer (the total number of
work units allowed for one run) or a configured :class:`Budget`
instance.  Entries such as :meth:`bleach.sanitizer.Cleaner.clean` call
:meth:`Budget.reset` before every run, so one budget object/config can be
reused safely after a failed call.

Work is metered along three dimensions, each with its own rule:

* **nodes** -- every token/node event, plus one unit per attribute
* **text** -- one unit per character of character/comment data
* **transforms** -- every extra transformation (URL/email linkification
  match, existing-link callback pass, ...), weighted separately
"""

from bleach._vendor.html5lib.constants import tokenTypes


#: Parsing / tree-construction stage.
STAGE_PARSE = "parse"

#: Sanitizer filtering stage ("clean").
STAGE_CLEAN = "clean"

#: Optional link processing stage ("linkify").
STAGE_LINKIFY = "linkify"

#: Stages a single unit of work flows through.
STAGES = (STAGE_PARSE, STAGE_CLEAN, STAGE_LINKIFY)

_CHARACTER_TOKEN_TYPES = {
    tokenTypes["Characters"],
    tokenTypes["SpaceCharacters"],
    "Characters",
    "SpaceCharacters",
}
_TAG_TOKEN_TYPES = {
    tokenTypes["StartTag"],
    tokenTypes["EndTag"],
    tokenTypes["EmptyTag"],
    "StartTag",
    "EndTag",
    "EmptyTag",
}
_COMMENT_TOKEN_TYPES = {tokenTypes["Comment"], "Comment"}
_ENTITY_TOKEN_TYPES = {"Entity"}


#: A generous default for callers that want a safety ceiling without
#: tuning anything.  Ordinary long comments are far below this.
DEFAULT_LIMIT = 500_000


class BudgetExceeded(Exception):
    """Raised when a shared :class:`Budget` is exhausted during a run.

    :ivar str stage: processing ring that detected the overrun -- one of
        :data:`STAGE_PARSE`, :data:`STAGE_CLEAN`, :data:`STAGE_LINKIFY`
    :ivar int limit: configured unit ceiling
    :ivar int used: cumulative units consumed when the limit was crossed
        (including the charge that crossed it)
    :ivar dict stage_spent: units consumed per stage at failure time
    :ivar dict counts: raw work counts (nodes/characters/attributes/
        transforms) at failure time
    :ivar str kind: optional kind of charge that triggered the failure
    """

    def __init__(self, stage, limit, used, *, budget=None, kind=None):
        self.stage = stage
        self.limit = limit
        self.used = used
        # Alias used by callers thinking in terms of "spent" units.
        self.spent = used
        self.kind = kind
        if budget is not None:
            self.stage_spent = dict(budget.stage_spent)
            self.counts = dict(budget.counts)
        else:
            self.stage_spent = {}
            self.counts = {}
        detail = f" ({kind})" if kind else ""
        super().__init__(
            f"Bleach work budget of {limit} units exceeded in stage "
            f"{stage!r}{detail}: {used} units consumed"
        )


# Common alternative names for the same failure type.  These are aliases
# of the *same* class so ``except BudgetExceededError`` catches a raise
# of ``BudgetExceeded`` and vice versa.
BudgetExceededError = BudgetExceeded
WorkBudgetExceeded = BudgetExceeded


def token_work(token):
    """Return the ``(nodes, characters, attributes)`` represented by a token.

    This accepts both raw tokenizer tokens (whose ``type`` is an integer
    constant) and tree-walker/filter tokens (whose ``type`` is a string).
    The function is defensive: malformed/unknown token shapes fall back to
    counting one node rather than raising.
    """
    if not isinstance(token, dict):
        return 1, 0, 0

    token_type = token.get("type")
    data = token.get("data")

    if token_type in _CHARACTER_TOKEN_TYPES:
        length = len(data) if isinstance(data, str) else 0
        return 0, length, 0

    if token_type in _TAG_TOKEN_TYPES:
        attributes = len(data) if isinstance(data, dict) else 0
        return 1, 0, attributes

    if token_type in _COMMENT_TOKEN_TYPES:
        length = len(data) if isinstance(data, str) else 0
        return 1, length, 0

    if token_type in _ENTITY_TOKEN_TYPES:
        name = token.get("name", "")
        return 1, len(name) if isinstance(name, str) else 0, 0

    # Doctype, parse errors and any future token types are still events
    # the pipeline has to handle.
    return 1, 0, 0


class Budget:
    """Meter shared by parsing, cleaning and optional link processing.

    :arg int limit: maximum cumulative work units for a single run.  When
        a charge would push :attr:`spent` strictly above ``limit``,
        :class:`BudgetExceeded` is raised naming the current stage.  Pass
        ``None`` to meter without enforcing (useful for measuring a
        baseline before choosing a quota).

    :arg int node_cost: units per node/token event
    :arg int attribute_cost: units per tag attribute
    :arg int character_cost: units per character of text/comment data
    :arg int transform_cost: units per extra transformation (for example
        one URL/email match converted into a link)
    """

    def __init__(
        self,
        limit=DEFAULT_LIMIT,
        *,
        node_cost=1,
        attribute_cost=1,
        character_cost=1,
        transform_cost=10,
    ):
        if limit is not None:
            if isinstance(limit, bool) or not isinstance(limit, int):
                raise TypeError("budget limit must be an integer or None")
            if limit < 0:
                raise ValueError("budget limit must be non-negative")
        for name, value in (
            ("node_cost", node_cost),
            ("attribute_cost", attribute_cost),
            ("character_cost", character_cost),
            ("transform_cost", transform_cost),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")

        self.limit = limit
        self.node_cost = node_cost
        self.attribute_cost = attribute_cost
        self.character_cost = character_cost
        self.transform_cost = transform_cost
        self.reset()

    def reset(self):
        """Zero all per-run counters.  Called at the start of every entry."""
        self.spent = 0
        self.stage_spent = {stage: 0 for stage in STAGES}
        self.counts = {
            "nodes": 0,
            "characters": 0,
            "attributes": 0,
            "transforms": 0,
        }
        self.exceeded_stage = None
        return self

    # Descriptive alias.
    @property
    def used(self):
        return self.spent

    @property
    def remaining(self):
        if self.limit is None:
            return None
        return max(0, self.limit - self.spent)

    def as_report(self):
        """Return a plain snapshot dict of limit, spend and counts."""
        return {
            "limit": self.limit,
            "spent": self.spent,
            "used": self.spent,
            "remaining": self.remaining,
            "exceeded": self.exceeded_stage is not None,
            "exceeded_stage": self.exceeded_stage,
            "stage_spent": dict(self.stage_spent),
            "counts": dict(self.counts),
        }

    def charge(
        self,
        amount,
        stage,
        *,
        nodes=0,
        characters=0,
        attributes=0,
        transforms=0,
        kind=None,
    ):
        """Add ``amount`` units to the shared pool for ``stage``.

        Updates raw counters and raises :class:`BudgetExceeded` if the
        cumulative spend crosses :attr:`limit`.
        """
        if amount is None or amount <= 0:
            return self.spent

        amount = int(amount)
        self.spent += amount
        self.stage_spent[stage] = self.stage_spent.get(stage, 0) + amount
        self.counts["nodes"] += int(nodes)
        self.counts["characters"] += int(characters)
        self.counts["attributes"] += int(attributes)
        self.counts["transforms"] += int(transforms)

        if self.limit is not None and self.spent > self.limit:
            self.exceeded_stage = stage
            raise BudgetExceeded(stage, self.limit, self.spent, budget=self, kind=kind)

        return self.spent

    def charge_token(self, token, stage):
        """Charge for one html5lib token at ``stage``."""
        nodes, characters, attributes = token_work(token)
        amount = (
            nodes * self.node_cost
            + characters * self.character_cost
            + attributes * self.attribute_cost
        )
        return self.charge(
            amount,
            stage,
            nodes=nodes,
            characters=characters,
            attributes=attributes,
        )

    def charge_text(self, text, stage, *, kind=None):
        """Charge for a raw string of text at ``stage``."""
        length = len(text) if isinstance(text, str) else 0
        return self.charge(
            length * self.character_cost,
            stage,
            characters=length,
            kind=kind,
        )

    def charge_transform(self, stage=STAGE_LINKIFY, count=1, *, kind=None):
        """Charge for ``count`` extra transformations at ``stage``."""
        count = max(0, int(count))
        return self.charge(
            count * self.transform_cost,
            stage,
            transforms=count,
            kind=kind,
        )


# Descriptive aliases for callers that prefer these names.
WorkBudget = Budget
ResourceBudget = Budget


def coerce_budget(budget):
    """Normalize a ``budget`` constructor argument to a :class:`Budget`.

    Accepts:

    * ``None`` -- budgeting disabled
    * an int -- a :class:`Budget` with that total limit
    * a :class:`Budget` -- returned as-is
    * a dict -- expanded as ``Budget(**budget)``
    """
    if budget is None:
        return None
    if isinstance(budget, Budget):
        return budget
    if isinstance(budget, dict):
        return Budget(**budget)
    if isinstance(budget, (int, float)) and not isinstance(budget, bool):
        return Budget(limit=int(budget))
    raise TypeError(
        "budget must be a Budget instance, an integer limit, a dict, or None; "
        f"got {budget.__class__.__name__!r}"
    )
