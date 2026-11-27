"""Review rules that flag findings on either parse path.

The placeholder rule matches a stable sentinel so tests are deterministic. It
operates on whatever representation is active: a normalized entry on the
structured path, or a raw line on the text fallback path. It never reaches
across representations.
"""
from dataclasses import dataclass
from typing import Optional

PLACEHOLDER_SENTINEL = 'REVIEW_PLACEHOLDER'
PLACEHOLDER_RULE_ID = 'placeholder-finding'


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    evidence: str
    restricted_value: Optional[str]


class PlaceholderRule:
    """Flags the deterministic placeholder sentinel."""

    rule_id = PLACEHOLDER_RULE_ID

    def evaluate_text(self, text: str) -> Optional[RuleHit]:
        if PLACEHOLDER_SENTINEL not in text:
            return None

        return RuleHit(
            rule_id=self.rule_id,
            evidence=self._describe(text),
            restricted_value=text.strip(),
        )

    @staticmethod
    def _describe(text: str) -> str:
        # Evidence is a non-sensitive descriptor: where the sentinel sits, not
        # the potentially restricted value around it.
        index = text.find(PLACEHOLDER_SENTINEL)
        return f'marker "{PLACEHOLDER_SENTINEL}" present at offset {index}'
