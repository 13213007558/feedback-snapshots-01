"""Human-readable rendering of the source-aware public configuration view."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .common import write_output
from .provenance import build_public_structured_result

if TYPE_CHECKING:
    from tox.session.state import State
    from tox.util.json_types import JsonValue


def show_config_public_text(state: State) -> int:
    """Render the public configuration view as plain explanatory text."""
    result, has_exception = build_public_structured_result(state)
    lines = [
        "# tox public configuration view",
        "# Values derived from restricted sources are masked; source names and resolution status remain visible.",
    ]
    env = result.get("env", {})
    if isinstance(env, dict):
        for name, section in env.items():
            lines.append("")
            lines.append(f"[testenv:{name}]")
            _render_section(lines, section)
    tox = result.get("tox")
    if isinstance(tox, dict):
        lines.append("")
        lines.append("[tox]")
        _render_section(lines, tox)

    output_file = state.conf.options.output_file
    write_output("\n".join(lines), output_file, False, lambda text: text)
    return -1 if has_exception else 0


def _render_section(lines: list[str], section: JsonValue) -> None:
    if not isinstance(section, dict):
        return
    for key, entry in section.items():
        if key in {"values", "provenance", "source_disclosure"}:
            continue
        if key == "unused":
            lines.append(f"# !!! unused: {', '.join(entry) if isinstance(entry, list) else entry}")
            continue
        if not isinstance(entry, dict) or "value" not in entry:
            lines.append(f"{key} = {entry}")
            continue
        display = str(entry.get("display_value") or "")
        if "\n" in display:
            lines.append(f"{key} =")
            lines.extend(f"  {line}" for line in display.splitlines())
        else:
            lines.append(f"{key} = {display}")
        lines.append(
            f"  status={entry.get('status')} resolution={entry.get('resolution')} "
            f"visibility={entry.get('visibility')} redacted={entry.get('redacted')}"
        )
        origin = entry.get("origin")
        if isinstance(origin, dict):
            lines.append(f"  source: {origin.get('label') or origin.get('id')}")
        inheritance = entry.get("inheritance")
        if isinstance(inheritance, list):
            for source in inheritance:
                if not isinstance(source, dict) or source.get("selected") is True:
                    continue
                lines.append(f"  inherited from: {source.get('label') or source.get('id')}")
        references = entry.get("references")
        if isinstance(references, list) and references:
            chain = " -> ".join(
                f"{item.get('target') or item.get('reference')}({item.get('status')})"
                for item in references
                if isinstance(item, dict)
            )
            lines.append(f"  replacements: {chain}")
        unresolved = entry.get("unresolved_references")
        if isinstance(unresolved, list) and unresolved:
            lines.append(f"  unresolved: {', '.join(str(item) for item in unresolved)}")
        explanation = entry.get("explanation")
        if isinstance(explanation, str) and explanation:
            lines.append(f"  why: {explanation}")


__all__ = ["show_config_public_text"]
