from ..reference_scopes import REFERENCE_SCOPE_KEY, scope_for_line
from .state_core import StateCore

_MISSING = object()


def inline(state: StateCore) -> None:
    """Parse inlines"""
    previous = state.env.get(REFERENCE_SCOPE_KEY, _MISSING)
    try:
        for token in state.tokens:
            if token.type == "inline":
                if token.children is None:
                    token.children = []
                scope = scope_for_line(state.env, token.map[0]) if token.map else None
                if scope is None:
                    state.env.pop(REFERENCE_SCOPE_KEY, None)
                else:
                    state.env[REFERENCE_SCOPE_KEY] = scope
                state.md.inline.parse(
                    token.content, state.md, state.env, token.children
                )
    finally:
        if previous is _MISSING:
            state.env.pop(REFERENCE_SCOPE_KEY, None)
        else:
            state.env[REFERENCE_SCOPE_KEY] = previous
