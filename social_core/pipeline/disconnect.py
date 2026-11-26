from __future__ import annotations

from typing import TYPE_CHECKING

from social_core.exceptions import AuthPolicyError, SocialAuthBaseException

if TYPE_CHECKING:
    from social_core.storage import UserProtocol
    from social_core.strategy import BaseStrategy


def allowed_to_disconnect(
    strategy: BaseStrategy[object],
    user: UserProtocol | None,
    name,
    user_storage,
    association_id=None,
    *args,
    **kwargs,
) -> dict[str, bool]:
    if not user_storage.allowed_to_disconnect(user, name, association_id):
        raise AuthPolicyError(code="disconnect_disallowed", stage="disconnect")
    return {"disconnect_policy_checked": True}


def get_entries(
    strategy: BaseStrategy[object],
    user: UserProtocol | None,
    name,
    user_storage,
    association_id=None,
    *args,
    **kwargs,
):
    return {
        "entries": user_storage.get_social_auth_for_user(user, name, association_id)
    }


def revoke_tokens(strategy, entries, *args, **kwargs) -> None:
    revoke_tokens_on_disconnect = strategy.setting("REVOKE_TOKENS_ON_DISCONNECT", False)
    if revoke_tokens_on_disconnect:
        for entry in entries:
            if "access_token" in entry.extra_data:
                backend = entry.get_backend_instance(strategy)
                try:
                    backend.revoke_token(entry.extra_data["access_token"], entry.uid)
                except SocialAuthBaseException as exc:
                    exc.context.setdefault("provider", entry.provider)
                    exc.context.setdefault("uid", entry.uid)
                    exc.context.setdefault("association_id", entry.id)
                    raise


def disconnect(
    strategy: BaseStrategy[object],
    entries,
    user_storage,
    user: UserProtocol | None = None,
    name: str | None = None,
    *args,
    **kwargs,
) -> None:
    disconnect_entries = getattr(user_storage, "disconnect_entries", None)
    if callable(disconnect_entries):
        disconnect_entries(
            entries,
            user=user,
            backend_name=name,
            check_policy=bool(kwargs.get("disconnect_policy_checked", False)),
        )
        return

    for entry in entries:
        user_storage.disconnect(entry)
