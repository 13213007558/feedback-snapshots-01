from __future__ import annotations

import abc
import time
from typing import Any

from django.contrib.auth import get_user_model
from django.contrib.auth.base_user import AbstractBaseUser

from allauth.account.internal.userkit import str_to_user_id, user_id_to_str


class AbstractCodeVerificationProcess(abc.ABC):
    def __init__(
        self,
        max_attempts: int,
        timeout: int,
        state: dict,
        user: AbstractBaseUser | None = None,
    ) -> None:
        self._user = user
        self.max_attempts = max_attempts
        self.timeout = timeout
        self.state = state

    @property
    def user(self) -> AbstractBaseUser | None:
        if self._user:
            return self._user
        user_id = self.state.get("user_id")
        if not user_id:
            return None
        user_id = str_to_user_id(user_id)
        self._user = get_user_model().objects.filter(pk=user_id).first()
        return self._user

    @property
    def code(self) -> str:
        return self.state.get("code", "")

    @property
    def failed_attempts(self) -> int:
        """The number of incorrect codes entered for this process."""
        return self.state["failed_attempts"]

    @property
    def attempts_left(self) -> int:
        """The number of attempts left at entering the code for this process."""
        return max(self.max_attempts - self.failed_attempts, 0)

    @property
    def resend_count(self) -> int:
        """The number of times a new code was sent for this same process."""
        return self.state["resend_count"]

    @property
    def code_generation(self) -> int:
        """Identifies the current code.

        It increments every time a fresh code is issued for this process, so a
        replacement (resend) is distinguishable from the code it replaced.
        """
        return self.state.get("code_generation", 0)

    def record_code_generated(self) -> None:
        """Marks that a fresh code was issued.

        The new code replaces the previous one and starts a new validity
        window. The attempt budget is intentionally left untouched: it is
        shared by all codes issued for this process.
        """
        self.state["code_generation"] = self.code_generation + 1
        self.state["at"] = time.time()

    @classmethod
    def initial_state(
        cls,
        user: AbstractBaseUser | None,
        email: str | None = None,
        phone: str | None = None,
    ) -> dict[str, Any]:
        state: dict[str, Any] = {
            "at": time.time(),
            "failed_attempts": 0,
            "resend_count": 0,
            "change_count": 0,
        }
        if email:
            state["email"] = email
        if phone:
            state["phone"] = phone
        if user:
            state["user_id"] = user_id_to_str(user)
        return state

    def record_invalid_attempt(self) -> bool:
        self.state["failed_attempts"] += 1
        if self.state["failed_attempts"] >= self.max_attempts:
            self.abort()
            return False
        self.persist()
        return True

    def abort_if_invalid(self):
        if not self.is_valid():
            self.abort()
            return None
        return self

    def is_valid(self) -> bool:
        return time.time() - self.state["at"] <= self.timeout

    @abc.abstractmethod
    def persist(self) -> None: ...  # noqa: E704

    @abc.abstractmethod
    def send(self) -> None: ...  # noqa: E704

    @abc.abstractmethod
    def abort(self) -> None: ...  # noqa: E704

    def is_resend_quota_reached(self, quota: int) -> bool:
        return self.state["resend_count"] >= quota

    def is_change_quota_reached(self, quota: int) -> bool:
        return self.state["change_count"] >= quota

    def record_change(
        self, *, email: str | None = None, phone: str | None = None
    ) -> None:
        self.state["change_count"] += 1
        if email:
            self.state["email"] = email
        if phone:
            self.state["phone"] = phone

    def record_resend(self) -> None:
        self.state["resend_count"] += 1

    @property
    def can_resend(self) -> bool:
        return False

    @property
    def can_change(self) -> bool:
        return False
