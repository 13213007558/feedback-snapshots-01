# -----------------------------------------------------------------------------
# Copyright (C) 2026 The python-ndn authors
#
# This file is part of python-ndn.
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
# -----------------------------------------------------------------------------
"""
Generation-aware online switching of LVS trust policies and trust anchors.

A :class:`LvsValidatorSwitch` keeps one immutable :class:`ValidationGeneration`
per installed policy/anchor combination. Every validation request is pinned to
the generation that is current when the request enters the switch, including
the whole certificate chain that request may fetch. Switching policy or anchor
installs a fresh generation with an independent public-key cache instead of
clearing the caches of generations that still have requests in flight.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ...app import NDNApp, PktContext, Validator
from ...encoding import BinaryStr, FormalName, Name, SignaturePtrs
from ...security.validator.cascade_validator import (
    CascadeChecker,
    MemoryKeyStorage,
    PublicKeyStorage,
)
from ...types import ValidResult
from .checker import Checker
from .validator import validate_lvs_trust_anchor


__all__ = ['ValidationGeneration', 'LvsValidatorSwitch']


@dataclass
class ValidationGeneration:
    """
    An immutable binding of an LVS policy, a trust anchor and a key cache.

    A generation is never mutated after creation: changing the policy or the
    anchor always produces a new generation with a new cache. The three
    attributes are therefore the exact basis against which every request
    pinned to this generation is validated.
    """

    generation_id: int
    checker: Checker
    trust_anchor: bytes
    storage: PublicKeyStorage
    cascade: CascadeChecker
    validator: Validator
    in_flight: int = 0
    retired: bool = False


class LvsValidatorSwitch:
    """
    Online, generation-based switch for an LVS validation policy.

    The object itself is a :any:`Validator`: pass it directly to
    :meth:`ndn.app.NDNApp.express` or a route handler. Each request adopts the
    generation returned by :attr:`current_generation` at entry time and keeps
    using that generation for every recursively fetched certificate, so a
    request started before a switch finishes against the old policy and writes
    its fetched keys only into the old generation's cache.

    New requests never fall back to a retired generation. When the last
    in-flight request of a retired generation finishes, that generation and its
    cache are released. Other generations keep their caches, so switching does
    not empty the whole process cache. Certificates carrying the same name are
    stored independently in each generation and can differ across policy
    domains.

    Every generation gets a fresh cache by default. A custom
    ``storage_factory`` must also return an independent storage per call;
    sharing one storage across generations would let stale keys bypass the new
    policy and defeats the generation boundary.
    """

    def __init__(
        self,
        checker: Checker,
        app: NDNApp,
        trust_anchor: BinaryStr,
        storage_factory: Callable[[], PublicKeyStorage] | None = None,
    ):
        """
        :param checker: compiled LVS policy checker for the first generation.
        :param app: application used to fetch certificates.
        :param trust_anchor: wire-encoded trust anchor certificate.
        :param storage_factory: optional zero-argument callable returning a
                                fresh :class:`PublicKeyStorage` for each
                                generation; defaults to :class:`MemoryKeyStorage`.
        :raises ValueError: if the initial checker/anchor combination is invalid.
        """
        self.app = app
        self.storage_factory = (
            storage_factory if storage_factory is not None else MemoryKeyStorage
        )
        self.logger = logging.getLogger(__name__)
        self._generations: dict[int, ValidationGeneration] = {}
        self._current_id = 0
        self._closed = False
        self._install(checker, bytes(trust_anchor))

    @property
    def current_generation(self) -> ValidationGeneration:
        """The generation that new validation requests are pinned to."""
        return self._generations[self._current_id]

    @property
    def generation_id(self) -> int:
        """Monotonic identifier of the current generation, starting at 1."""
        return self._current_id

    def generation(self, generation_id: int) -> ValidationGeneration | None:
        """Return a live generation by id, or ``None`` if it was retired."""
        return self._generations.get(generation_id)

    def _install(
        self,
        checker: Checker,
        trust_anchor: bytes,
    ) -> ValidationGeneration:
        # Validate before mutating any state so a bad switch keeps the
        # previously installed generation serving traffic.
        validate_lvs_trust_anchor(checker, trust_anchor)
        storage = self.storage_factory()
        cascade = CascadeChecker(self.app, trust_anchor, storage)
        generation_id = self._current_id + 1

        async def validate(
            name: FormalName,
            sig_ptrs: SignaturePtrs,
            context: PktContext,
        ) -> ValidResult:
            sig_info = sig_ptrs.signature_info
            if (
                sig_info is None
                or sig_info.key_locator is None
                or not sig_info.key_locator.name
            ):
                return ValidResult.FAIL

            cert_name = sig_info.key_locator.name
            self.logger.debug(
                'LVS gen %d checking %s <- %s ...',
                generation_id,
                Name.to_str(name),
                Name.to_str(cert_name),
            )
            if not checker.check(name, cert_name):
                return ValidResult.FAIL
            return await cascade(name, sig_ptrs, context)

        cascade.next_level = validate

        generation = ValidationGeneration(
            generation_id=generation_id,
            checker=checker,
            trust_anchor=trust_anchor,
            storage=storage,
            cascade=cascade,
            validator=validate,
        )
        self._current_id = generation.generation_id
        self._generations[generation.generation_id] = generation
        return generation

    def switch(
        self,
        checker: Checker | None = None,
        trust_anchor: BinaryStr | None = None,
    ) -> int:
        """
        Install a new generation and retire the previous one.

        Only one argument needs to be supplied; the omitted argument is taken
        from the current generation. Passing neither argument still starts a
        fresh generation with an empty cache, which is useful when the trust
        decision must be re-evaluated without changing policy or anchor.

        :param checker: new LVS policy checker; defaults to the current one.
        :param trust_anchor: new wire-encoded trust anchor; defaults to the
                             current one.
        :return: the identifier of the newly installed generation.
        :raises ValueError: if the new checker/anchor combination is invalid,
                            in which case the current generation is left intact.
        """
        if self._closed:
            raise RuntimeError('Validator switch has been closed')
        current = self.current_generation
        next_checker = current.checker if checker is None else checker
        next_anchor = (
            current.trust_anchor if trust_anchor is None else bytes(trust_anchor)
        )
        new_generation = self._install(next_checker, next_anchor)
        current.retired = True
        self._retire_if_idle(current)
        self.logger.info(
            'Switched LVS validation to generation %d',
            new_generation.generation_id,
        )
        return new_generation.generation_id

    def _retire_if_idle(self, generation: ValidationGeneration) -> None:
        if generation.retired and generation.in_flight == 0:
            self._generations.pop(generation.generation_id, None)

    async def __call__(
        self,
        name: FormalName,
        sig_ptrs: SignaturePtrs,
        context: dict[str, Any],
    ) -> ValidResult:
        # Pin the generation once, synchronously, before the first await so an
        # interleaved switch cannot redirect this request or its certificate
        # chain to the new generation.
        generation = self.current_generation
        generation.in_flight += 1
        try:
            return await generation.validator(name, sig_ptrs, context)
        finally:
            generation.in_flight -= 1
            self._retire_if_idle(generation)

    async def aclose(self) -> None:
        """Retire every generation. In-flight requests still finish safely."""
        if self._closed:
            return
        self._closed = True
        for generation in list(self._generations.values()):
            generation.retired = True
            self._retire_if_idle(generation)
