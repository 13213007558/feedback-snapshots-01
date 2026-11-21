# SPDX-License-Identifier: Apache-2.0
#
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.
#
# Modifications Copyright OpenSearch Contributors. See
# GitHub history for details.
#
#  Licensed to Elasticsearch B.V. under one or more contributor
#  license agreements. See the NOTICE file distributed with
#  this work for additional information regarding copyright
#  ownership. Elasticsearch B.V. licenses this file to you under
#  the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
# 	http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing,
#  software distributed under the License is distributed on an
#  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#  KIND, either express or implied.  See the License for the
#  specific language governing permissions and limitations
#  under the License.

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, FrozenSet, Tuple

from .errors import ReindexCapabilityError


def _index_name(value: Any, role: str) -> str:
    """Return a concrete index name or fail closed."""
    if not isinstance(value, str):
        raise ReindexCapabilityError(
            f"reindex capability {role} must be a concrete index name, got {value!r}"
        )

    name = value.strip()
    if (
        not name
        or name == "_all"
        or name.startswith(("+", "-"))
        or any(character in name for character in "*?,")
    ):
        raise ReindexCapabilityError(
            f"reindex capability {role} must be a concrete index name, got {value!r}"
        )
    return name


def _index_names(values: Any, role: str) -> Tuple[str, ...]:
    if isinstance(values, str):
        values = (values,)
    elif isinstance(values, (set, frozenset)):
        values = tuple(sorted(values, key=str))
    elif not isinstance(values, (list, tuple)):
        raise ReindexCapabilityError(
            f"reindex capability {role} must be an index name or a collection of names"
        )

    names = tuple(dict.fromkeys(_index_name(value, role) for value in values))
    if not names:
        raise ReindexCapabilityError(
            f"reindex capability {role} must contain at least one index"
        )
    return names


@dataclass(frozen=True)
class ReindexCapability:
    """
    Declares the identities and index scope a reindex job may use.

    The capability binds the exact source and target client objects (the
    selected identities) as well as the permitted source indices and the
    single permitted target index. It can be passed to
    :func:`~opensearchpy.helpers.reindex` and to the bulk helpers.

    :arg source_client: client authorized to search and scroll the source
    :arg source_indices: concrete source index names the job may read
    :arg target_client: client authorized to perform bulk writes
    :arg target_index: the only index bulk actions may write to

    Bulk actions must resolve to the capability's target index, either by
    naming it explicitly in the action metadata or by using the matching
    request-level ``index``. An action with no resolvable target is rejected
    before the bulk request is sent.
    """

    source_client: Any
    source_indices: Any
    target_client: Any
    target_index: str
    _source_index_set: FrozenSet[str] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.source_client is None:
            raise ReindexCapabilityError("reindex capability requires a source client")
        if self.target_client is None:
            raise ReindexCapabilityError("reindex capability requires a target client")

        source_indices = _index_names(self.source_indices, "source")
        target_index = _index_name(self.target_index, "target")
        object.__setattr__(self, "source_indices", source_indices)
        object.__setattr__(self, "target_index", target_index)
        object.__setattr__(self, "_source_index_set", frozenset(source_indices))

    def authorize_reader(self, client: Any) -> None:
        """Ensure ``client`` is the selected source identity."""
        if client is not self.source_client:
            raise ReindexCapabilityError(
                "reindex source client does not match the capability identity"
            )

    def authorize_writer(self, client: Any) -> None:
        """Ensure ``client`` is the selected target identity."""
        if client is not self.target_client:
            raise ReindexCapabilityError(
                "reindex target client does not match the capability identity"
            )

    def authorize_source(self, client: Any, source_index: Any) -> Tuple[str, ...]:
        """Validate a source read request and return canonical index names."""
        self.authorize_reader(client)
        requested = _index_names(source_index, "source")
        denied = tuple(name for name in requested if name not in self._source_index_set)
        if denied:
            raise ReindexCapabilityError(
                "reindex source index is outside the capability scope: "
                + ", ".join(repr(name) for name in denied)
            )
        return requested

    def authorize_target(self, client: Any, target_index: Any) -> str:
        """Validate a target write request and return its canonical index name."""
        self.authorize_writer(client)
        requested = _index_name(target_index, "target")
        if requested != self.target_index:
            raise ReindexCapabilityError(
                "reindex target index is outside the capability scope: "
                f"{requested!r}"
            )
        return self.target_index

    def authorize_bulk_kwargs(self, kwargs: Mapping[str, Any]) -> None:
        """Reject a request-level index that could change the write target."""
        if "index" in kwargs and kwargs["index"] is not None:
            requested = _index_name(kwargs["index"], "target")
            if requested != self.target_index:
                raise ReindexCapabilityError(
                    "bulk request index is outside the capability scope: "
                    f"{requested!r}"
                )

    def authorize_action(self, action: Any, request_index: Any = None) -> None:
        """Reject one expanded bulk action unless it targets the capability."""
        if not isinstance(action, Mapping) or len(action) != 1:
            raise ReindexCapabilityError(
                "bulk action does not contain exactly one operation"
            )

        op_type, metadata = next(iter(action.items()))
        if op_type not in ("index", "create", "update", "delete") or not isinstance(
            metadata, Mapping
        ):
            raise ReindexCapabilityError(
                f"unsupported bulk action for reindex capability: {op_type!r}"
            )

        target = metadata.get("_index")
        if target is None:
            target = request_index
        if target != self.target_index:
            raise ReindexCapabilityError(
                "bulk action target is outside the capability scope: " f"{target!r}"
            )

    def authorize_chunk(
        self, bulk_data: Iterable[Any], request_index: Any = None
    ) -> None:
        """Validate every action in a chunk before an HTTP request is sent."""
        for data in bulk_data:
            if not isinstance(data, (list, tuple)) or not data:
                raise ReindexCapabilityError("bulk action is malformed")
            self.authorize_action(data[0], request_index=request_index)
