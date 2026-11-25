# Copyright 2018 The Kubernetes Authors.
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


from .create_from_yaml import (FailToCreateError, create_from_dict,
                               create_from_yaml, create_from_directory)
from .quantity import parse_quantity
from .duration import parse_duration
from .metrics import (get_nodes_metrics, get_pods_metrics,
                      get_pods_metrics_in_all_namespaces)
from .retry import (Backoff, DEFAULT_BACKOFF, DEFAULT_RETRY,
                    DEFAULT_RETRY_AFTER_BACKOFF, is_conflict,
                    is_retry_after_response, is_too_many_requests, on_error,
                    on_retry_after_error, retry_after_backoff,
                    retry_after_max_retries, retry_on_conflict,
                    retry_after_seconds)
from .keepalive import tcp_keepalive_socket_options

# The dry-run permit helpers depend on kubernetes.client, which imports
# kubernetes.utils.retry.  Resolve them lazily so importing this package
# from the generated client's REST layer cannot create an import cycle.
_DRY_RUN_EXPORTS = {
    "CommitApproval": "CommitApproval",
    "DRY_RUN_ALL": "DRY_RUN_ALL",
    "DryRunAttempt": "DryRunAttempt",
    "DryRunExchange": "DryRunExchange",
    "DryRunPermit": "DryRunPermit",
    "DryRunRequest": "DryRunRequest",
    "DryRunRetry": "DryRunRetry",
    "DryRunSession": "DryRunSession",
    "PermitCheck": "PermitCheck",
    "PermitMismatch": "PermitMismatch",
    "review_preview": "review_preview",
}


def __getattr__(name):
    if name in _DRY_RUN_EXPORTS:
        from . import dry_run
        value = getattr(dry_run, _DRY_RUN_EXPORTS[name])
        globals()[name] = value
        return value
    raise AttributeError(
        "module {!r} has no attribute {!r}".format(__name__, name))


def __dir__():
    return sorted(set(globals()) | set(_DRY_RUN_EXPORTS))

__all__ = [
    "FailToCreateError",
    "create_from_dict",
    "create_from_yaml",
    "create_from_directory",
    "parse_quantity",
    "parse_duration",
    "get_nodes_metrics",
    "get_pods_metrics",
    "get_pods_metrics_in_all_namespaces",
    "Backoff",
    "DEFAULT_BACKOFF",
    "DEFAULT_RETRY",
    "DEFAULT_RETRY_AFTER_BACKOFF",
    "is_conflict",
    "is_retry_after_response",
    "is_too_many_requests",
    "on_error",
    "on_retry_after_error",
    "retry_after_backoff",
    "retry_after_max_retries",
    "retry_on_conflict",
    "retry_after_seconds",
    "tcp_keepalive_socket_options",
    "CommitApproval",
    "DRY_RUN_ALL",
    "DryRunAttempt",
    "DryRunExchange",
    "DryRunPermit",
    "DryRunRequest",
    "DryRunRetry",
    "DryRunSession",
    "PermitCheck",
    "PermitMismatch",
    "review_preview",
]
