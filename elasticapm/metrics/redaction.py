#  BSD 3-Clause License
#
#  Copyright (c) 2026, Elasticsearch BV
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#
#  * Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
#  * Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
#  * Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
#  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
#  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""Public projection for labelled metrics.

Metric sets accumulate samples under their full label set so that internal
aggregation and subsequent collection cycles keep every dimension.  Labels are
only a disclosure surface when a metricset is published, and the permission for
a label may be withdrawn between two collection cycles or even after a batch
was captured but before it is sent.

The helpers in this module deliberately do not touch the metric stores.  They
take the data that is about to leave the process, remove labels that are not
allowed at that moment, and merge samples whose originally distinct label sets
collapse onto the same public series.  Counters, timers and histograms keep
their real totals while gauges keep their latest value.
"""

from __future__ import absolute_import

import copy

from elasticapm.utils import starmatch_to_regex

# Correlation labels that a ``SpanBoundMetricSet`` moves from the flat tag
# mapping into nested event fields before the event is queued.
NESTED_LABEL_FIELDS = (
    ("span", ("type", "subtype")),
    ("transaction", ("name", "type")),
)


class MetricLabelPolicy(object):
    """Decide which metric labels may be published.

    ``allowlist`` and ``denylist`` accept glob patterns.  A plain pattern
    matches the label key, a pattern with ``=`` matches the public
    ``key=value`` pair, and a pattern that matches neither the key nor
    ``key=value`` may still match the bare value.  A mapping value is expanded
    into ``key=value`` entries; a mapping entry whose value is ``None``, ``*``
    or an empty sequence allows or denies every value of that key.

    A label must match an allowlist entry (when one is configured) and must not
    match a denylist entry.
    """

    def __init__(self, allowlist=None, denylist=None) -> None:
        self.allowlist = self._compile(allowlist)
        self.denylist = self._compile(denylist)
        # An allowlist that was explicitly configured denies everything it
        # does not mention.  ``None`` means "no allowlist was configured".
        self.allowlist_configured = allowlist is not None

    @classmethod
    def _compile(cls, value):
        if value is None:
            return []
        if isinstance(value, cls):
            return list(value.allowlist)
        patterns = []

        def add(item):
            if item is None:
                return
            if isinstance(item, cls):
                patterns.extend(item.allowlist)
            elif isinstance(item, dict):
                for key, allowed in item.items():
                    if allowed is None or allowed == "*" or allowed == []:
                        add(key)
                    elif isinstance(allowed, (list, tuple, set, frozenset)):
                        for entry in allowed:
                            add("%s=%s" % (key, entry))
                    else:
                        add("%s=%s" % (key, allowed))
            elif isinstance(item, str):
                patterns.extend(part.strip() for part in item.split(",") if part.strip())
            elif isinstance(item, (list, tuple, set, frozenset)):
                for entry in item:
                    add(entry)
            else:
                patterns.append(item)
        add(value)
        return [starmatch_to_regex(pattern) if isinstance(pattern, str) else pattern for pattern in patterns]

    @property
    def active(self) -> bool:
        return self.allowlist_configured or bool(self.denylist)

    def allows(self, key, value=None) -> bool:
        key = str(key)
        candidates = [key]
        if value is not None and value != "":
            candidates.append(str(value))
            candidates.append("%s=%s" % (key, value))

        if any(pattern.match(candidate) for pattern in self.denylist for candidate in candidates):
            return False
        if not self.allowlist_configured:
            return True
        return any(pattern.match(candidate) for pattern in self.allowlist for candidate in candidates)


def policy_from_config(config):
    """Build a :class:`MetricLabelPolicy` from a config-like object.

    ``None`` is returned when no label permission was configured, which keeps
    the default export path byte-compatible with older agent versions.
    """
    if config is None:
        return None

    allowlist = getattr(config, "metric_labels_allowlist", None)
    denylist = getattr(config, "metric_labels_denylist", None)
    # Tolerate the singular spelling used by some dynamic configuration
    # payloads without adding a second set of public options.
    if allowlist is None:
        allowlist = getattr(config, "metric_label_allowlist", None)
    if denylist is None:
        denylist = getattr(config, "metric_label_denylist", None)
    if allowlist is None and denylist is None:
        return None

    policy = MetricLabelPolicy(allowlist=allowlist, denylist=denylist)
    return policy if policy.active else None


def metricset_policy(metricset):
    """Return the live label policy for a metricset/registry object.

    The policy is read on every call, not cached with the metric stores, so a
    permission change applies to the next collection cycle and to any batch
    that has not been published yet.
    """
    registry = getattr(metricset, "_registry", metricset)
    client = getattr(registry, "client", None)
    if client is None:
        return None
    config = getattr(client, "config", None)
    if config is None:
        return None
    return policy_from_config(config)


def project_metricset_event(data, policy):
    """Return ``data`` with labels that ``policy`` forbids removed.

    The input mapping is not modified.  ``data`` may be either a complete
    metricset event (with ``samples``) or just its tag/correlation payload.
    """
    if policy is None:
        return data

    data = dict(data)
    tags = data.get("tags")
    if isinstance(tags, dict):
        filtered = {key: value for key, value in tags.items() if policy.allows(key, value)}
        if filtered:
            data["tags"] = filtered
        else:
            data.pop("tags", None)

    for section, fields in NESTED_LABEL_FIELDS:
        value = data.get(section)
        if not isinstance(value, dict):
            continue
        filtered = {}
        for field in fields:
            if field not in value:
                continue
            if policy.allows("%s.%s" % (section, field), value[field]):
                filtered[field] = value[field]
        if filtered:
            data[section] = filtered
        else:
            data.pop(section, None)
    return data


def public_metricset_identity(data, policy=None):
    """Return the values that determine a public metric series.

    ``timestamp`` is part of the identity so that samples from different
    collection cycles stay separate time-series points.  Histogram bucket
    boundaries are included when present, because counts with a different
    bucket layout cannot be added element-wise.
    """
    if policy is not None:
        data = project_metricset_event(data, policy)

    sample_names = []
    shapes = []
    for name, sample in sorted((data.get("samples") or {}).items()):
        sample_names.append(str(name))
        if isinstance(sample, dict) and "values" in sample:
            shapes.append((str(name), tuple(sample.get("values") or ())))

    return (
        data.get("timestamp"),
        _stable_mapping(data.get("tags")),
        _stable_mapping(data.get("span")),
        _stable_mapping(data.get("transaction")),
        tuple(sample_names),
        tuple(shapes),
    )


def _stable_mapping(value):
    if not isinstance(value, dict):
        return ()
    return tuple(sorted((str(key), str(field_value)) for key, field_value in value.items()))


def merge_sample(target, source):
    """Merge ``source`` metric samples into ``target`` without losing totals."""
    for name, sample in source.items():
        existing = target.get(name)
        if existing is None:
            target[name] = copy.deepcopy(sample)
            continue

        if "counts" in existing and "counts" in sample and "values" in existing and "values" in sample:
            target[name]["counts"] = _merge_histogram_counts(existing, sample)
        elif existing.get("type") == "gauge" or sample.get("type") == "gauge":
            # Gauges are point-in-time values, not additive amounts.  When two
            # gauges collapse onto one public series the latest observation is
            # the only truthful value; adding them would invent a measurement.
            target[name]["value"] = sample.get("value", existing.get("value"))
        elif "value" in existing and "value" in sample:
            target[name]["value"] = existing["value"] + sample["value"]
    return target


def _merge_histogram_counts(existing, sample):
    existing_counts = existing.get("counts") or []
    sample_counts = sample.get("counts") or []
    length = max(len(existing_counts), len(sample_counts))
    merged = []
    for index in range(length):
        left = existing_counts[index] if index < len(existing_counts) else 0
        right = sample_counts[index] if index < len(sample_counts) else 0
        merged.append(left + right)
    return merged


def merge_metricset_events(target, source):
    """Merge two metricset events that have the same public identity."""
    merge_sample(target.setdefault("samples", {}), source.get("samples") or {})
    if "timestamp" not in target and "timestamp" in source:
        target["timestamp"] = source["timestamp"]
    return target


def merge_metricsets(events, policy=None):
    """Project and merge a sequence of metricset events.

    Order is preserved: the position of a merged series is the position of its
    first contributor.  Events without a metric payload are returned as-is.
    """
    result = []
    positions = {}
    for event in events:
        if not isinstance(event, dict) or "samples" not in event:
            result.append(event)
            continue
        projected = project_metricset_event(event, policy)
        identity = public_metricset_identity(projected)
        position = positions.get(identity)
        if position is None:
            positions[identity] = len(result)
            result.append(copy.deepcopy(projected))
        else:
            merge_metricset_events(result[position], projected)
    return result


def reproject_batch_entries(entries, policy):
    """Apply ``policy`` to the metricsets of an already captured batch.

    ``entries`` is an ordered list of ``(event_type, raw_line, payload)``
    tuples.  ``raw_line`` is the exact serialized NDJSON line for non-metric
    events; those are re-emitted byte-for-byte so an unrelated processor or
    caller cannot change their representation at flush time.  ``payload`` is
    the captured metricset mapping, needed to honour a permission change that
    happened after the batch was captured.

    Returns an ordered list of ``(event_type, raw_line, payload)`` tuples.  For
    metricsets, ``raw_line`` is ``None`` and ``payload`` is the projected,
    merged event.  Metricsets that share a public series after projection are
    collapsed into their first position.
    """
    if policy is None:
        return entries

    result = []
    positions = {}
    for event_type, raw_line, payload in entries:
        if event_type != "metricset" or payload is None:
            result.append((event_type, raw_line, payload))
            continue
        projected = project_metricset_event(payload, policy)
        identity = public_metricset_identity(projected)
        position = positions.get(identity)
        if position is None:
            positions[identity] = len(result)
            result.append(("metricset", None, copy.deepcopy(projected)))
        else:
            merge_metricset_events(result[position][2], projected)
    return result
