"""
v1.6 baseline upgrade
=====================

Earlier baseline versions mixed two distinct kinds of information inside each entry of
``results``:

1. the *finding* itself (what the scanner observed: type, location, fingerprint), and
2. the *audit evidence* (the human review decision: ``is_secret``).

When the detecting configuration is unified, two previously distinct findings can collapse
into a single new fingerprint. Because the baseline only stores fingerprints (never the
secret value), a fingerprint migration cannot be recomputed: it must be supplied alongside the
configuration change. An old baseline may declare this mapping in a top-level
``fingerprint_updates`` table.

This upgrade therefore:

* migrates finding data and audit evidence into separate sections (``results`` and ``audit``),
* applies the fingerprint migration to each finding's identity,
* merges findings that map to the same new fingerprint into one candidate, while keeping every
  contributing source's evidence attached to the merged entry (no source is dropped), and
* leaves a merged entry pending review (``needs_review``) when the inherited human decisions
  conflict, instead of guessing an outcome.
"""
from copy import deepcopy
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

#: Old baselines may carry a top-level table mapping an old fingerprint to its new one.
FINGERPRINT_UPGRADES_KEY = 'fingerprint_updates'

#: New top-level section holding the migrated human review evidence, keyed by finding identity.
AUDIT_SECTION = 'audit'

#: A single, unambiguous decision was inherited from the contributing source(s).
STATUS_LABELLED = 'labelled'

#: No human decision has ever been recorded for this finding.
STATUS_UNLABELLED = 'unlabelled'

#: Contributing sources disagree (or were merged); a human must make the call.
STATUS_NEEDS_REVIEW = 'needs_review'

FindingKey = Tuple[str, str, str]


def upgrade(baseline: Dict[str, Any]) -> None:
    """In-place upgrade of a single, already-loaded baseline (see ``baseline.upgrade``)."""
    merged = migrate([baseline])
    baseline.clear()
    baseline.update(merged)


def migrate(
    baselines: List[Dict[str, Any]],
    *,
    source_names: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Migrate one or more old baselines into a single v1.6 baseline.

    Finding data and audit evidence are migrated separately: deduplicated, label-free findings
    land in ``results``, while every source's review evidence is preserved in ``audit``.

    :param baselines: old-version baseline dicts, each optionally carrying a
        ``fingerprint_updates`` table.
    :param source_names: human-readable identifiers for each baseline, used as provenance.
        Defaults to ``source-1``, ``source-2``, ...
    """
    if not baselines:
        raise ValueError('At least one baseline is required to perform a migration.')

    if source_names is None:
        source_names = [f'source-{index + 1}' for index in range(len(baselines))]
    elif len(source_names) != len(baselines):
        raise ValueError('A source name must be provided for every baseline.')

    # Findings are grouped by their *new* identity, so distinct old fingerprints that map to
    # the same new one collapse into one candidate.
    findings: Dict[FindingKey, Dict[str, Any]] = {}
    evidence: Dict[FindingKey, List[Dict[str, Any]]] = {}

    for source_name, source_baseline in zip(source_names, baselines):
        fingerprint_map = source_baseline.get(FINGERPRINT_UPGRADES_KEY, {})

        for filename, entries in _iter_results(source_baseline.get('results', {})):
            for entry in entries:
                old_hash = entry['hashed_secret']
                new_hash = fingerprint_map.get(old_hash, old_hash)

                finding, key = _build_finding(filename, entry, new_hash)
                findings.setdefault(key, finding)
                evidence.setdefault(key, []).append(
                    _build_evidence(source_name, filename, entry, old_hash, new_hash),
                )

    output: Dict[str, Any] = {
        key: deepcopy(value)
        for key, value in baselines[0].items()
        if key not in ('results', FINGERPRINT_UPGRADES_KEY)
    }
    output['results'] = _serialize_findings(findings)
    output[AUDIT_SECTION] = _build_audit_section(evidence)
    return output


def _build_finding(
    filename: str,
    entry: Dict[str, Any],
    new_hash: str,
) -> Tuple[Dict[str, Any], FindingKey]:
    # Audit state never belongs in the finding itself anymore.
    finding = {
        key: value
        for key, value in entry.items()
        if key != 'is_secret'
    }
    finding['hashed_secret'] = new_hash
    finding['filename'] = filename
    return finding, (filename, new_hash, str(entry['type']))


def _build_evidence(
    source_name: str,
    filename: str,
    entry: Dict[str, Any],
    old_hash: str,
    new_hash: str,
) -> Dict[str, Any]:
    record = {
        'source': source_name,
        'type': entry['type'],
        'filename': filename,
        'hashed_secret': old_hash,
        'line_number': entry.get('line_number', 0),
        'is_secret': entry.get('is_secret'),
    }
    if old_hash != new_hash:
        # Keep the remapping explicit, so the decision remains re-reviewable afterwards.
        record['migrated_hashed_secret'] = new_hash
    return record


def _build_audit_section(
    evidence: Dict[FindingKey, List[Dict[str, Any]]],
) -> Dict[str, Dict[str, Any]]:
    section: Dict[str, Dict[str, Any]] = {}
    for key, records in evidence.items():
        labels = {
            record['is_secret']
            for record in records
            if record['is_secret'] is not None
        }

        if len(labels) > 1:
            # Conflicting inherited decisions: never guess. Hold the merge for review.
            status = STATUS_NEEDS_REVIEW
            decision: Optional[bool] = None
        elif len(labels) == 1:
            status = STATUS_LABELLED
            decision = labels.pop()
        else:
            status = STATUS_UNLABELLED
            decision = None

        # A single, unlabelled source contributes no review evidence worth carrying; keeping a
        # noisy empty entry would make every fresh finding look like a migrated one.
        if len(records) == 1 and records[0]['is_secret'] is None:
            continue

        section[_identity_key(key)] = {
            'type': key[2],
            'filename': key[0],
            'hashed_secret': key[1],
            'is_secret': decision,
            'status': status,
            'sources': records,
        }

    return section


def _serialize_findings(
    findings: Dict[FindingKey, Dict[str, Any]],
) -> Dict[str, List[Dict[str, Any]]]:
    output: Dict[str, List[Dict[str, Any]]] = {}
    for (filename, _, _), finding in findings.items():
        output.setdefault(filename, []).append(dict(finding))

    for entries in output.values():
        entries.sort(key=lambda entry: (entry.get('line_number', 0), entry['hashed_secret']))

    return dict(sorted(output.items()))


def _identity_key(key: FindingKey) -> str:
    filename, hashed_secret, secret_type = key
    return f'{filename}:{hashed_secret}:{secret_type}'


def _iter_results(results: Any) -> List[Tuple[str, List[Dict[str, Any]]]]:
    """
    Normalizes the legacy ``results`` layouts. Modern baselines map filenames to their findings,
    but very old baselines stored an empty list when no secrets were found.
    """
    return list(results.items()) if isinstance(results, dict) else []
