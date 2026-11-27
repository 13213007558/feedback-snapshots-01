import json

from detect_secrets.__version__ import VERSION
from detect_secrets.audit.common import format_audit_evidence
from detect_secrets.audit.iterator import get_secret_iterator
from detect_secrets.core import baseline
from detect_secrets.core.upgrades import v1_6
from detect_secrets.settings import get_settings


SECRET_TYPE = 'AWS Access Key'
FILENAME = 'config/settings.py'
OLD_HASH_A = '1111111111111111111111111111111111111111'
OLD_HASH_B = '2222222222222222222222222222222222222222'
NEW_HASH = '9999999999999999999999999999999999999999'


def _old_baseline(source_name, entries, fingerprint_updates=None):
    output = {
        'version': '1.5.0',
        'plugins_used': [
            {
                'name': 'AWSKeyDetector',
            },
        ],
        'filters_used': [
            {
                'path': 'detect_secrets.filters.allowlist.is_line_allowlisted',
            },
        ],
        'generated_at': '2026-11-20T00:00:00Z',
        'results': {
            FILENAME: entries,
        },
    }
    output['source'] = source_name
    if fingerprint_updates is not None:
        output[v1_6.FINGERPRINT_UPGRADES_KEY] = fingerprint_updates
    return output


def _entry(hashed_secret, line_number, is_secret=None):
    entry = {
        'type': SECRET_TYPE,
        'filename': FILENAME,
        'hashed_secret': hashed_secret,
        'is_verified': False,
        'line_number': line_number,
    }
    if is_secret is not None:
        entry['is_secret'] = is_secret
    return entry


def _configure_plugins():
    # The findings are loaded from dicts, but a configured plugin keeps settings round-trippable.
    get_settings().configure_plugins([
        {
            'name': 'AWSKeyDetector',
        },
    ])


class TestConflictMerge:
    """Two sources, two distinct old findings, conflicting review decisions, one new fingerprint."""

    @staticmethod
    def _baselines():
        baseline_a = _old_baseline(
            'team-a',
            [_entry(OLD_HASH_A, line_number=10, is_secret=True)],
            fingerprint_updates={OLD_HASH_A: NEW_HASH},
        )
        baseline_b = _old_baseline(
            'team-b',
            [_entry(OLD_HASH_B, line_number=12, is_secret=False)],
            fingerprint_updates={OLD_HASH_B: NEW_HASH},
        )
        return baseline_a, baseline_b

    def test_migrates_findings_and_evidence_separately_with_conflict_held_for_review(self):
        baseline_a, baseline_b = self._baselines()

        upgraded = v1_6.migrate(
            [baseline_a, baseline_b],
            source_names=['team-a', 'team-b'],
        )

        # The two old findings collapse into a single candidate under the new fingerprint.
        assert upgraded['version'] == '1.5.0'
        assert upgraded['results'] == {
            FILENAME: [
                {
                    'type': SECRET_TYPE,
                    'filename': FILENAME,
                    'hashed_secret': NEW_HASH,
                    'is_verified': False,
                    'line_number': 10,
                },
            ],
        }

        # Finding data carries no inline decision: audit evidence lives in its own section.
        merged_entry = upgraded['results'][FILENAME][0]
        assert 'is_secret' not in merged_entry
        assert v1_6.FINGERPRINT_UPGRADES_KEY not in upgraded

        identity = f'{FILENAME}:{NEW_HASH}:{SECRET_TYPE}'
        audit_entry = upgraded[v1_6.AUDIT_SECTION][identity]
        assert audit_entry['status'] == v1_6.STATUS_NEEDS_REVIEW
        assert audit_entry['is_secret'] is None

        # Neither contributing source may disappear: both decisions remain re-reviewable.
        sources = {
            record['source']: record
            for record in audit_entry['sources']
        }
        assert set(sources) == {'team-a', 'team-b'}
        assert sources['team-a']['is_secret'] is True
        assert sources['team-a']['hashed_secret'] == OLD_HASH_A
        assert sources['team-a']['migrated_hashed_secret'] == NEW_HASH
        assert sources['team-b']['is_secret'] is False
        assert sources['team-b']['hashed_secret'] == OLD_HASH_B
        assert sources['team-b']['migrated_hashed_secret'] == NEW_HASH

    def test_loaded_collection_keeps_conflict_pending_and_counts_one_to_audit(self):
        _configure_plugins()
        baseline_a, baseline_b = self._baselines()
        upgraded = v1_6.migrate(
            [baseline_a, baseline_b],
            source_names=['team-a', 'team-b'],
        )
        upgraded['version'] = VERSION

        collection = baseline.load(upgraded, filename='merged.baseline')

        assert len(collection) == 1
        secret = list(collection)[0][1]
        assert secret.secret_hash == NEW_HASH
        # Conflicting decisions cannot be auto-judged: the merge stays unlabelled.
        assert secret.is_secret is None
        assert secret.audit_metadata['status'] == v1_6.STATUS_NEEDS_REVIEW

        pending = get_secret_iterator(collection).collection
        assert len(pending) == 1
        assert pending[0].audit_metadata['status'] == v1_6.STATUS_NEEDS_REVIEW

        header = format_audit_evidence(secret)
        assert 'needs_review' in header
        assert 'team-a' in header and 'team-b' in header
        assert OLD_HASH_A in header and NEW_HASH in header

    def test_save_and_reread_preserves_evidence_and_pending_count(self, tmp_path):
        _configure_plugins()
        baseline_a, baseline_b = self._baselines()
        upgraded = v1_6.migrate(
            [baseline_a, baseline_b],
            source_names=['team-a', 'team-b'],
        )
        upgraded['version'] = VERSION

        filename = tmp_path / 'merged.baseline'
        baseline.save_to_file(upgraded, str(filename))

        reread = baseline.load(baseline.load_from_file(str(filename)), str(filename))
        assert len(reread) == 1
        secret = list(reread)[0][1]
        assert secret.is_secret is None
        assert secret.audit_metadata['status'] == v1_6.STATUS_NEEDS_REVIEW
        assert len(get_secret_iterator(reread).collection) == 1

        on_disk = json.loads(filename.read_text())
        identity = f'{FILENAME}:{NEW_HASH}:{SECRET_TYPE}'
        assert 'is_secret' not in on_disk['results'][FILENAME][0]
        assert len(on_disk['audit'][identity]['sources']) == 2

    def test_resolving_conflict_moves_entry_out_of_pending_without_losing_sources(self, tmp_path):
        _configure_plugins()
        baseline_a, baseline_b = self._baselines()
        upgraded = v1_6.migrate(
            [baseline_a, baseline_b],
            source_names=['team-a', 'team-b'],
        )
        upgraded['version'] = VERSION

        collection = baseline.load(upgraded, filename='merged.baseline')
        secret = list(collection)[0][1]
        secret.is_secret = True

        filename = tmp_path / 'resolved.baseline'
        baseline.save_to_file(collection, str(filename))

        reread = baseline.load(baseline.load_from_file(str(filename)), str(filename))
        resolved = list(reread)[0][1]
        assert resolved.is_secret is True
        assert resolved.audit_metadata['status'] == v1_6.STATUS_LABELLED
        assert len(resolved.audit_metadata['sources']) == 2
        assert get_secret_iterator(reread).collection == []


class TestInheritableSingleSource:
    """A control case: one clear source with an unambiguous decision is inherited."""

    def test_single_source_decision_is_inherited_and_not_pending(self):
        _configure_plugins()
        old = _old_baseline(
            'security-team',
            [_entry(OLD_HASH_A, line_number=10, is_secret=False)],
            fingerprint_updates={OLD_HASH_A: NEW_HASH},
        )

        upgraded = v1_6.migrate([old], source_names=['security-team'])
        upgraded['version'] = VERSION

        collection = baseline.load(upgraded, filename='reviewed.baseline')
        secret = list(collection)[0][1]

        assert secret.secret_hash == NEW_HASH
        assert secret.is_secret is False
        assert secret.audit_metadata['status'] == v1_6.STATUS_LABELLED
        assert secret.audit_metadata['sources'][0]['source'] == 'security-team'
        assert get_secret_iterator(collection).collection == []

        # The round trip keeps the inherited decision in the separate audit section.
        reformatted = baseline.format_for_output(collection)
        identity = f'{FILENAME}:{NEW_HASH}:{SECRET_TYPE}'
        assert 'is_secret' not in reformatted['results'][FILENAME][0]
        assert reformatted['audit'][identity]['is_secret'] is False
        assert reformatted['audit'][identity]['status'] == v1_6.STATUS_LABELLED

    def test_unlabelled_single_source_has_no_audit_entry_and_stays_pending(self):
        _configure_plugins()
        old = _old_baseline(
            'security-team',
            [_entry(OLD_HASH_A, line_number=10)],
            fingerprint_updates={OLD_HASH_A: NEW_HASH},
        )

        upgraded = v1_6.migrate([old], source_names=['security-team'])
        upgraded['version'] = VERSION

        assert upgraded[v1_6.AUDIT_SECTION] == {}

        collection = baseline.load(upgraded, filename='fresh.baseline')
        secret = list(collection)[0][1]
        assert secret.is_secret is None
        assert not getattr(secret, 'audit_metadata', None)
        assert len(get_secret_iterator(collection).collection) == 1


class TestInPlaceUpgrade:
    def test_upgrade_function_matches_migrate_for_single_baseline(self):
        old = _old_baseline(
            'security-team',
            [_entry(OLD_HASH_A, line_number=10, is_secret=True)],
            fingerprint_updates={OLD_HASH_A: NEW_HASH},
        )

        v1_6.upgrade(old)

        identity = f'{FILENAME}:{NEW_HASH}:{SECRET_TYPE}'
        assert old['results'][FILENAME][0]['hashed_secret'] == NEW_HASH
        assert 'is_secret' not in old['results'][FILENAME][0]
        assert old[v1_6.AUDIT_SECTION][identity]['status'] == v1_6.STATUS_LABELLED

    def test_identical_decisions_merged_from_two_sources_are_inherited(self):
        baseline_a = _old_baseline(
            'team-a',
            [_entry(OLD_HASH_A, line_number=10, is_secret=True)],
            fingerprint_updates={OLD_HASH_A: NEW_HASH},
        )
        baseline_b = _old_baseline(
            'team-b',
            [_entry(OLD_HASH_B, line_number=12, is_secret=True)],
            fingerprint_updates={OLD_HASH_B: NEW_HASH},
        )

        upgraded = v1_6.migrate(
            [baseline_a, baseline_b],
            source_names=['team-a', 'team-b'],
        )

        identity = f'{FILENAME}:{NEW_HASH}:{SECRET_TYPE}'
        audit_entry = upgraded[v1_6.AUDIT_SECTION][identity]
        assert audit_entry['status'] == v1_6.STATUS_LABELLED
        assert audit_entry['is_secret'] is True
        assert len(audit_entry['sources']) == 2


class TestLegacyLayouts:
    def test_legacy_empty_results_list_upgrades_without_findings(self):
        # Very old baselines stored an empty list instead of a filename->findings mapping.
        old = {
            'version': '0.0.1',
            'plugins_used': [
                {
                    'name': 'AWSKeyDetector',
                },
            ],
            'results': [],
        }

        v1_6.upgrade(old)

        assert old['results'] == {}
        assert old[v1_6.AUDIT_SECTION] == {}

    def test_load_tolerates_legacy_empty_results_list(self):
        _configure_plugins()
        old = {
            'version': '0.0.1',
            'plugins_used': [
                {
                    'name': 'AWSKeyDetector',
                },
            ],
            'results': [],
        }

        collection = baseline.load(old, filename='legacy.baseline')
        assert len(collection) == 0
        assert collection.audit == {}
