import contextlib
import io
import json
import os
import tempfile
import unittest

from flower import recovery_demo


class RecoveryDemoTests(unittest.TestCase):
    def run_demo(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(0, recovery_demo.main(list(args)))
        return out.getvalue()

    def test_demo_reports_the_three_startups(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = self.run_demo('--dir', tmpdir)

            self.assertIn('startup 1: after a normal save', output)
            self.assertIn('startup 2: after a partial save', output)
            self.assertIn('startup 3: tightened admission', output)
            self.assertIn('selected source: generation (generation 1)', output)
            self.assertIn('manifest is missing: the generation was never completed',
                          output)
            self.assertIn('is below the admitted minimum 2', output)

            report_path = os.path.join(tmpdir, 'flower.recovery', 'latest.json')
            self.assertTrue(os.path.isfile(report_path))
            with open(report_path, encoding='utf-8') as f:
                report = json.load(f)
            self.assertEqual('fresh', report['selected']['source'])
            self.assertEqual(0, report['retrieval']['task_count'])
            statuses = {(c['source'], c['status']) for c in report['candidates']}
            self.assertIn(('generation', 'rejected'), statuses)
            self.assertIn(('staging', 'rejected'), statuses)

    def test_demo_can_start_from_a_legacy_shelf(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = self.run_demo('--dir', tmpdir, '--from-legacy')

            self.assertIn('startup 0: legacy shelf', output)
            self.assertIn('selected source: legacy', output)
            self.assertIn('startup 1: after a normal save', output)
            self.assertIn('selected source: generation (generation 1)', output)
            self.assertIn('legacy dbm shelf', output)

    def test_each_startup_appends_a_record(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            self.run_demo('--dir', tmpdir)
            history = os.path.join(tmpdir, 'flower.recovery', 'recovery.jsonl')
            with open(history, encoding='utf-8') as f:
                records = [json.loads(line) for line in f if line.strip()]

            self.assertEqual(4, len(records))
            self.assertEqual(
                ['no checkpoint present',
                 'highest admitted generation',
                 'highest admitted generation',
                 'no checkpoint passed admission'],
                [record['selected']['reason'] for record in records])
            # Every record describes the same task/index/counter source.
            for record in records:
                retrieval = record['retrieval']
                self.assertEqual('state', retrieval['source'])
                self.assertEqual(retrieval['task_count'],
                                 retrieval['indexed_task_count'])


if __name__ == '__main__':
    unittest.main()
