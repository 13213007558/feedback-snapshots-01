import os
import shutil
import tempfile
import unittest

from tests.differential import differential


class Asn1ToolsCDifferentialTest(unittest.TestCase):
    """Differential regression: the Python OER/UPER decoders (protocol
    review backend reference) must agree with the generated C decoders
    (device side) on accept/reject, consumed length and decoded fields
    for the SecMsg schema. Crashes are never counted as agreement."""

    build_dir = None
    divergences = None

    @classmethod
    def setUpClass(cls):
        if shutil.which('cc') is None:
            raise unittest.SkipTest('no C compiler available')

        cls.build_dir = tempfile.mkdtemp(prefix='asn1tools-c-differential-')
        cls.divergences = differential.run_regression(cls.build_dir)

    @classmethod
    def tearDownClass(cls):
        if cls.build_dir is None:
            return

        if cls.divergences:
            # Keep the failing build dir and copy the divergence records
            # (minimal schema + minimal input bytes + both outcomes)
            # next to the schema for inspection.
            persistent = os.path.join(differential.HERE, 'divergences')

            if os.path.isdir(persistent):
                shutil.rmtree(persistent)

            shutil.copytree(os.path.join(cls.build_dir, 'divergences'),
                            persistent)
            print('divergence records kept in {}'.format(persistent))
        else:
            shutil.rmtree(cls.build_dir, ignore_errors=True)

    def assert_no_divergences(self, codec):
        divergences = [record for record in self.divergences
                       if record['codec'] == codec]

        if divergences:
            kinds = {}

            for record in divergences:
                kinds[record['kind']] = kinds.get(record['kind'], 0) + 1

            first = divergences[0]
            self.fail(
                '{} {} divergence(s) between Python and C decoders '
                '({}); first: {} {} input {}'.format(
                    len(divergences),
                    codec,
                    ', '.join('{}x {}'.format(count, kind)
                              for kind, count in sorted(kinds.items())),
                    first['label'],
                    first['kind'],
                    first['input_hex']))

    def test_oer_python_matches_c(self):
        self.assert_no_divergences('oer')

    def test_uper_python_matches_c(self):
        self.assert_no_divergences('uper')


if __name__ == '__main__':
    unittest.main()
