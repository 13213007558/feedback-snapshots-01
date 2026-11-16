"""Differential regression between the asn1tools Python decoders and the
generated C decoders (OER and UPER) for the SecMsg schema.

The protocol review backend decodes security messages with the asn1tools
Python codecs, while devices decode them with the generated C decoders.
This module feeds both sides the same finite, seeded corpus of valid,
truncated, mutated and random inputs and checks that

* both sides accept or reject the same inputs,
* both sides report the same consumed length on accept, and
* both sides produce the same fields, which for valid seeds are also
  checked against the independently known expected fields.

Only the intersection of semantics implemented by both decoders is
compared (see secmsg.asn for the feature intersection: constrained
integers, nested CHOICE, variable-length arrays and optional fields,
for both OER and UPER):

* The generated C decoder enforces only what must fit its fixed-size
  destination structs: SEQUENCE OF element counts beyond the array
  capacity and variable OCTET STRING lengths beyond the buffer size
  are rejected. c_capacity_ok() mirrors exactly those checks.
* The C decoder does NOT enforce ASN.1 integer ranges or SIZE
  minimums on decode (e.g. it accepts 137 for INTEGER (0..3) in OER),
  so value-range validation is outside the compared intersection and
  remains the backend's own responsibility.

A crash on either side is never counted as agreement; two crashing sides
are recorded as a "both-crash" divergence. Every divergence is stored
with the minimal reproducing input bytes, a copy of the (already minimal)
schema and both outcomes.
"""

import json
import os
import random
import shutil
import subprocess

import asn1tools
from asn1tools.source import c as c_generator

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA_PATH = os.path.join(HERE, 'secmsg.asn')
HARNESS_TEMPLATE_PATH = os.path.join(HERE, 'harness.c.tmpl')
TYPE_NAME = 'SecMsg'
CODECS = ('oer', 'uper')

# Finite corpus sizes. Every case is derived from these seeds, so the
# corpus is fully deterministic.
NUM_VALID_SEEDS = 25
NUM_MUTATIONS_PER_VALID = 5
NUM_ALL_PREFIX_TRUNCATION_SEEDS = 6
NUM_RANDOM_SEEDS = 15

DECODE_TIMEOUT = 10
BATCH_TIMEOUT = 120
MAX_MINIMIZE_ROUNDS = 200


def normalize(value):
    """Convert an asn1tools decoded value to a JSON-comparable structure.

    CHOICE values (2-tuples) become {"choice": name, "value": ...} and
    octet strings become hex strings, matching the C harness output.
    """

    if isinstance(value, bytes):
        return value.hex()

    if isinstance(value, tuple):
        return {'choice': value[0], 'value': normalize(value[1])}

    if isinstance(value, dict):
        return {key: normalize(item) for key, item in value.items()}

    if isinstance(value, list):
        return [normalize(item) for item in value]

    return value


def _random_bytes(rng, length):
    return bytes(rng.randrange(256) for _ in range(length))


def generate_valid_value(rng):
    """Generate a random schema-conforming SecMsg value."""

    value = {
        'version': rng.randint(0, 7),
        'msgId': rng.randint(0, 0xffffffff),
        'body': _generate_body(rng)
    }

    if rng.random() < 0.5:
        value['trustAnchor'] = _random_bytes(rng, 8)

    if rng.random() < 0.5:
        value['priority'] = rng.randint(0, 255)

    return value


def _generate_body(rng):
    kind = rng.choice(['signedData', 'plain', 'control'])

    if kind == 'signedData':
        return (kind, {
            'signerDigest': _random_bytes(rng, 8),
            'signature': _random_bytes(rng, 4),
            'content': _generate_content(rng)
        })

    if kind == 'plain':
        return (kind, {
            'recipients': [rng.randint(0, 65535)
                           for _ in range(rng.randint(0, 4))],
            'urgent': rng.random() < 0.5
        })

    return (kind, {
        'command': rng.randint(0, 3),
        'params': [{
            'key': rng.randint(0, 255),
            'value': rng.randint(-32768, 32767)
        } for _ in range(rng.randint(1, 3))]
    })


def _generate_content(rng):
    kind = rng.choice(['text', 'raw', 'empty'])

    if kind == 'text':
        return (kind, _random_bytes(rng, rng.randint(1, 8)))

    if kind == 'raw':
        return (kind, _random_bytes(rng, 2))

    return (kind, rng.random() < 0.5)


def mutate(rng, data):
    """Return a mutated copy of data (truncation, bit flips, byte
    writes, insertion, deletion or trailing garbage)."""

    if not data:
        return _random_bytes(rng, rng.randint(1, 4))

    choice = rng.randrange(6)
    mutated = bytearray(data)

    if choice == 0:
        # Truncate; malformed prefixes must be rejected, never decoded
        # into default values.
        return bytes(mutated[:rng.randrange(len(mutated))])

    if choice == 1:
        for _ in range(rng.randint(1, 4)):
            mutated[rng.randrange(len(mutated))] ^= 1 << rng.randrange(8)
    elif choice == 2:
        for _ in range(rng.randint(1, 3)):
            mutated[rng.randrange(len(mutated))] = rng.choice(
                [0x00, 0xff, rng.randrange(256)])
    elif choice == 3:
        mutated.insert(rng.randrange(len(mutated) + 1), rng.randrange(256))
    elif choice == 4:
        del mutated[rng.randrange(len(mutated))]
    else:
        mutated.extend(_random_bytes(rng, rng.randint(1, 4)))

    return bytes(mutated)


def generate_corpus(spec):
    """Build the deterministic corpus.

    Returns a list of (label, data, expected) tuples. expected is None
    for mutated/random inputs, otherwise a dict with the independently
    known 'fields' and 'consumed' (the full encoded length).
    """

    cases = []

    for seed in range(NUM_VALID_SEEDS):
        rng = random.Random('valid-{}'.format(seed))
        value = generate_valid_value(rng)
        data = spec.encode(TYPE_NAME, value)
        expected = {'fields': normalize(value), 'consumed': len(data)}
        cases.append(('valid-{}'.format(seed), data, expected))

        for index in range(NUM_MUTATIONS_PER_VALID):
            mutation_rng = random.Random('mut-{}-{}'.format(seed, index))
            cases.append(('mut-{}-{}'.format(seed, index),
                          mutate(mutation_rng, data),
                          None))

        if seed < NUM_ALL_PREFIX_TRUNCATION_SEEDS:
            for length in range(len(data)):
                cases.append(('trunc-{}-{}'.format(seed, length),
                              data[:length],
                              None))

    for seed in range(NUM_RANDOM_SEEDS):
        rng = random.Random('rand-{}'.format(seed))
        cases.append(('rand-{}'.format(seed),
                      _random_bytes(rng, rng.randint(0, 24)),
                      None))

    return cases


class CHarness(object):
    """Builds and runs the generated C decoder for one codec."""

    def __init__(self, codec, build_dir):
        self.codec = codec
        self.namespace = 'secmsg_' + codec
        self.build_dir = build_dir
        self.executable = os.path.join(build_dir,
                                       self.namespace + '_harness')

    def build(self):
        compiled = asn1tools.compile_files([SCHEMA_PATH], self.codec)
        header, source, _, _ = c_generator.generate(
            compiled,
            self.codec,
            self.namespace,
            self.namespace + '.h',
            self.namespace + '.c',
            self.namespace + '_fuzzer.c')

        self._write(self.namespace + '.h', header)
        self._write(self.namespace + '.c', source)

        with open(HARNESS_TEMPLATE_PATH) as fin:
            harness = fin.read().replace('@NS@', self.namespace)

        harness_name = self.namespace + '_harness.c'
        self._write(harness_name, harness)

        base_cmd = [
            'cc', '-std=c99', '-Wall', '-Wextra', '-Werror', '-O1',
            '-I', self.build_dir,
            os.path.join(self.build_dir, self.namespace + '.c'),
            os.path.join(self.build_dir, harness_name),
            '-o', self.executable
        ]

        try:
            self._compile(base_cmd + ['-fsanitize=address,undefined'])
        except subprocess.CalledProcessError:
            # Sanitizers unavailable; a plain build still checks
            # accept/reject, consumed length and fields.
            self._compile(base_cmd)

    def _write(self, name, content):
        with open(os.path.join(self.build_dir, name), 'w') as fout:
            fout.write(content)

    @staticmethod
    def _compile(command):
        subprocess.run(command,
                       check=True,
                       stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)

    def decode(self, data):
        """Decode data with the C decoder. Returns an outcome dict with
        status 'ok', 'reject' or 'crash'."""

        try:
            proc = subprocess.run([self.executable, data.hex()],
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE,
                                  timeout=DECODE_TIMEOUT)
        except subprocess.TimeoutExpired:
            return {'status': 'crash', 'detail': 'timeout'}

        outcomes = self._parse_run(proc, 1)

        if outcomes is None:
            return {'status': 'crash', 'detail': 'unexpected output'}

        return outcomes[0]

    def decode_batch(self, datas):
        """Decode many inputs in one harness process (one hex line per
        input). If the batch crashes or desynchronizes, fall back to
        per-case processes so the crashing input is identified; a crash
        is never counted as agreement."""

        if not datas:
            return []

        payload = ''.join(data.hex() + '\n' for data in datas)

        try:
            proc = subprocess.run([self.executable],
                                  input=payload.encode('ascii'),
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE,
                                  timeout=BATCH_TIMEOUT)
        except subprocess.TimeoutExpired:
            return [self.decode(data) for data in datas]

        outcomes = self._parse_run(proc, len(datas))

        if outcomes is None or len(outcomes) != len(datas):
            return [self.decode(data) for data in datas]

        return outcomes

    @staticmethod
    def _parse_run(proc, expected):
        if proc.returncode != 0:
            detail = 'exit code {}, stderr: {}'.format(
                proc.returncode,
                proc.stderr.decode('utf-8', 'replace')[:200])

            if expected == 1:
                return [{'status': 'crash', 'detail': detail}]

            return None

        lines = proc.stdout.decode('utf-8').splitlines()

        if len(lines) != expected:
            return None

        outcomes = []

        for line in lines:
            try:
                outcome = json.loads(line)
            except ValueError:
                outcome = None

            if (not isinstance(outcome, dict)
                    or outcome.get('status') not in ('ok', 'reject')):
                if expected == 1:
                    return [{'status': 'crash',
                             'detail': 'invalid output: {!r}'.format(line[:200])}]

                return None

            outcomes.append(outcome)

        return outcomes


def c_capacity_ok(decoded):
    """Mirror the structural limits enforced by the generated C structs.

    The generated C decoder rejects exactly what does not fit its
    fixed-size destination structs: SEQUENCE OF element counts beyond
    the array capacity and variable OCTET STRING lengths beyond the
    buffer size. It does not enforce ASN.1 integer ranges or SIZE
    minimums, so those are outside the compared intersection. The
    limits below must stay in sync with secmsg.asn.
    """

    body_choice, body = decoded['body']

    if body_choice == 'signedData':
        content_choice, content = body['content']

        if content_choice == 'text' and len(content) > 8:
            return False
    elif body_choice == 'plain':
        if len(body['recipients']) > 4:
            return False
    else:
        if len(body['params']) > 3:
            return False

    return True


def python_decode(spec, data):
    """Decode data with the Python decoder. Returns an outcome dict.

    Schema constraint checking is intentionally NOT enabled: the
    generated C decoder only enforces the structural capacity of its
    output structs, so the comparable intersection is wire-format
    decoding plus those capacity limits (mirrored by c_capacity_ok()).
    The consumed length is derived by re-encoding the decoded value:
    OER and UPER are deterministic prefix-free encodings, so a
    successful decode consumes exactly the canonical encoding length.
    """

    try:
        decoded = spec.decode(TYPE_NAME, data)
    except (asn1tools.DecodeError, asn1tools.ConstraintsError):
        return {'status': 'reject'}
    except Exception as error:
        return {'status': 'crash',
                'detail': '{}: {}'.format(type(error).__name__, error)}

    if not c_capacity_ok(decoded):
        return {'status': 'reject'}

    try:
        consumed = len(spec.encode(TYPE_NAME, decoded))
    except Exception as error:
        return {'status': 'crash',
                'detail': 're-encode failed: {}: {}'.format(
                    type(error).__name__, error)}

    return {
        'status': 'ok',
        'consumed': consumed,
        'fields': normalize(decoded)
    }


def classify(python, c, expected):
    """Compare both outcomes. Returns a divergence kind or None."""

    python_crashed = python['status'] == 'crash'
    c_crashed = c['status'] == 'crash'

    if python_crashed and c_crashed:
        return 'both-crash'

    if python_crashed:
        return 'python-crash'

    if c_crashed:
        return 'c-crash'

    if python['status'] != c['status']:
        return 'accept-mismatch'

    if python['status'] == 'reject':
        return None

    if python['consumed'] != c['consumed']:
        return 'consumed-mismatch'

    if python['fields'] != c['fields']:
        return 'fields-mismatch'

    if expected is not None:
        if python['fields'] != expected['fields']:
            return 'python-fields-vs-expected'

        if c['fields'] != expected['fields']:
            return 'c-fields-vs-expected'

        if python['consumed'] != expected['consumed']:
            return 'python-consumed-vs-expected'

        if c['consumed'] != expected['consumed']:
            return 'c-consumed-vs-expected'

    return None


def minimize(data, kind, evaluate):
    """Greedily shrink data while evaluate() still reports the same
    divergence kind. Returns the minimal reproducing bytes."""

    def reproduces(candidate):
        if candidate == data:
            return True

        return evaluate(candidate) == kind

    rounds = 0
    chunk = max(1, len(data) // 2)

    while chunk >= 1 and len(data) > 1 and rounds < MAX_MINIMIZE_ROUNDS:
        offset = 0
        changed = False

        while offset < len(data) and rounds < MAX_MINIMIZE_ROUNDS:
            candidate = data[:offset] + data[offset + chunk:]
            rounds += 1

            if candidate and reproduces(candidate):
                data = candidate
                changed = True
            else:
                offset += chunk

        if not changed:
            chunk //= 2

    return data


def run_regression(build_dir, divergences_dir=None, codecs=CODECS,
                   progress=None):
    """Run the differential regression. Returns a list of divergence
    records. Records are also written to divergences_dir (defaults to
    <build_dir>/divergences) as one JSON file per divergence, each with
    the minimal reproducing bytes, plus a copy of the minimal schema."""

    os.makedirs(build_dir, exist_ok=True)

    if divergences_dir is None:
        divergences_dir = os.path.join(build_dir, 'divergences')

    if os.path.isdir(divergences_dir):
        shutil.rmtree(divergences_dir)

    specs = {
        codec: asn1tools.compile_files([SCHEMA_PATH], codec)
        for codec in codecs
    }
    harnesses = {}

    for codec in codecs:
        harness = CHarness(codec, build_dir)
        harness.build()
        harnesses[codec] = harness

    divergences = []

    for codec in codecs:
        spec = specs[codec]
        harness = harnesses[codec]
        cases = generate_corpus(spec)
        c_outcomes = harness.decode_batch([data for _, data, _ in cases])

        def evaluate(data, spec=spec, harness=harness):
            python = python_decode(spec, data)
            c = harness.decode(data)

            return classify(python, c, None)

        for (label, data, expected), c in zip(cases, c_outcomes):
            python = python_decode(spec, data)
            kind = classify(python, c, expected)

            if kind is None:
                continue

            if kind.endswith('-vs-expected'):
                # Expected-value mismatches compare against the seed
                # value, not between decoders; shrinking adds nothing.
                minimal = data
            else:
                minimal = minimize(data, kind, evaluate)
            record = {
                'label': label,
                'codec': codec,
                'kind': kind,
                'input_hex': minimal.hex(),
                'input_length': len(minimal),
                'python': (python if minimal == data
                           else python_decode(spec, minimal)),
                'c': c if minimal == data else harness.decode(minimal),
                'expected': expected
            }
            divergences.append(record)

            if progress is not None:
                progress(record)

    if divergences:
        os.makedirs(divergences_dir, exist_ok=True)
        shutil.copyfile(SCHEMA_PATH,
                        os.path.join(divergences_dir, 'secmsg.asn'))

        for index, record in enumerate(divergences):
            path = os.path.join(
                divergences_dir,
                '{}-{}-{}.json'.format(index, record['codec'], record['label']))

            with open(path, 'w') as fout:
                json.dump(record, fout, indent=2, sort_keys=True)

    return divergences


def main():
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir',
                        default=None,
                        help='Where to put generated C and binaries '
                             '(default: a temporary directory).')
    parser.add_argument('--divergences-dir',
                        default=None,
                        help='Where to write divergence records '
                             '(default: <build-dir>/divergences).')
    args = parser.parse_args()

    build_dir = args.build_dir

    if build_dir is None:
        import tempfile
        build_dir = tempfile.mkdtemp(prefix='secmsg-diff-')

    def report(record):
        print('DIVERGENCE {} {} {}: {}'.format(record['codec'],
                                               record['label'],
                                               record['kind'],
                                               record['input_hex']))

    divergences = run_regression(build_dir,
                                 divergences_dir=args.divergences_dir,
                                 progress=report)

    print('build dir: {}'.format(build_dir))

    if divergences:
        print('{} divergence(s) found; records in {}'.format(
            len(divergences),
            args.divergences_dir or os.path.join(build_dir, 'divergences')))

        return 1

    print('no divergences')

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
