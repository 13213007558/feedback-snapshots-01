#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
from copy import copy
from copy import deepcopy

from .utils import Asn1ToolsBaseTest
import asn1tools
from asn1tools.codecs import unknown_extensions


NEW_SEQUENCE = '''
Foo DEFINITIONS AUTOMATIC TAGS ::= BEGIN
V ::= SEQUENCE {
  a BOOLEAN,
  ...,
  u0 OCTET STRING (SIZE (0..10)),
  u1 OCTET STRING (SIZE (0..10)),
  [[ k0 INTEGER (0..255) ]],
  u3 OCTET STRING (SIZE (0..10)),
  u4 OCTET STRING (SIZE (0..10))
}
END
'''

OLD_SEQUENCE = '''
Foo DEFINITIONS AUTOMATIC TAGS ::= BEGIN
V ::= SEQUENCE {
  a BOOLEAN,
  ...
}
END
'''

NEW_CHOICE = '''
Foo DEFINITIONS AUTOMATIC TAGS ::= BEGIN
C ::= CHOICE {
  a BOOLEAN,
  ...,
  b BOOLEAN,
  c INTEGER
}
END
'''

OLD_CHOICE = '''
Foo DEFINITIONS AUTOMATIC TAGS ::= BEGIN
C ::= CHOICE {
  a BOOLEAN,
  ...
}
END
'''


class Asn1ToolsUnknownExtensionTest(Asn1ToolsBaseTest):

    maxDiff = None

    codecs = ['per', 'uper']

    def relay(self, codec, new_spec, old_spec, type_name, data):
        encoded = new_spec.encode(type_name, data)
        decoded = old_spec.decode(type_name,
                                  encoded,
                                  preserve_unknown_extensions=True)
        forwarded = old_spec.encode(type_name,
                                    decoded,
                                    preserve_unknown_extensions=True)

        return encoded, decoded, forwarded

    def test_sequence_unknown_between_known(self):
        for codec in self.codecs:
            new_spec = asn1tools.compile_string(NEW_SEQUENCE, codec)
            old_spec = asn1tools.compile_string(OLD_SEQUENCE, codec)
            data = {
                'a': True,
                'u0': b'A',
                'u1': b'BB',
                'k0': 9,
                'u3': b'CCC',
                'u4': b'DDDD'
            }

            encoded, decoded, forwarded = self.relay(codec,
                                                     new_spec,
                                                     old_spec,
                                                     'V',
                                                     data)

            # The old schema exposes only its root member. Unknown
            # extensions must not appear as known/verified fields.
            self.assertEqual(
                dict((key, value)
                     for key, value in decoded.items()
                     if key != unknown_extensions.UNKNOWN_EXTENSIONS_KEY),
                {'a': True})
            self.assertEqual(decoded.can_resend_unknown_extensions(), True)
            self.assertEqual(forwarded, encoded)
            self.assertEqual(new_spec.decode('V', forwarded), data)

            metadata = decoded.unknown_extensions
            self.assertEqual([entry.index for entry in metadata],
                             [0, 1, 2, 3, 4])
            self.assertEqual([entry.verified for entry in metadata],
                             [False, False, False, False, False])
            self.assertEqual(metadata.presence_length, 5)

            for entry in metadata:
                self.assertEqual(entry['index'], entry.index)
                self.assertEqual(entry['open_type'], entry.data)
                self.assertEqual(entry['raw'], entry.data)
                self.assertIsNotNone(entry['alignment_bits'])

    def test_known_extension_index_conflict_is_not_verified(self):
        new_spec_string = '''
Foo DEFINITIONS AUTOMATIC TAGS ::= BEGIN
V ::= SEQUENCE {
  a BOOLEAN,
  ...,
  new1 ENUMERATED { zero, one },
  new2 INTEGER (0..255)
}
END
'''
        old_spec_string = '''
Foo DEFINITIONS AUTOMATIC TAGS ::= BEGIN
V ::= SEQUENCE {
  a BOOLEAN,
  ...,
  new1 ENUMERATED { zero, one }
}
END
'''
        for codec in self.codecs:
            new_spec = asn1tools.compile_string(new_spec_string, codec)
            old_spec = asn1tools.compile_string(old_spec_string, codec)
            data = {'a': True, 'new1': 'one', 'new2': 7}
            encoded = new_spec.encode('V', data)
            decoded = old_spec.decode('V',
                                      encoded,
                                      preserve_unknown_extensions=True)

            # Additions are open types, so the old schema's ENUMERATED
            # cannot claim the new INTEGER payload is a verified value.
            self.assertNotIn('new1', decoded)
            entry = decoded.unknown_extensions[0]
            self.assertEqual(entry.index, 0)
            self.assertEqual(entry.kind, 'conflicting-known-addition')
            self.assertEqual(entry.verified, False)
            self.assertEqual(
                old_spec.encode('V',
                                decoded,
                                preserve_unknown_extensions=True),
                encoded)
            self.assertEqual(new_spec.decode('V', encoded), data)

    def test_known_addition_then_unknown_additions(self):
        new_spec_string = '''
Foo DEFINITIONS AUTOMATIC TAGS ::= BEGIN
V ::= SEQUENCE {
  a BOOLEAN,
  ...,
  [[ k0 INTEGER (0..255) ]],
  u1 OCTET STRING (SIZE (0..10)),
  u2 OCTET STRING (SIZE (0..10))
}
END
'''
        old_spec_string = '''
Foo DEFINITIONS AUTOMATIC TAGS ::= BEGIN
V ::= SEQUENCE {
  a BOOLEAN,
  ...,
  [[ k0 INTEGER (0..255) ]]
}
END
'''
        for codec in self.codecs:
            new_spec = asn1tools.compile_string(new_spec_string, codec)
            old_spec = asn1tools.compile_string(old_spec_string, codec)
            data = {'a': True, 'k0': 5, 'u1': b'X', 'u2': b'YZ'}
            encoded = new_spec.encode('V', data)
            decoded = old_spec.decode('V',
                                      encoded,
                                      preserve_unknown_extensions=True)

            self.assertEqual(decoded['k0'], 5)
            self.assertEqual([entry.index for entry in
                              decoded.unknown_extensions],
                             [1, 2])
            self.assertEqual(decoded.unknown_extensions.presence_length, 3)
            self.assertEqual(
                old_spec.encode('V',
                                decoded,
                                preserve_unknown_extensions=True),
                encoded)
            self.assertEqual(new_spec.decode('V', encoded), data)

    def test_unknown_sequence_nested_in_known_addition(self):
        new_spec_string = '''
Foo DEFINITIONS AUTOMATIC TAGS ::= BEGIN
V ::= SEQUENCE {
  a BOOLEAN,
  ...,
  [[ g SEQUENCE {
       b BOOLEAN,
       ...,
       x OCTET STRING (SIZE (0..10))
     }
  ]]
}
END
'''
        old_spec_string = '''
Foo DEFINITIONS AUTOMATIC TAGS ::= BEGIN
V ::= SEQUENCE {
  a BOOLEAN,
  ...,
  [[ g SEQUENCE {
       b BOOLEAN,
       ...
     }
  ]]
}
END
'''
        for codec in self.codecs:
            new_spec = asn1tools.compile_string(new_spec_string, codec)
            old_spec = asn1tools.compile_string(old_spec_string, codec)
            data = {'a': True, 'g': {'b': False, 'x': b'nested'}}
            encoded = new_spec.encode('V', data)
            decoded = old_spec.decode('V',
                                      encoded,
                                      preserve_unknown_extensions=True)

            if 'g' in decoded:
                # Known addition could be decoded in isolation.
                self.assertEqual(decoded['g']['b'], False)
                self.assertNotIn('x', decoded['g'])
                nested = decoded['g'].unknown_extensions
                self.assertEqual(len(nested), 1)
                self.assertEqual(nested[0].index, 0)
            else:
                # The codec cannot isolate this addition safely. It is
                # forwarded as opaque open type content and is not
                # exposed as a verified known field.
                entry = decoded.unknown_extensions[0]
                self.assertEqual(entry.index, 0)
                self.assertEqual(entry.kind, 'conflicting-known-addition')

            self.assertEqual(
                old_spec.encode('V',
                                decoded,
                                preserve_unknown_extensions=True),
                encoded)

            # Editing a known field inside the same known addition
            # invalidates forwarding when that addition was decoded.
            edited = old_spec.decode('V',
                                     encoded,
                                     preserve_unknown_extensions=True)
            if 'g' in edited:
                edited['g']['b'] = True
                self.assertEqual(
                    edited.can_resend_unknown_extensions(), False)

                with self.assertRaises(asn1tools.EncodeError):
                    old_spec.encode('V',
                                    edited,
                                    preserve_unknown_extensions=True)

            self.assertEqual(new_spec.decode('V', encoded), data)

    def test_unknown_choice_alternative(self):
        for codec in self.codecs:
            new_spec = asn1tools.compile_string(NEW_CHOICE, codec)
            old_spec = asn1tools.compile_string(OLD_CHOICE, codec)

            for value in [('b', True), ('c', 42)]:
                encoded = new_spec.encode('C', value)
                decoded = old_spec.decode('C',
                                          encoded,
                                          preserve_unknown_extensions=True)

                self.assertIsNone(decoded[0])
                marker = decoded[1]
                self.assertIsInstance(
                    marker,
                    unknown_extensions.UnknownChoiceExtension)
                self.assertEqual(marker.verified, False)
                self.assertEqual(marker['data'], marker.data)
                self.assertEqual(
                    old_spec.encode('C',
                                    decoded,
                                    preserve_unknown_extensions=True),
                    encoded)
                self.assertEqual(new_spec.decode('C', encoded), value)

            # Mutating the opaque marker is rejected.
            decoded = old_spec.decode('C',
                                      encoded,
                                      preserve_unknown_extensions=True)
            decoded[1].data = b'\x00'
            self.assertEqual(
                unknown_extensions.unknown_extensions_can_resend(decoded),
                False)

            # Closed mode keeps the historical (None, None) result.
            encoded = new_spec.encode('C', ('b', True))
            self.assertEqual(old_spec.decode('C', encoded), (None, None))

    def test_unknown_addition_inside_known_choice_branch(self):
        new_spec_string = '''
Foo DEFINITIONS AUTOMATIC TAGS ::= BEGIN
C ::= CHOICE {
  a BOOLEAN,
  ...,
  s SEQUENCE {
    b BOOLEAN,
    ...,
    x OCTET STRING (SIZE (0..10))
  }
}
END
'''
        old_spec_string = '''
Foo DEFINITIONS AUTOMATIC TAGS ::= BEGIN
C ::= CHOICE {
  a BOOLEAN,
  ...,
  s SEQUENCE {
    b BOOLEAN,
    ...
  }
}
END
'''
        for codec in self.codecs:
            new_spec = asn1tools.compile_string(new_spec_string, codec)
            old_spec = asn1tools.compile_string(old_spec_string, codec)
            data = ('s', {'b': True, 'x': b'hi'})
            encoded = new_spec.encode('C', data)
            decoded = old_spec.decode('C',
                                      encoded,
                                      preserve_unknown_extensions=True)

            self.assertEqual(decoded[0], 's')
            self.assertEqual(decoded[1]['b'], True)
            self.assertNotIn('x', decoded[1])
            self.assertEqual(
                unknown_extensions.unknown_extensions_can_resend(decoded),
                True)
            self.assertEqual(
                old_spec.encode('C',
                                decoded,
                                preserve_unknown_extensions=True),
                encoded)
            self.assertEqual(new_spec.decode('C', encoded), data)

    def test_resend_requires_unchanged_known_fields(self):
        for codec in self.codecs:
            new_spec = asn1tools.compile_string(NEW_SEQUENCE, codec)
            old_spec = asn1tools.compile_string(OLD_SEQUENCE, codec)
            encoded = new_spec.encode('V', {'a': True, 'u0': b'x'})
            decoded = old_spec.decode('V',
                                      encoded,
                                      preserve_unknown_extensions=True)

            for altered in [copy(decoded), deepcopy(decoded)]:
                self.assertEqual(
                    altered.can_resend_unknown_extensions(), True)

            decoded['a'] = False
            self.assertEqual(decoded.can_resend_unknown_extensions(), False)

            with self.assertRaises(asn1tools.EncodeError) as cm:
                old_spec.encode('V',
                                decoded,
                                preserve_unknown_extensions=True)

            self.assertEqual(
                str(cm.exception),
                'Cannot preserve unknown extensions because known fields '
                'have changed since decoding.')

            # Replacing the metadata container is also detected.
            decoded = old_spec.decode('V',
                                      encoded,
                                      preserve_unknown_extensions=True)
            decoded.unknown_extensions[0].data = b'\x00'
            self.assertEqual(decoded.can_resend_unknown_extensions(), False)

    def test_fragmented_open_type(self):
        new_spec_string = '''
Foo DEFINITIONS AUTOMATIC TAGS ::= BEGIN
V ::= SEQUENCE {
  a BOOLEAN,
  ...,
  pad OCTET STRING (SIZE (0..70000))
}
END
'''
        old_spec_string = '''
Foo DEFINITIONS AUTOMATIC TAGS ::= BEGIN
V ::= SEQUENCE {
  a BOOLEAN,
  ...
}
END
'''
        for codec in self.codecs:
            new_spec = asn1tools.compile_string(new_spec_string, codec)
            old_spec = asn1tools.compile_string(old_spec_string, codec)
            data = {'a': True, 'pad': 40000 * b'\x5a'}
            encoded = new_spec.encode('V', data)
            decoded = old_spec.decode('V',
                                      encoded,
                                      preserve_unknown_extensions=True)
            metadata = decoded.unknown_extensions
            self.assertEqual(len(metadata), 1)
            self.assertEqual(metadata[0].index, 0)
            self.assertGreater(len(metadata[0].fragments), 1)
            self.assertGreater(len(metadata[0].data), 16384)

            forwarded = old_spec.encode('V',
                                        decoded,
                                        preserve_unknown_extensions=True)
            self.assertEqual(forwarded, encoded)
            self.assertEqual(new_spec.decode('V', forwarded), data)

    def test_closed_mode_does_not_expose_metadata(self):
        for codec in self.codecs:
            new_spec = asn1tools.compile_string(NEW_SEQUENCE, codec)
            old_spec = asn1tools.compile_string(OLD_SEQUENCE, codec)
            encoded = new_spec.encode('V', {'a': True, 'u0': b'x'})
            decoded = old_spec.decode('V', encoded)

            self.assertFalse(
                unknown_extensions.has_unknown_extensions(decoded))
            self.assertNotIn(unknown_extensions.UNKNOWN_EXTENSIONS_KEY,
                             decoded)
            self.assertEqual(
                unknown_extensions.unknown_extensions_can_resend(decoded),
                True)

            # Unknown CHOICE alternatives remain (None, None).
            old_choice = asn1tools.compile_string(OLD_CHOICE, codec)
            new_choice = asn1tools.compile_string(NEW_CHOICE, codec)
            self.assertEqual(
                old_choice.decode('C', new_choice.encode('C', ('b', True))),
                (None, None))


if __name__ == '__main__':
    unittest.main()
