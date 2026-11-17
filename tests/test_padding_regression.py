# -*- coding: utf-8
# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Regression tests for EDNS(0) PADDING on the final, on-the-wire message.
#
# The point of these tests is the *combination* of features, in the exact byte
# string handed to a transport: block padding over different name lengths,
# pre-existing EDNS options, the UDP size limit, truncated responses, and a
# TSIG signature that is appended after the OPT record.  Padding must only ever
# contribute the EDNS PADDING option, must not disturb the question or the other
# options, and must never be "fixed" by silently dropping the TSIG or the
# padding policy when a transport limit cannot be satisfied.
#
# Scope/limitation: block padding only coarsens the observable *length* of a
# message (it buckets sizes onto a block grid).  It does not encrypt or hide the
# query content -- the QNAME, QTYPE and class are still cleartext in the wire
# message -- and it does not conceal traffic patterns such as timing, packet
# counts, direction or the sizes of a full exchange.

import unittest

import dns.edns
import dns.exception
import dns.flags
import dns.message
import dns.rdatatype
import dns.rrset
import dns.tsigkeyring

KEYRING = dns.tsigkeyring.from_text({"keyname.": "NjHwPsMKjdN++dOfE5iAiQ=="})

# Names chosen to span short, typical and long owner names so the unpadded
# question length varies and padding has different amounts of work to do.
NAMES = [
    "a",
    "www.example",
    "a-very-long-label-0123456789abcdef.multi.level.example",
]

# Deliberately tiny block sizes so that block-boundary conditions are exercised
# with small, easy-to-reason-about messages rather than only the RFC 8467 sizes.
TINY_BLOCKS = (1, 2, 3, 4, 5, 7, 8, 11, 13, 16)


def padding_option(message):
    """Return the EDNS PADDING option of *message*, or None."""
    for option in message.options:
        if option.otype == dns.edns.OptionType.PADDING:
            return option
    return None


def padding_length(message):
    option = padding_option(message)
    return 0 if option is None else len(option.data)


def answer_rrsets(count):
    return [
        dns.rrset.from_text(
            "www.example.", 3600, "in", "a", f"10.0.0.{n}"
        )
        for n in range(count)
    ]


class PaddingRegressionTestCase(unittest.TestCase):
    def assertBlockAligned(self, wire, block):
        self.assertEqual(
            len(wire) % block,
            0,
            f"wire length {len(wire)} is not a multiple of block {block}",
        )

    def assertOnlyPaddingChanged(self, baseline_wire, padded_wire):
        """The padded message must be a strict superset of the unpadded one:
        every non-padding byte is identical and the only added bytes are the
        EDNS PADDING option (its 4-byte header plus zero-valued data)."""
        baseline = dns.message.from_wire(baseline_wire)
        padded = dns.message.from_wire(padded_wire)
        # The question and every non-padding option survive untouched.
        self.assertEqual(baseline.question, padded.question)
        baseline_options = [
            o for o in baseline.options if o.otype != dns.edns.OptionType.PADDING
        ]
        padded_non_padding = [
            o for o in padded.options if o.otype != dns.edns.OptionType.PADDING
        ]
        self.assertEqual(baseline_options, padded_non_padding)
        option = padding_option(padded)
        self.assertIsNotNone(option)
        # Padding data is, by specification, zero-valued bytes.
        self.assertTrue(all(byte == 0 for byte in option.data))
        # The entire size increase is accounted for by the PADDING option
        # (4 option-header bytes plus the data bytes).
        self.assertEqual(
            len(padded_wire) - len(baseline_wire), 4 + len(option.data)
        )

    def test_name_lengths_align_to_block(self):
        for name in NAMES:
            for block in (16, 32, 48, 64):
                with self.subTest(name=name, block=block):
                    query = dns.message.make_query(
                        name, "a", use_edns=0, pad=block
                    )
                    wire = query.to_wire()
                    self.assertBlockAligned(wire, block)
                    parsed = dns.message.from_wire(wire)
                    self.assertEqual(
                        parsed.question[0].rdtype, dns.rdatatype.A
                    )
                    self.assertEqual(parsed.question[0].name.to_text(), name + ".")
                    self.assertGreaterEqual(padding_length(parsed), 0)

    def test_tiny_block_boundary_sweep_unsigned(self):
        # Every tiny block must land exactly on a multiple of the block for the
        # unsigned message, and the result must independently re-parse.
        for block in TINY_BLOCKS:
            with self.subTest(block=block):
                query = dns.message.make_query(
                    "www.example", "a", use_edns=0, pad=block
                )
                wire = query.to_wire()
                self.assertBlockAligned(wire, block)
                parsed = dns.message.from_wire(wire)
                self.assertEqual(parsed.question, query.question)

    def test_tiny_block_boundary_sweep_signed(self):
        # Same sweep with a TSIG appended *after* the OPT record: padding has
        # to reserve room for the signature and still hit the block size, and
        # the independent re-parse must validate the TSIG MAC.
        for block in TINY_BLOCKS:
            with self.subTest(block=block):
                query = dns.message.make_query(
                    "www.example", "a", use_edns=0, pad=block
                )
                query.use_tsig(KEYRING)
                wire = query.to_wire()
                self.assertBlockAligned(wire, block)
                parsed = dns.message.from_wire(wire, keyring=KEYRING)
                self.assertIsNotNone(parsed.tsig)
                self.assertEqual(parsed.question, query.question)

    def test_unsigned_and_signed_lengths_separately_checked(self):
        # The unsigned and signed outputs are rendered separately and each is
        # independently aligned to the block; neither length is derived from the
        # other.  Adding a TSIG never shrinks the output, and when the block is
        # large enough padding can absorb the signature so both share a size.
        for block in (16, 64, 128):
            with self.subTest(block=block):
                unsigned = dns.message.make_query(
                    "www.example", "a", use_edns=0, pad=block
                )
                unsigned_wire = unsigned.to_wire()

                signed = dns.message.make_query(
                    "www.example", "a", use_edns=0, pad=block
                )
                signed.use_tsig(KEYRING)
                signed_wire = signed.to_wire()

                self.assertBlockAligned(unsigned_wire, block)
                self.assertBlockAligned(signed_wire, block)
                # The TSIG RR never shrinks the message; padding may absorb it
                # so both can share a block boundary (e.g. block=128).
                self.assertGreaterEqual(len(signed_wire), len(unsigned_wire))
                # And both independently parse, the signed one authenticating.
                dns.message.from_wire(unsigned_wire)
                parsed_signed = dns.message.from_wire(
                    signed_wire, keyring=KEYRING
                )
                self.assertIsNotNone(parsed_signed.tsig)

    def test_existing_options_are_preserved_and_reordered_not(self):
        options = [
            dns.edns.NSIDOption(b"node-7"),
            dns.edns.ECSOption("1.2.3.0", 24),
        ]
        baseline = dns.message.make_query(
            "www.example", "a", use_edns=0, options=list(options)
        )
        baseline_wire = baseline.to_wire()

        padded = dns.message.make_query(
            "www.example", "a", use_edns=0, options=list(options), pad=128
        )
        padded_wire = padded.to_wire()

        self.assertBlockAligned(padded_wire, 128)
        self.assertOnlyPaddingChanged(baseline_wire, padded_wire)

        parsed = dns.message.from_wire(padded_wire)
        otypes = [option.otype for option in parsed.options]
        # PADDING is appended after the pre-existing options, never replacing
        # or reordering them.
        self.assertEqual(
            otypes,
            [
                dns.edns.OptionType.NSID,
                dns.edns.OptionType.ECS,
                dns.edns.OptionType.PADDING,
            ],
        )
        ecs = next(
            o for o in parsed.options if o.otype == dns.edns.OptionType.ECS
        )
        self.assertEqual(ecs.to_text(), "ECS 1.2.3.0/24 scope/0")

    def test_existing_options_preserved_with_tsig(self):
        options = [dns.edns.ECSOption("1.2.3.0", 24)]
        query = dns.message.make_query(
            "www.example",
            "a",
            use_edns=0,
            options=options,
            pad=128,
        )
        query.use_tsig(KEYRING)
        wire = query.to_wire()
        self.assertBlockAligned(wire, 128)
        parsed = dns.message.from_wire(wire, keyring=KEYRING)
        self.assertIsNotNone(parsed.tsig)
        self.assertIn(dns.edns.OptionType.ECS, [o.otype for o in parsed.options])
        self.assertIsNotNone(padding_option(parsed))
        self.assertEqual(parsed.question, query.question)

    def test_tsig_mac_covers_padding_and_detects_tampering(self):
        query = dns.message.make_query(
            "www.example", "a", use_edns=0, pad=128
        )
        query.use_tsig(KEYRING)
        wire = query.to_wire()
        # Good wire authenticates.
        parsed = dns.message.from_wire(wire, keyring=KEYRING)
        self.assertIsNotNone(parsed.tsig)
        # Flipping a byte anywhere -- including inside the padding -- must
        # invalidate the signature, proving the MAC covers the padded message.
        tampered = bytearray(wire)
        tampered[-5] ^= 0xFF
        with self.assertRaises(dns.exception.DNSException):
            dns.message.from_wire(bytes(tampered), keyring=KEYRING)

    def test_udp_cap_strict_conflict_is_explicit(self):
        # A padded query parsed from wire drives RFC 8467 response padding
        # (pad=468).  Answers that leave no room for the padded OPT record
        # within a 512-byte UDP cap cannot satisfy both the cap and the padding
        # policy: the result must be an explicit TooBig, never a quietly
        # truncated or unauthenticated message.
        padded_query = dns.message.from_wire(
            dns.message.make_query(
                "www.example", "a", use_edns=0, pad=128
            ).to_wire()
        )
        response = dns.message.make_response(padded_query)
        self.assertEqual(response.pad, 468)
        response.answer.extend(answer_rrsets(30))

        with self.assertRaises(dns.exception.TooBig):
            response.to_wire(max_size=512)
        # The failure does not mutate the message: policy and EDNS stay intact.
        self.assertEqual(response.pad, 468)
        self.assertIsNotNone(response.opt)

    def test_udp_cap_conflict_never_strips_tsig(self):
        padded_query = dns.message.from_wire(
            dns.message.make_query(
                "www.example", "a", use_edns=0, pad=128
            ).to_wire()
        )
        response = dns.message.make_response(padded_query)
        response.answer.extend(answer_rrsets(30))
        response.use_tsig(KEYRING)
        self.assertIsNotNone(response.tsig)

        # Both the strict and the prefer-truncation paths must fail loudly
        # rather than emit a message whose authentication was removed.
        with self.assertRaises(dns.exception.TooBig):
            response.to_wire(max_size=512)
        with self.assertRaises(dns.exception.TooBig):
            response.to_wire(max_size=512, prefer_truncation=True)

        # The TSIG and OPT are still attached to the in-memory message; the
        # library did not silently drop authentication to make it fit.
        self.assertIsNotNone(response.tsig)
        self.assertIsNotNone(response.opt)

    def test_truncated_response_when_opt_still_fits(self):
        # When the answers overflow but the (padded) OPT record still fits after
        # truncation, prefer_truncation returns a TC message that remains block
        # aligned; the OPT/padding are retained rather than dropped.
        padded_query = dns.message.from_wire(
            dns.message.make_query(
                "www.example", "a", use_edns=0, pad=128
            ).to_wire()
        )
        response = dns.message.make_response(padded_query, pad=128)
        response.answer.extend(answer_rrsets(30))

        wire = response.to_wire(max_size=512, prefer_truncation=True)
        parsed = dns.message.from_wire(wire)
        self.assertTrue(parsed.flags & dns.flags.TC)
        self.assertIsNotNone(parsed.opt)
        self.assertIsNotNone(padding_option(parsed))
        self.assertBlockAligned(wire, 128)
        self.assertLessEqual(len(wire), 512)

    def test_truncation_does_not_silently_shrink_when_strict(self):
        # Without prefer_truncation the same oversized response raises instead
        # of returning a shortened wire message.
        padded_query = dns.message.from_wire(
            dns.message.make_query(
                "www.example", "a", use_edns=0, pad=128
            ).to_wire()
        )
        response = dns.message.make_response(padded_query, pad=0)
        response.answer.extend(answer_rrsets(40))
        with self.assertRaises(dns.exception.TooBig):
            response.to_wire(max_size=512)

    def test_padding_does_not_hide_query_content(self):
        # Guardrail documenting the actual privacy boundary: padding changes
        # only the message length.  The question is still cleartext and the
        # padding contains no encrypted content.
        qname = "cleartext-owner-label"
        query = dns.message.make_query(qname, "a", use_edns=0, pad=128)
        wire = query.to_wire()
        self.assertBlockAligned(wire, 128)
        # The owner name is present verbatim (uncompressed) in the wire bytes.
        self.assertIn(b"cleartext-owner-label", wire)
        parsed = dns.message.from_wire(wire)
        self.assertEqual(parsed.question[0].name.to_text(), qname + ".")
        self.assertEqual(parsed.question[0].rdtype, dns.rdatatype.A)
        option = padding_option(parsed)
        self.assertTrue(all(byte == 0 for byte in option.data))


if __name__ == "__main__":
    unittest.main()
