import asyncio as aio
import os
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from tempfile import TemporaryDirectory

from Cryptodome.PublicKey import ECC

from ndn import encoding as enc, types, utils
from ndn.app_support.light_versec import Checker, compile_lvs, lvs_validator
from ndn.app_support.security_v2 import derive_cert, parse_certificate
from ndn.security import KeychainSqlite3, TpmFile, verify_ecdsa


LVS_TEXT = r'''
#ca: "lvs-ca"
#KEY: "KEY"/_/_/_
#anchor: #ca/#KEY
#org: #ca/"org"/org/#KEY & { org: "acme" | "globex" } <= #anchor
#user: #ca/"org"/org/"user"/subject/purpose/#KEY & { purpose: "read" | "write" } <= #org
#doc: #ca/"org"/org/"data"/subject/purpose/content <= #user
#auditor: #ca/"org"/org/"user"/subject/purpose/#KEY & { purpose: "audit" } <= #org
#audit: #ca/"org"/org/"audit"/subject/purpose/entry <= #auditor
'''

LVS_NO_SUBJECT_EQUALITY = LVS_TEXT.replace(
    '#doc: #ca/"org"/org/"data"/subject/purpose/content <= #user',
    '#doc: #ca/"org"/org/"data"/_subject/purpose/content <= #user',
)
assert LVS_NO_SUBJECT_EQUALITY != LVS_TEXT

ORGS = ('acme', 'globex')
SUBJECTS = ('alice', 'bob')
USER_PURPOSES = ('read', 'write', 'audit')
DATA_PURPOSES = ('read', 'write')


@dataclass(frozen=True)
class Entity:
    cert_name: enc.FormalName
    cert_wire: bytes
    public_key: bytes


@dataclass
class Hierarchy:
    keychain: KeychainSqlite3
    anchor: Entity
    orgs: dict[str, Entity]
    users: dict[tuple[str, str, str], Entity]

    def org(self, org: str) -> Entity:
        return self.orgs[org]

    def user(self, org: str, subject: str, purpose: str) -> Entity:
        return self.users[(org, subject, purpose)]

    def signer(self, entity: Entity, key_locator: Entity | None = None):
        args = {'cert': entity.cert_name}
        if key_locator is not None:
            args['key_locator'] = key_locator.cert_name
        return self.keychain.get_signer(args)


def build_hierarchy(base_dir: str) -> Hierarchy:
    pib_file = os.path.join(base_dir, 'pib.db')
    tpm_dir = os.path.join(base_dir, 'privKeys')
    assert KeychainSqlite3.initialize(pib_file, 'tpm-file', tpm_dir)
    keychain = KeychainSqlite3(pib_file, TpmFile(tpm_dir))

    anchor_id = keychain.touch_identity('/lvs-ca')
    anchor_key = anchor_id.default_key()
    anchor_cert = anchor_key.default_cert()
    anchor = Entity(
        anchor_cert.name,
        bytes(anchor_cert.data),
        bytes(anchor_key.key_bits),
    )
    anchor_signer = keychain.get_signer({'cert': anchor.cert_name})

    orgs = {}
    users = {}
    for org_name in ORGS:
        org_id = keychain.touch_identity(f'/lvs-ca/org/{org_name}')
        org_key = org_id.default_key()
        org_cert_name, org_cert = derive_cert(
            org_key.name,
            enc.Component.from_str('lvs-ca'),
            org_key.key_bits,
            anchor_signer,
            datetime.now(UTC),
            3600,
        )
        keychain.import_cert(org_key.name, org_cert_name, org_cert)
        org_entity = Entity(
            org_cert_name,
            bytes(org_cert),
            bytes(org_key.key_bits),
        )
        orgs[org_name] = org_entity
        org_signer = keychain.get_signer({'cert': org_cert_name})

        for subject in SUBJECTS:
            for purpose in USER_PURPOSES:
                user_id = keychain.touch_identity(
                    f'/lvs-ca/org/{org_name}/user/{subject}/{purpose}'
                )
                user_key = user_id.default_key()
                user_cert_name, user_cert = derive_cert(
                    user_key.name,
                    enc.Component.from_str(org_name),
                    user_key.key_bits,
                    org_signer,
                    datetime.now(UTC),
                    3600,
                )
                keychain.import_cert(user_key.name, user_cert_name, user_cert)
                users[(org_name, subject, purpose)] = Entity(
                    user_cert_name,
                    bytes(user_cert),
                    bytes(user_key.key_bits),
                )

    return Hierarchy(keychain, anchor, orgs, users)


@contextmanager
def hierarchy():
    with TemporaryDirectory() as base_dir:
        tb = build_hierarchy(base_dir)
        try:
            yield tb
        finally:
            tb.keychain.shutdown()


class FakeApp:
    def __init__(self, certificates: list[bytes]):
        self.packets = {
            enc.Name.to_bytes(parse_certificate(wire).name): wire
            for wire in certificates
        }
        self.expressed: list[enc.FormalName] = []

    async def express(self, name, validator, **kwargs):
        name = enc.Name.normalize(name)
        self.expressed.append(name)
        try:
            wire = self.packets[enc.Name.to_bytes(name)]
        except KeyError as exc:
            raise types.InterestTimeout() from exc

        data_name, meta_info, content, sig_ptrs = enc.parse_data(wire)
        context = {
            'meta_info': meta_info,
            'sig_ptrs': sig_ptrs,
            'raw_packet': wire,
            'deadline': utils.timestamp() + kwargs.get('lifetime', 4000),
        }
        result = await validator(data_name, sig_ptrs, context)
        if result not in (
            types.ValidResult.PASS,
            types.ValidResult.ALLOW_BYPASS,
        ):
            raise types.ValidationFailure(
                data_name,
                meta_info,
                content,
                sig_ptrs,
                result,
            )
        return data_name, content, context


def data_name(org: str, subject: str, purpose: str) -> str:
    return f'/lvs-ca/org/{org}/data/{subject}/{purpose}/report'


def audit_name(org: str, subject: str, purpose: str) -> str:
    return f'/lvs-ca/org/{org}/audit/{subject}/{purpose}/entry'


def key_name(org: str, subject: str, purpose: str) -> str:
    return f'/lvs-ca/org/{org}/user/{subject}/{purpose}/KEY/1/{org}/v=1'


def signed_data(
    name: str,
    signer: enc.Signer,
) -> bytes:
    return bytes(enc.make_data(name, enc.MetaInfo(), b'payload', signer))


def validate(
    tb: Hierarchy,
    checker: Checker,
    packet: bytes,
    certificates: list[bytes],
) -> tuple[types.ValidResult, list[enc.FormalName]]:
    app = FakeApp(certificates)
    validator = lvs_validator(checker, app, tb.anchor.cert_wire)
    name, _, _, sig_ptrs = enc.parse_data(packet)
    result = aio.run(
        validator(name, sig_ptrs, {'deadline': utils.timestamp() + 4000})
    )
    return result, app.expressed


def verify_packet(public_key: bytes, packet: bytes) -> bool:
    _, _, _, sig_ptrs = enc.parse_data(packet)
    assert (
        sig_ptrs.signature_info.signature_type
        == enc.SignatureType.SHA256_WITH_ECDSA
    )
    return verify_ecdsa(ECC.import_key(public_key), sig_ptrs)


def verify_certificate(child: Entity, issuer: Entity) -> bool:
    child_cert = parse_certificate(child.cert_wire)
    assert (
        enc.Name.to_bytes(child_cert.signature_info.key_locator.name)
        == enc.Name.to_bytes(issuer.cert_name)
    )
    return verify_packet(issuer.public_key, child.cert_wire)


def plain(x: enc.BinaryStr) -> bytes:
    return bytes(enc.Component.get_value(x))


def contexts(
    checker: Checker, name: str
) -> list[tuple[list[str], dict[str, bytes]]]:
    return [
        (rules, {key: plain(value) for key, value in context.items()})
        for rules, context in checker.match(name)
    ]


class TestNamingAuthorization:
    @staticmethod
    def test_subject_binding_blocks_cross_user_signing():
        checker = Checker(compile_lvs(LVS_TEXT), {})
        assert checker.root_of_trust() == {'#anchor'}

        assert checker.check(
            data_name('acme', 'alice', 'read'),
            key_name('acme', 'alice', 'read'),
        )
        assert not checker.check(
            data_name('acme', 'bob', 'read'),
            key_name('acme', 'alice', 'read'),
        )
        assert not checker.check(
            data_name('acme', 'alice', 'read'),
            key_name('acme', 'bob', 'read'),
        )
        assert not checker.check(
            data_name('acme', 'alice', 'read'),
            key_name('acme', 'alice', 'write'),
        )
        assert not checker.check(
            data_name('globex', 'alice', 'read'),
            key_name('acme', 'alice', 'read'),
        )
        assert not checker.check(
            data_name('acme', 'alice', 'read'),
            key_name('globex', 'alice', 'read'),
        )

    @staticmethod
    def test_rule_references_enforce_direct_issuers():
        with hierarchy() as tb:
            checker = Checker(compile_lvs(LVS_TEXT), {})
            alice = tb.user('acme', 'alice', 'read')
            acme = tb.org('acme')

            assert checker.check(alice.cert_name, acme.cert_name)
            assert checker.check(acme.cert_name, tb.anchor.cert_name)
            assert not checker.check(alice.cert_name, tb.anchor.cert_name)
            assert not checker.check(
                data_name('acme', 'alice', 'read'),
                acme.cert_name,
            )

    @staticmethod
    def test_reused_variable_names_keep_per_rule_scope():
        checker = Checker(compile_lvs(LVS_TEXT), {})
        symbols = {}
        for symbol in checker.model.symbols:
            assert symbol.ident not in symbols
            symbols[symbol.ident] = symbol.tag
        assert {'org', 'subject', 'purpose'} <= symbols.keys()

        weak = Checker(compile_lvs(LVS_NO_SUBJECT_EQUALITY), {})
        doc_context = (
            ['#doc'],
            {
                'org': b'acme',
                'subject': b'alice',
                'purpose': b'read',
                'content': b'report',
            },
        )
        assert contexts(checker, data_name('acme', 'alice', 'read')) == [
            doc_context
        ]
        assert contexts(checker, audit_name('acme', 'bob', 'audit')) == [
            (
                ['#audit'],
                {
                    'org': b'acme',
                    'subject': b'bob',
                    'purpose': b'audit',
                    'entry': b'entry',
                },
            )
        ]
        assert contexts(checker, data_name('globex', 'bob', 'write')) == [
            (
                ['#doc'],
                {
                    'org': b'globex',
                    'subject': b'bob',
                    'purpose': b'write',
                    'content': b'report',
                },
            )
        ]

        assert checker.check(
            audit_name('acme', 'bob', 'audit'),
            key_name('acme', 'bob', 'audit'),
        )
        assert not checker.check(
            audit_name('acme', 'bob', 'audit'),
            key_name('acme', 'alice', 'audit'),
        )
        assert not checker.check(
            audit_name('acme', 'alice', 'audit'),
            key_name('acme', 'alice', 'read'),
        )
        assert not checker.check(
            data_name('acme', 'alice', 'read'),
            key_name('acme', 'alice', 'audit'),
        )

    @staticmethod
    def test_both_user_chains_reach_the_same_anchor():
        with hierarchy() as tb:
            checker = Checker(compile_lvs(LVS_TEXT), {})
            acme = tb.org('acme')
            alice = tb.user('acme', 'alice', 'read')
            bob = tb.user('acme', 'bob', 'read')

            for user in (alice, bob):
                assert verify_certificate(user, acme)
                assert verify_certificate(acme, tb.anchor)
                assert checker.check(user.cert_name, acme.cert_name)
                assert checker.check(acme.cert_name, tb.anchor.cert_name)

            for user, subject in ((alice, 'alice'), (bob, 'bob')):
                packet = signed_data(
                    data_name('acme', subject, 'read'),
                    tb.signer(user),
                )
                result, expressed = validate(
                    tb, checker, packet, [user.cert_wire, acme.cert_wire]
                )
                assert result is types.ValidResult.PASS
                assert len(expressed) == 2

    @staticmethod
    def test_cross_user_substitution_separates_naming_and_crypto():
        with hierarchy() as tb:
            checker = Checker(compile_lvs(LVS_TEXT), {})
            acme = tb.org('acme')
            alice = tb.user('acme', 'alice', 'read')
            bob = tb.user('acme', 'bob', 'read')

            alice_signed = signed_data(
                data_name('acme', 'bob', 'read'),
                tb.signer(alice),
            )
            name, _, _, _ = enc.parse_data(alice_signed)
            assert verify_packet(alice.public_key, alice_signed)
            assert not verify_packet(bob.public_key, alice_signed)
            assert not checker.check(name, alice.cert_name)
            result, expressed = validate(
                tb,
                checker,
                alice_signed,
                [alice.cert_wire, bob.cert_wire, acme.cert_wire],
            )
            assert result is types.ValidResult.FAIL
            assert expressed == []

            relabeled = signed_data(
                data_name('acme', 'bob', 'read'),
                tb.signer(alice, key_locator=bob),
            )
            name, _, _, _ = enc.parse_data(relabeled)
            assert verify_packet(alice.public_key, relabeled)
            assert not verify_packet(bob.public_key, relabeled)
            assert checker.check(name, bob.cert_name)
            assert not checker.check(name, alice.cert_name)
            result, expressed = validate(
                tb,
                checker,
                relabeled,
                [alice.cert_wire, bob.cert_wire, acme.cert_wire],
            )
            assert result is types.ValidResult.FAIL
            assert [enc.Name.to_bytes(name) for name in expressed] == [
                enc.Name.to_bytes(bob.cert_name),
                enc.Name.to_bytes(acme.cert_name),
            ]

    @staticmethod
    def test_directly_anchored_user_certificate_is_rejected_by_rule_reference():
        with hierarchy() as tb:
            checker = Checker(compile_lvs(LVS_TEXT), {})
            mallory_id = tb.keychain.touch_identity(
                '/lvs-ca/org/acme/user/mallory/read'
            )
            mallory_key = mallory_id.default_key()
            mallory_cert_name, mallory_cert = derive_cert(
                mallory_key.name,
                enc.Component.from_str('lvs-ca'),
                mallory_key.key_bits,
                tb.signer(tb.anchor),
                datetime.now(UTC),
                3600,
            )
            tb.keychain.import_cert(
                mallory_key.name,
                mallory_cert_name,
                mallory_cert,
            )
            mallory = Entity(
                mallory_cert_name,
                bytes(mallory_cert),
                bytes(mallory_key.key_bits),
            )

            assert verify_certificate(mallory, tb.anchor)
            assert not checker.check(mallory.cert_name, tb.anchor.cert_name)

            packet = signed_data(
                data_name('acme', 'mallory', 'read'),
                tb.signer(mallory),
            )
            result, expressed = validate(
                tb,
                checker,
                packet,
                [mallory.cert_wire, tb.anchor.cert_wire],
            )
            assert result is types.ValidResult.FAIL
            assert [enc.Name.to_bytes(name) for name in expressed] == [
                enc.Name.to_bytes(mallory.cert_name),
            ]

    @staticmethod
    def test_removed_subject_equality_only_adds_cross_subject_pairs():
        strong = Checker(compile_lvs(LVS_TEXT), {})
        weak = Checker(compile_lvs(LVS_NO_SUBJECT_EQUALITY), {})

        def accepts(checker):
            accepted = set()
            for d_org in ORGS:
                for k_org in ORGS:
                    for d_subject in SUBJECTS:
                        for k_subject in SUBJECTS:
                            for d_purpose in DATA_PURPOSES:
                                for k_purpose in DATA_PURPOSES:
                                    pair = (
                                        d_org,
                                        d_subject,
                                        d_purpose,
                                        k_org,
                                        k_subject,
                                        k_purpose,
                                    )
                                    if checker.check(
                                        data_name(d_org, d_subject, d_purpose),
                                        key_name(k_org, k_subject, k_purpose),
                                    ):
                                        accepted.add(pair)
            return accepted

        strong_accepted = accepts(strong)
        weak_accepted = accepts(weak)

        assert strong_accepted == {
            (d_org, d_subject, d_purpose, d_org, d_subject, d_purpose)
            for d_org in ORGS
            for d_subject in SUBJECTS
            for d_purpose in DATA_PURPOSES
        }
        assert weak_accepted == {
            (d_org, d_subject, d_purpose, d_org, k_subject, d_purpose)
            for d_org in ORGS
            for d_subject in SUBJECTS
            for k_subject in SUBJECTS
            for d_purpose in DATA_PURPOSES
        }
        assert weak_accepted - strong_accepted == {
            (d_org, d_subject, d_purpose, d_org, d_other, d_purpose)
            for d_org in ORGS
            for d_subject in SUBJECTS
            for d_other in SUBJECTS
            for d_purpose in DATA_PURPOSES
            if d_other != d_subject
        }

        assert contexts(weak, data_name('acme', 'alice', 'read')) == [
            (
                ['#doc'],
                {
                    'org': b'acme',
                    'purpose': b'read',
                    'content': b'report',
                },
            )
        ]

    @staticmethod
    def test_removed_subject_equality_is_exploitable_end_to_end():
        with hierarchy() as tb:
            strong = Checker(compile_lvs(LVS_TEXT), {})
            weak = Checker(compile_lvs(LVS_NO_SUBJECT_EQUALITY), {})
            acme = tb.org('acme')
            alice = tb.user('acme', 'alice', 'read')

            packet = signed_data(
                data_name('acme', 'bob', 'read'),
                tb.signer(alice),
            )
            name, _, _, _ = enc.parse_data(packet)
            assert not strong.check(name, alice.cert_name)
            assert weak.check(name, alice.cert_name)

            strong_result, strong_expressed = validate(
                tb,
                strong,
                packet,
                [alice.cert_wire, acme.cert_wire],
            )
            assert strong_result is types.ValidResult.FAIL
            assert strong_expressed == []

            weak_result, weak_expressed = validate(
                tb,
                weak,
                packet,
                [alice.cert_wire, acme.cert_wire],
            )
            assert weak_result is types.ValidResult.PASS
            assert [enc.Name.to_bytes(name) for name in weak_expressed] == [
                enc.Name.to_bytes(alice.cert_name),
                enc.Name.to_bytes(acme.cert_name),
            ]

            wrong_purpose = signed_data(
                data_name('acme', 'bob', 'write'),
                tb.signer(alice),
            )
            assert not weak.check(
                enc.parse_data(wrong_purpose)[0],
                alice.cert_name,
            )

            other_org = signed_data(
                data_name('globex', 'bob', 'read'),
                tb.signer(alice),
            )
            assert not weak.check(
                enc.parse_data(other_org)[0],
                alice.cert_name,
            )
