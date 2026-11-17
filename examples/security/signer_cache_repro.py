"""Minimal reproduction: a shared KeyLocator must not pin a cached signer.

Two identities (/ns/A, /ns/B) publish Data under one policy-enforced
KeyLocator string while the default identity switches between them. The
KeyLocator is identical in every packet, so only verification against the
actual public keys reveals which key signed each packet.

Run:  .venv/bin/python examples/security/signer_cache_repro.py
"""
import os
import tempfile

from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS

from ndn.encoding import MetaInfo, Name, make_data, parse_data
from ndn.security import KeychainSqlite3, TpmFile

SHARED_KEY_LOCATOR = '/policy/issuer'


def verify(pkt, pub_der):
    _, _, _, sp = parse_data(pkt)
    verifier = DSS.new(ECC.import_key(pub_der), 'fips-186-3', 'der')
    h = SHA256.new()
    for part in sp.signature_covered_part:
        h.update(part)
    try:
        verifier.verify(h, bytes(sp.signature_value_buf))
        return True
    except ValueError:
        return False


def main():
    base = tempfile.mkdtemp()
    pib = os.path.join(base, 'pib.db')
    tpm_dir = os.path.join(base, 'ndnsec-key-file')
    KeychainSqlite3.initialize(pib, 'tpm-file', tpm_dir)
    kc = KeychainSqlite3(pib, TpmFile(tpm_dir))

    key_a = kc.touch_identity('/ns/A').default_key()
    key_b = kc.touch_identity('/ns/B').default_key()
    pub_a, pub_b = bytes(key_a.key_bits), bytes(key_b.key_bits)

    def publish():
        return make_data('/ns/data', MetaInfo(), b'x',
                         signer=kc.get_signer({'key_locator': SHARED_KEY_LOCATOR}))

    kc.set_default_identity('/ns/A')
    pkt_a = publish()
    kc.set_default_identity('/ns/B')
    pkt_b = publish()

    kl_a = Name.to_str(parse_data(pkt_a)[3].signature_info.key_locator.name)
    kl_b = Name.to_str(parse_data(pkt_b)[3].signature_info.key_locator.name)
    print(f'KeyLocator A={kl_a}  B={kl_b}  (identical: {kl_a == kl_b})')
    print(f'pkt_a signed by A={verify(pkt_a, pub_a)}  B={verify(pkt_a, pub_b)}')
    print(f'pkt_b signed by A={verify(pkt_b, pub_a)}  B={verify(pkt_b, pub_b)}')

    assert kl_a == kl_b == SHARED_KEY_LOCATOR
    assert verify(pkt_a, pub_a) and not verify(pkt_a, pub_b)
    assert verify(pkt_b, pub_b) and not verify(pkt_b, pub_a)
    print('OK: the KeyLocator string is shared, but each packet is verified '
          'against its own key.')


if __name__ == '__main__':
    main()
