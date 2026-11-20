"""Local matrix check: legacy MKP -> keyring migration, static AES test key."""
import secrets

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy
from aws_encryption_sdk.identifiers import EncryptionKeyType, WrappingAlgorithm
from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider

from aws_cryptographic_material_providers.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_material_providers.mpl.config import MaterialProvidersConfig
from aws_cryptographic_material_providers.mpl.models import (
    AesWrappingAlg,
    CreateDefaultCryptographicMaterialsManagerInput,
    CreateRawAesKeyringInput,
    CreateRequiredEncryptionContextCMMInput,
)

STATIC_KEY = secrets.token_bytes(32)
NS, NAME = "managed-raw-keys", "aes-256-wrapping-key"
DATA = b"archive-payload"
EC = {"tenant": "tenant-001", "owner": "billing-team"}

REQUIRE = CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
FORBID = CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT


class StaticMKP(RawMasterKeyProvider):
    provider_id = NS

    def __init__(self, **kwargs):
        self._static_keys = {}

    def _get_raw_key(self, key_id):
        return WrappingKey(
            wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
            wrapping_key=STATIC_KEY,
            wrapping_key_type=EncryptionKeyType.SYMMETRIC,
        )


def make_mkp():
    mkp = StaticMKP()
    mkp.add_master_key(NAME)
    return mkp


mpl = AwsCryptographicMaterialProviders(config=MaterialProvidersConfig())
keyring = mpl.create_raw_aes_keyring(CreateRawAesKeyringInput(
    key_namespace=NS, key_name=NAME,
    wrapping_key=STATIC_KEY, wrapping_alg=AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16,
))
default_cmm = mpl.create_default_cryptographic_materials_manager(
    CreateDefaultCryptographicMaterialsManagerInput(keyring=keyring))
required_ec_cmm = mpl.create_required_encryption_context_cmm(
    CreateRequiredEncryptionContextCMMInput(
        required_encryption_context_keys=["tenant", "owner"],
        underlying_cmm=default_cmm))

results = []

def check(label, fn, expect_ok):
    try:
        fn()
        ok, detail = True, ""
    except Exception as e:  # noqa: BLE001
        ok, detail = False, f"{type(e).__name__}: {e}"
    status = "PASS" if ok == expect_ok else "UNEXPECTED"
    results.append((status, label, "ok" if ok else f"fail ({detail[:110]})"))


mkp = make_mkp()
client_req = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=REQUIRE)
client_forbid = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=FORBID)

# --- legacy writes (two flavours) ---
ct_legacy_noncommit, _ = client_forbid.encrypt(source=DATA, key_provider=mkp, encryption_context=EC)
ct_legacy_commit, _ = client_req.encrypt(source=DATA, key_provider=mkp, encryption_context=EC)
# --- new write ---
ct_new, _ = client_req.encrypt(source=DATA, keyring=keyring, encryption_context=EC)
# --- new write with required-EC CMM (attribution keys not stored in message) ---
ct_reqec, _ = client_req.encrypt(source=DATA, materials_manager=required_ec_cmm, encryption_context=EC)

# 1. old-write/new-read, non-committing archive
check("old(non-commit)->new read, policy=FORBID_ENCRYPT_ALLOW_DECRYPT",
      lambda: client_forbid.decrypt(source=ct_legacy_noncommit, keyring=keyring), True)
check("old(non-commit)->new read, policy=REQUIRE_ENCRYPT_REQUIRE_DECRYPT",
      lambda: client_req.decrypt(source=ct_legacy_noncommit, keyring=keyring), False)
# 2. old-write(committing)/new read
check("old(committing)->new read, policy=REQUIRE_ENCRYPT_REQUIRE_DECRYPT",
      lambda: client_req.decrypt(source=ct_legacy_commit, keyring=keyring), True)
# 3. new-write/new-read
check("new->new read, keyring, REQUIRE_*",
      lambda: client_req.decrypt(source=ct_new, keyring=keyring), True)
# 4. new-write/old-read (transition safety)
check("new->old read, MKP, REQUIRE_*",
      lambda: client_req.decrypt(source=ct_new, key_provider=mkp), True)
# 5. required-EC CMM: missing required context on decrypt
check("required-EC write -> read WITHOUT reproduced context",
      lambda: client_req.decrypt(source=ct_reqec, materials_manager=required_ec_cmm), False)
check("required-EC write -> read WITH reproduced context",
      lambda: client_req.decrypt(source=ct_reqec, materials_manager=required_ec_cmm,
                                 encryption_context={"tenant": "tenant-001", "owner": "billing-team"}), True)
# 6. probe: does required-EC CMM allow non-committing encrypt?
check("required-EC CMM encrypt under FORBID_ENCRYPT_ALLOW_DECRYPT",
      lambda: client_forbid.encrypt(source=DATA, materials_manager=required_ec_cmm, encryption_context=EC), False)
# 7. probe: legacy MKP path has no required-EC support (context always fully stored)
_, hdr = client_req.decrypt(source=ct_legacy_commit, key_provider=mkp)
print("legacy MKP message stores full EC in header:", all(p in hdr.encryption_context.items() for p in EC.items()))

for status, label, outcome in results:
    print(f"[{status}] {label} -> {outcome}")
