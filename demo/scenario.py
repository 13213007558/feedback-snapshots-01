"""The scenario: one host, two same-named dependencies, one nested chain.

Host.exe declares, in this order:

  AssemblyRef #1  Contoso.Utils 1.0.0.0  neutral  token A     (no retargetable)
  AssemblyRef #2  Contoso.Utils 2.0.0.0  neutral  token B     afRetargetable

  TypeRef #1  [AssemblyRef #1] Contoso.Utils.Facade
  TypeRef #2  [TypeRef #1]     Contoso.Utils.Facade/Builder     <- nested
  TypeRef #3  [AssemblyRef #2] Contoso.Utils.Facade

  MemberRef #1  [TypeRef #2] Builder::Make
  MemberRef #2  [TypeRef #3] Facade::Make

The two candidate files on disk have the same simple name `Contoso.Utils.dll`
but different identities, and they each define `Contoso.Utils.Facade` with a
different `Facade/Builder` shape.
"""

from __future__ import annotations

from pathlib import Path

import pebuilder

# Fixed identity seeds.  These are synthetic keys, not real signatures.
TOKEN_A = pebuilder.public_key_token(pebuilder.synthetic_public_key(b"contoso-a"))
TOKEN_B = pebuilder.public_key_token(pebuilder.synthetic_public_key(b"contoso-b"))
KEY_A = pebuilder.synthetic_public_key(b"contoso-a")
KEY_B = pebuilder.synthetic_public_key(b"contoso-b")

# Method signatures (ECMA-335 II.23.2.1): default calling convention,
# param count, return type, then parameter types.
SIG_VOID_INSTANCE = b"\x20\x00\x01"          # instance void Make()
SIG_INT32_INSTANCE = b"\x20\x00\x01\x08"     # instance int32 Make()


def _candidate(identity: dict, builder_returns_int: bool) -> bytes:
    b = pebuilder.AssemblyBuilder(
        name="Contoso.Utils",
        version=identity["version"],
        culture="",
        public_key=identity["public_key"],
        kind="dll",
        mvid_seed=identity["mvid_seed"],
    )
    b.add_type_ref(None, "System", "Object")

    # <Module>, then the public Facade type.
    b.add_type_def("", "<Module>", None)
    facade = b.add_type_def("Contoso.Utils", "Facade", ("TypeRef", 1))
    # Nested type: no namespace, declared inside Facade.
    builder = b.add_type_def(
        "", "Builder", ("TypeRef", 1), flags=0x00000002
    )
    b.add_nested(builder, facade)

    # Both candidates expose Builder::Make, but with different signatures and
    # different IL.  That is what makes a wrong candidate observable: the
    # resolved method identity changes, not just the assembly version.
    if builder_returns_int:
        b.add_method("Make", SIG_INT32_INSTANCE, flags=0x0006, body=b"\x17\x2a")   # ldc.i4.1; ret
    else:
        b.add_method("Make", SIG_VOID_INSTANCE, flags=0x0006, body=b"\x2a")          # ret
    return b.build()


def build(dest: Path) -> dict[str, Path]:
    dest.mkdir(parents=True, exist_ok=True)

    # ---- Host.exe -------------------------------------------------------
    host = pebuilder.AssemblyBuilder(
        "Host", (1, 0, 0, 0), kind="exe", mvid_seed=b"host"
    )
    host.add_type_ref(None, "System", "Object")                       # TypeRef 1 base
    host.add_type_def("", "<Module>", None)
    host_type = host.add_type_def("Demo", "Host", ("TypeRef", 1))

    # Two encoding styles on purpose:
    #   ref A carries an 8-byte token (afPublicKey clear)
    #   ref B carries a full public key (afPublicKey set)
    # A naive byte comparison of PublicKey vs PublicKey fails for both.
    ref_a = host.add_assembly_ref(
        "Contoso.Utils", (1, 0, 0, 0), "", TOKEN_A, flags=0
    )
    ref_b = host.add_assembly_ref(
        "Contoso.Utils", (2, 0, 0, 0), "", KEY_B,
        flags=pebuilder.AF_PUBLIC_KEY | pebuilder.AF_RETARGETABLE,
    )

    facade_a = host.add_type_ref(("AssemblyRef", ref_a), "Contoso.Utils", "Facade")
    builder_a = host.add_type_ref(("TypeRef", facade_a), "", "Builder")
    facade_b = host.add_type_ref(("AssemblyRef", ref_b), "Contoso.Utils", "Facade")
    builder_b = host.add_type_ref(("TypeRef", facade_b), "", "Builder")

    # Each MemberRef is written against the candidate it was compiled for:
    # v1 exposes void Make(), v2 exposes int32 Make().
    host.add_member_ref(("TypeRef", builder_a), "Make", SIG_VOID_INSTANCE)
    host.add_member_ref(("TypeRef", builder_b), "Make", SIG_INT32_INSTANCE)
    host.add_method("Main", b"\x00\x00\x01", 0x0016, body=b"\x2a")
    (dest / "Host.exe").write_bytes(host.build())

    # ---- Two candidates, same file name, different identities ----------
    a = {
        "version": (1, 0, 0, 0),
        "public_key": KEY_A,
        "mvid_seed": b"candidate-a",
    }
    b = {
        "version": (2, 0, 0, 0),
        "public_key": KEY_B,
        "mvid_seed": b"candidate-b",
    }
    (dest / "candidates" / "v1").mkdir(parents=True, exist_ok=True)
    (dest / "candidates" / "v2").mkdir(parents=True, exist_ok=True)
    (dest / "candidates" / "v1" / "Contoso.Utils.dll").write_bytes(
        _candidate(a, builder_returns_int=False)
    )
    (dest / "candidates" / "v2" / "Contoso.Utils.dll").write_bytes(
        _candidate(b, builder_returns_int=True)
    )
    return {
        "host": dest / "Host.exe",
        "candidate_v1": dest / "candidates" / "v1" / "Contoso.Utils.dll",
        "candidate_v2": dest / "candidates" / "v2" / "Contoso.Utils.dll",
    }
