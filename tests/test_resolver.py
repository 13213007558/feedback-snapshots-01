import pytest

import netasm

import dnfile
from dnfile.resolver import (
    ExportedTypeResolver,
    ResolutionStatus,
    UnresolvedReason,
    public_key_token,
)

KEY_CHAIN = b"chain-full-public-key"
KEY_MIDDLE = b"middle-full-public-key"
KEY_IMPL = b"impl-full-public-key"
KEY_OTHER = b"other-full-public-key"

TOKEN_TYPEDEF = 0x02000000
TOKEN_ASSEMBLYREF = 0x23000000
TOKEN_FILE = 0x26000000
TOKEN_EXPORTEDTYPE = 0x27000000


def load(data):
    pe = dnfile.dnPE(data=data)
    assert pe.net is not None
    assert pe.net.mdtables is not None
    return pe


def make_chain():
    """Chain.dll -> Middle.dll -> Impl.dll (which defines Lib.Widget)."""
    chain = load(netasm.build_module(
        module_name="Chain.dll",
        assembly={"name": "Chain", "version": (1, 0, 0, 0), "public_key": KEY_CHAIN},
        assembly_refs=[{
            "name": "Middle",
            "version": (2, 0, 0, 0),
            "public_key_or_token": public_key_token(KEY_MIDDLE),
        }],
        exported_types=[{
            "namespace": "Lib", "name": "Widget", "impl": ("AssemblyRef", 1),
        }],
    ))
    middle = load(netasm.build_module(
        module_name="Middle.dll",
        assembly={"name": "Middle", "version": (2, 0, 0, 0), "public_key": KEY_MIDDLE},
        assembly_refs=[{
            "name": "Impl",
            "version": (3, 1, 0, 0),
            "public_key_or_token": public_key_token(KEY_IMPL),
        }],
        exported_types=[{
            "namespace": "Lib", "name": "Widget", "impl": ("AssemblyRef", 1),
        }],
    ))
    impl = load(netasm.build_module(
        module_name="Impl.dll",
        assembly={"name": "Impl", "version": (3, 1, 0, 0), "public_key": KEY_IMPL},
        type_defs=[("Lib", "Widget")],
    ))
    return chain, middle, impl


def test_forward_chain_resolves_to_definition():
    chain, middle, impl = make_chain()
    resolver = ExportedTypeResolver([chain, middle, impl])

    result = resolver.resolve(chain, 1)

    assert result.status is ResolutionStatus.FORWARDED
    assert result.resolved
    assert result.is_forwarder
    assert result.definition_token == TOKEN_TYPEDEF | 1
    assert result.definition_assembly.startswith("Impl,")
    # every step cites the source token it was derived from
    tokens = [step.token for step in result.steps]
    assert TOKEN_EXPORTEDTYPE | 1 in tokens          # Chain's ExportedType
    assert TOKEN_ASSEMBLYREF | 1 in tokens           # Chain's AssemblyRef
    assert tokens.count(TOKEN_EXPORTEDTYPE | 1) >= 2  # Chain's and Middle's
    assert tokens[-1] == TOKEN_TYPEDEF | 1           # ends at Impl's TypeDef


def test_forwarder_is_never_reported_as_local_definition():
    chain, middle, impl = make_chain()
    resolver = ExportedTypeResolver([chain, middle, impl])

    result = resolver.resolve(chain, 1)

    # the row in Chain.dll is only a forwarder declaration: it must not be
    # reported as an implementation found in Chain.dll itself
    assert result.status is not ResolutionStatus.DEFINED_HERE
    assert not result.definition_assembly.startswith("Chain,")

    # same for the intermediate forwarder in Middle.dll
    result = resolver.resolve(middle, 1)
    assert result.status is ResolutionStatus.FORWARDED
    assert result.definition_assembly.startswith("Impl,")


def test_resolve_accepts_row_and_token():
    chain, middle, impl = make_chain()
    resolver = ExportedTypeResolver([chain, middle, impl])

    row = chain.net.mdtables.ExportedType.get_with_row_index(1)
    by_row = resolver.resolve(chain, row)
    by_token = resolver.resolve(chain, TOKEN_EXPORTEDTYPE | 1)

    assert by_row.status is ResolutionStatus.FORWARDED
    assert by_token.status is ResolutionStatus.FORWARDED
    assert by_row.definition_token == by_token.definition_token


def make_client(ref):
    return load(netasm.build_module(
        module_name="Client.dll",
        assembly={"name": "Client", "version": (1, 0, 0, 0)},
        assembly_refs=[ref],
        exported_types=[{
            "namespace": "Lib", "name": "Widget", "impl": ("AssemblyRef", 1),
        }],
    ))


GOOD_REF = {
    "name": "Impl",
    "version": (3, 1, 0, 0),
    "public_key_or_token": public_key_token(KEY_IMPL),
}


def make_fake_impl(**overrides):
    assembly = {"name": "Impl", "version": (3, 1, 0, 0), "public_key": KEY_IMPL}
    assembly.update(overrides)
    return load(netasm.build_module(
        module_name="Impl.dll",
        assembly=assembly,
        type_defs=[("Lib", "Widget")],
    ))


@pytest.mark.parametrize("fake_overrides", [
    {"version": (9, 9, 9, 9)},                      # same name, other version
    {"public_key": KEY_OTHER},                      # same name, other key token
    {"culture": "de-DE"},                           # same name, other culture
])
def test_similar_identity_is_not_matched(fake_overrides):
    client = make_client(GOOD_REF)
    fake = make_fake_impl(**fake_overrides)
    resolver = ExportedTypeResolver([client, fake])

    result = resolver.resolve(client, 1)

    assert result.status is ResolutionStatus.UNRESOLVED
    assert result.reason is UnresolvedReason.IDENTITY_MISMATCH
    assert result.definition_token is None
    assert any(step.token == TOKEN_ASSEMBLYREF | 1 for step in result.steps)


def test_missing_assembly_stays_unresolved():
    client = make_client(GOOD_REF)
    resolver = ExportedTypeResolver([client])

    result = resolver.resolve(client, 1)

    assert result.status is ResolutionStatus.UNRESOLVED
    assert result.reason is UnresolvedReason.MISSING_ASSEMBLY
    assert result.definition_token is None


def make_cycle():
    loop_a = load(netasm.build_module(
        module_name="LoopA.dll",
        assembly={"name": "LoopA", "version": (1, 0, 0, 0)},
        assembly_refs=[{"name": "LoopB", "version": (1, 0, 0, 0)}],
        exported_types=[{
            "namespace": "Cycles", "name": "Gadget", "impl": ("AssemblyRef", 1),
        }],
    ))
    loop_b = load(netasm.build_module(
        module_name="LoopB.dll",
        assembly={"name": "LoopB", "version": (1, 0, 0, 0)},
        assembly_refs=[{"name": "LoopA", "version": (1, 0, 0, 0)}],
        exported_types=[{
            "namespace": "Cycles", "name": "Gadget", "impl": ("AssemblyRef", 1),
        }],
    ))
    return loop_a, loop_b


def test_forwarding_cycle_stays_unresolved():
    loop_a, loop_b = make_cycle()
    resolver = ExportedTypeResolver([loop_a, loop_b])

    result = resolver.resolve(loop_a, 1)

    assert result.status is ResolutionStatus.UNRESOLVED
    assert result.reason is UnresolvedReason.CYCLE
    assert result.definition_token is None
    # the trace shows the cycle: LoopA -> LoopB -> LoopA again
    exported_steps = [
        step for step in result.steps if step.table == "ExportedType"
        and step.token == TOKEN_EXPORTEDTYPE | 1
    ]
    assemblies_seen = [step.assembly.split(",")[0] for step in exported_steps]
    assert assemblies_seen[:2] == ["LoopA", "LoopB"]
    assert assemblies_seen.count("LoopA") >= 2


def test_type_defined_in_this_file():
    local = load(netasm.build_module(
        module_name="Local.dll",
        assembly={"name": "Local", "version": (1, 0, 0, 0)},
        type_defs=[("Here", "Local")],
        exported_types=[{
            "namespace": "Here", "name": "Local", "typedef_id": 1,
        }],
    ))
    resolver = ExportedTypeResolver([local])

    result = resolver.resolve(local, 1)

    assert result.status is ResolutionStatus.DEFINED_HERE
    assert not result.is_forwarder
    assert result.definition_token == TOKEN_TYPEDEF | 1
    assert result.definition_assembly.startswith("Local,")


def make_multi():
    multi = load(netasm.build_module(
        module_name="Multi.dll",
        assembly={"name": "Multi", "version": (1, 0, 0, 0)},
        files=["part2.netmodule"],
        exported_types=[{
            "namespace": "Multi", "name": "Deep", "impl": ("File", 1),
        }],
    ))
    part2 = load(netasm.build_module(
        module_name="part2.netmodule",
        type_defs=[("Multi", "Deep")],
    ))
    return multi, part2


def test_file_implementation_resolves_to_provided_module():
    multi, part2 = make_multi()
    resolver = ExportedTypeResolver([multi, part2])

    result = resolver.resolve(multi, 1)

    assert result.status is ResolutionStatus.DEFINED_IN_MODULE
    assert result.definition_token == TOKEN_TYPEDEF | 1
    assert result.definition_assembly == "part2.netmodule"
    assert any(step.token == TOKEN_FILE | 1 for step in result.steps)


def test_file_implementation_without_module_stays_unresolved():
    multi, _ = make_multi()
    resolver = ExportedTypeResolver([multi])

    result = resolver.resolve(multi, 1)

    assert result.status is ResolutionStatus.UNRESOLVED
    assert result.reason is UnresolvedReason.MISSING_MODULE
    assert result.definition_token is None


def test_nested_exported_type_follows_enclosing():
    nest = load(netasm.build_module(
        module_name="Nest.dll",
        assembly={"name": "Nest", "version": (1, 0, 0, 0)},
        assembly_refs=[{
            "name": "Impl2",
            "version": (1, 0, 0, 0),
            "public_key_or_token": public_key_token(KEY_IMPL),
        }],
        exported_types=[
            {"namespace": "Ns", "name": "Outer", "impl": ("AssemblyRef", 1)},
            {"namespace": "", "name": "Inner", "impl": ("ExportedType", 1)},
        ],
    ))
    impl2 = load(netasm.build_module(
        module_name="Impl2.dll",
        assembly={"name": "Impl2", "version": (1, 0, 0, 0), "public_key": KEY_IMPL},
        type_defs=[("Ns", "Outer"), ("", "Inner")],
    ))
    resolver = ExportedTypeResolver([nest, impl2])

    result = resolver.resolve(nest, 2)

    assert result.status is ResolutionStatus.FORWARDED
    assert result.definition_token == TOKEN_TYPEDEF | 2
    assert result.definition_assembly.startswith("Impl2,")
    # the trace passes through the enclosing ExportedType row
    enclosing_steps = [
        step for step in result.steps
        if step.table == "ExportedType" and step.row_index == 1
    ]
    assert enclosing_steps


def test_resolver_rejects_module_outside_the_provided_set():
    chain, middle, impl = make_chain()
    resolver = ExportedTypeResolver([middle, impl])

    with pytest.raises(ValueError):
        resolver.resolve(chain, 1)
