from __future__ import annotations

import bisect
import hashlib
import struct
from io import BytesIO

from dissect.cim.c_cim import INDEX_PAGE_SIZE, c_cim
from dissect.cim.cim import Class
from dissect.cim.index import Index, Key
from dissect.cim.mappings import Mapping

NAMESPACE_NAME = "root\\lab"
TARGET_CLASS_NAME = "Target"
TARGET_NAMESPACE = hashlib.sha256(NAMESPACE_NAME.upper().encode("utf-16-le")).hexdigest().upper()
TARGET_CLASS = hashlib.sha256(TARGET_CLASS_NAME.upper().encode("utf-16-le")).hexdigest().upper()

# Manually listed instances of the target class: (data page, data id, data length).
TARGET_INSTANCES = [
    (100, 3, 10),
    (101, 4, 10),
    (102, 8, 10),
    (103, 15, 10),
    (104, 16, 10),
    (105, 23, 10),
    (106, 42, 10),
    (107, 108, 10),
    (108, 199, 10),
    (109, 256, 10),
    (110, 301, 10),
    (111, 404, 10),
    (112, 512, 10),
    (113, 640, 10),
    (114, 777, 10),
    (115, 888, 10),
    (116, 999, 10),
    (117, 1024, 10),
    (118, 1337, 10),
    (119, 2048, 10),
    (200, 3000, 10),
    (201, 4096, 10),
    (202, 5000, 10),
    (203, 8192, 10),
]
TARGET_INSTANCE_KEYS = {f"{page}.{data_id}.{length}" for page, data_id, length in TARGET_INSTANCES}

NEIGHBOUR_REFS = {
    # Another class whose name is a textual extension of the target digest.
    f"NS_{TARGET_NAMESPACE}/CI_{TARGET_CLASS}0/IL_{'A' * 64}.1.1.1",
    # Another class whose name is a textual prefix of the target digest.
    f"NS_{TARGET_NAMESPACE}/CI_{TARGET_CLASS[:-1]}/IL_{'B' * 64}.1.1.2",
    # The target digest in the class reference part, but a different class index.
    f"NS_{TARGET_NAMESPACE}/CR_{'C' * 64}/C_{TARGET_CLASS}",
    # The target digest in a key index part.
    f"NS_{TARGET_NAMESPACE}/KI_{TARGET_CLASS}/I_{'D' * 64}.1.1.3",
    # The target digest in a different namespace.
    f"NS_{'E' * 64}/CI_{TARGET_CLASS}/IL_{'F' * 64}.1.1.4",
    # The target digest in the instance location part of a different class.
    f"NS_{TARGET_NAMESPACE}/CI_{'1' * 64}/IL_{TARGET_CLASS}.1.1.5",
}


class Node:
    def __init__(self, keys: list[str] | None = None, children: list[Node] | None = None):
        self.keys = keys or []
        self.children = children or []
        self.logical = 0
        self.min_key = ""
        self.max_key = ""


def _insert(node: Node, key: str, max_keys: int) -> tuple[str, Node, Node] | None:
    if not node.children:
        bisect.insort(node.keys, key)
        if len(node.keys) <= max_keys:
            return None

        median = len(node.keys) // 2
        return node.keys[median], Node(node.keys[:median]), Node(node.keys[median + 1 :])

    index = bisect.bisect_right(node.keys, key)
    split = _insert(node.children[index], key, max_keys)
    if split:
        median, left, right = split
        node.keys.insert(index, median)
        node.children[index] = left
        node.children.insert(index + 1, right)

    if len(node.keys) <= max_keys:
        return None

    median = len(node.keys) // 2
    return (
        node.keys[median],
        Node(node.keys[:median], node.children[: median + 1]),
        Node(node.keys[median + 1 :], node.children[median + 1 :]),
    )


def build_tree(keys: list[str], max_keys: int = 6) -> tuple[Node, list[Node]]:
    """Build a B-tree that is forced to split into many pages."""
    root = Node()
    for key in sorted(keys):
        split = _insert(root, key, max_keys)
        if split:
            median, left, right = split
            root = Node([median], [left, right])

    nodes = []

    def assign(node: Node) -> tuple[str, str]:
        node.logical = len(nodes) + 1
        nodes.append(node)
        if node.children:
            bounds = [assign(child) for child in node.children]
            node.min_key = min([*node.keys, *(bound[0] for bound in bounds)])
            node.max_key = max([*node.keys, *(bound[1] for bound in bounds)])
        else:
            node.min_key = node.keys[0]
            node.max_key = node.keys[-1]
        return node.min_key, node.max_key

    assign(root)
    return root, nodes


def _encode_page(logical: int, keys: list[str], children: list[int]) -> bytes:
    definitions = []
    strings = []
    data = bytearray()

    for key in keys:
        strings.append(len(data))
        data += key.encode() + b"\x00"
        definitions.extend((1, len(strings) - 1))

    header = struct.pack("<IIIII", 0xACCC, logical & 0xF, 0, 0, len(keys))
    header += b"\x00" * (4 * len(keys))
    header += struct.pack(f"<{len(children)}I", *children)
    header += struct.pack(f"<{len(keys)}H", *range(0, 2 * len(keys), 2))
    header += struct.pack("<H", len(definitions)) + struct.pack(f"<{len(definitions)}H", *definitions)
    header += struct.pack("<H", len(strings) - 1) + struct.pack(f"<{len(strings)}H", *strings)

    page = header + bytes(data)
    assert len(page) <= INDEX_PAGE_SIZE
    return page + b"\x00" * (INDEX_PAGE_SIZE - len(page))


def encode_index(root: Node, nodes: list[Node]) -> bytes:
    pages = {}
    for node in nodes:
        children = [child.logical for child in node.children] or [0xFFFFFFFF] * (len(node.keys) + 1)
        pages[node.logical] = _encode_page(node.logical, node.keys, children)

    buf = bytearray((len(nodes) + 1) * INDEX_PAGE_SIZE)
    for logical, page in pages.items():
        buf[logical * INDEX_PAGE_SIZE : (logical + 1) * INDEX_PAGE_SIZE] = page
    return bytes(buf)


def encode_mapping(page_count: int, root: int) -> BytesIO:
    entries = []
    for logical in range(page_count + 1):
        entries.extend((logical, 0, 0, root if logical == 0 else 0, 0, 0))

    return BytesIO(
        struct.pack("<6I", 0xABCD, 1, 1, 0, page_count + 1, page_count + 1)
        + struct.pack(f"<{len(entries)}I", *entries)
        + struct.pack("<I", 0)
    )


class StubClassInstance:
    def __init__(self, ref: Key):
        self.ref = ref
        self.key = ".".join(ref.key.split(".")[-3:])


class StubClassDefinition:
    class_name = TARGET_CLASS_NAME


class StubNamespace:
    def __init__(self, name: str):
        self.name = name


class StubCIM:
    type_xp = False
    map_type = c_cim.mapping

    def __init__(self, index: Index):
        self.index = index

    def key(self, *parts: str) -> Key:
        return Key(self, *parts)

    def get_class_instance(self, class_: Class, ref: Key) -> StubClassInstance:
        return StubClassInstance(ref)


def _target_ref(page: int, data_id: int, length: int) -> str:
    digest = hashlib.sha256(f"instance {page}.{data_id}.{length}".encode()).hexdigest().upper()
    return f"NS_{TARGET_NAMESPACE}/CI_{TARGET_CLASS}/IL_{digest}.{page}.{data_id}.{length}"


def build_index() -> tuple[StubCIM, list[Node], list[str]]:
    refs = [_target_ref(*instance) for instance in TARGET_INSTANCES]
    refs.extend(NEIGHBOUR_REFS)
    # Repeated index references for the first target instance.
    refs.extend([refs[0], refs[0]])

    for n in range(120):
        digest = hashlib.sha256(str(n).encode()).hexdigest().upper()
        refs.append(f"NS_{TARGET_NAMESPACE}/CI_Filler{n:03d}/IL_{digest}.{n}.{n}.8")
        refs.append(f"NS_{TARGET_NAMESPACE}/CD_Filler{n:03d}.{n}.{n}.9")

    root, nodes = build_tree(refs)
    buf = encode_index(root, nodes)
    cim = StubCIM(index=None)
    cim.index = Index(cim, BytesIO(buf), Mapping(cim, encode_mapping(len(nodes), root.logical)))

    return cim, nodes, refs


def query_target(cim: StubCIM) -> list[Key]:
    return cim.key().NS(NAMESPACE_NAME).CI(TARGET_CLASS_NAME).IL().references()


def test_class_instances_multi_page_index() -> None:
    cim, nodes, _ = build_index()
    assert len(nodes) > 20

    class_ = Class(cim, StubNamespace(NAMESPACE_NAME), StubClassDefinition())

    instances = list(class_.instances)
    assert {str(instance.key) for instance in instances} == TARGET_INSTANCE_KEYS
    assert len(instances) == len(TARGET_INSTANCE_KEYS)

    refs = {str(instance.class_instance.ref) for instance in instances}
    assert refs.isdisjoint(NEIGHBOUR_REFS)
    assert all(ref.startswith(f"NS_{TARGET_NAMESPACE}/CI_{TARGET_CLASS}/IL_") for ref in refs)


def test_class_instances_accesses_only_pages_covering_target_range() -> None:
    cim, nodes, _ = build_index()
    class_ = Class(cim, StubNamespace(NAMESPACE_NAME), StubClassDefinition())

    query = f"NS_{TARGET_NAMESPACE}/CI_{TARGET_CLASS}/IL"
    lower = query
    upper = query + chr(0x10FFFF)

    accessed = []
    original_page = cim.index.store.page

    def page(logical: int):
        accessed.append(logical)
        return original_page(logical)

    cim.index.store.page = page
    cim.index._lookup.cache_clear()
    try:
        assert {str(instance.key) for instance in class_.instances} == TARGET_INSTANCE_KEYS
    finally:
        cim.index.store.page = original_page

    # The root page is read once when the index is opened, so it is not part of the recorded child page reads.
    overlap_pages = {
        node.logical
        for node in nodes
        if node.logical != cim.index.store.root_page.logical_num and node.max_key >= lower and node.min_key <= upper
    }
    assert overlap_pages <= set(accessed)

    # At most one boundary leaf on either side may be read because a separator points into it. Such a leaf lies
    # entirely outside the requested range, so none of its records can end up in the result.
    extra_pages = {node.logical: node for node in nodes if node.logical in set(accessed) - overlap_pages}
    assert len(extra_pages) <= 2
    for node in extra_pages.values():
        assert not node.children
        assert node.min_key > upper or node.max_key < lower

    # The target range must span an internal separator with both adjacent children on the query path.
    both_sides = 0
    for node in nodes:
        if not node.children:
            continue
        for i, separator in enumerate(node.keys):
            if (
                lower < separator < upper
                and node.children[i].logical in accessed
                and node.children[i + 1].logical in accessed
            ):
                both_sides += 1

    assert both_sides > 0


def test_lookup_distinguishes_typed_components_and_prefix() -> None:
    cim, _, _ = build_index()

    refs = {str(ref) for ref in query_target(cim)}
    assert all(ref.startswith(f"NS_{TARGET_NAMESPACE}/CI_{TARGET_CLASS}/IL_") for ref in refs)
    assert refs.isdisjoint(NEIGHBOUR_REFS)
    assert len(refs) == len(TARGET_INSTANCES)


def test_lookup_deduplicates_repeated_index_references() -> None:
    cim, _, refs = build_index()
    first_ref = refs[0]
    assert refs.count(first_ref) >= 2

    results = query_target(cim)
    assert [str(ref) for ref in results].count(first_ref) == 1
    assert len(results) == len({str(ref) for ref in results})


def test_lookup_exact_data_reference() -> None:
    cim, _, _ = build_index()

    ref = _target_ref(100, 3, 10)
    assert [str(ref) for ref in Key(cim, ref).references()] == [ref]

    # A complete key must not degrade into a prefix query for a longer data suffix.
    longer = ref + "0"
    assert Key(cim, longer).references() == []

    # An incomplete suffix is not a valid data reference.
    assert Key(cim, ref.rsplit(".", 1)[0]).references() == []


def test_lookup_empty_result() -> None:
    cim, nodes, _ = build_index()

    accessed = []
    original_page = cim.index.store.page

    def page(logical: int):
        accessed.append(logical)
        return original_page(logical)

    cim.index.store.page = page
    cim.index._lookup.cache_clear()
    try:
        assert Key(cim, f"NS_{TARGET_NAMESPACE}/CI_{'9' * 64}").references() == []
    finally:
        cim.index.store.page = original_page

    # An empty result must not walk every page in the database.
    assert len(accessed) < len(nodes) // 2


def test_lookup_namespace_range_excludes_other_index_parts() -> None:
    cim, _, refs = build_index()

    digest = TARGET_NAMESPACE
    namespace_keys = {str(ref) for ref in Key(cim, f"NS_{digest}").references()}
    assert namespace_keys == {ref for ref in refs if ref.startswith(f"NS_{digest}/")}

    # A different namespace that only contains the digest in one of its parts must not match.
    other = f"NS_{'E' * 64}"
    assert {str(ref) for ref in Key(cim, other).references()} == {ref for ref in refs if ref.startswith(f"{other}/")}


def test_lookup_namespace_and_class_prefix_ranges() -> None:
    cim, _, refs = build_index()

    class_keys = {str(ref) for ref in Key(cim, f"NS_{TARGET_NAMESPACE}/CD").references()}
    assert class_keys == {ref for ref in refs if ref.startswith(f"NS_{TARGET_NAMESPACE}/CD_")}
    assert len(class_keys) == 120

    # A namespace/class prefix query must only match the corresponding typed component, even when the target digest
    # occurs as a separate part in other records.
    class_refs = {str(ref) for ref in Key(cim, f"NS_{TARGET_NAMESPACE}/CI_{TARGET_CLASS}").references()}
    assert class_refs == {
        ref
        for ref in refs
        if ref.startswith(f"NS_{TARGET_NAMESPACE}/CI_{TARGET_CLASS}/")
        and not ref.startswith(f"NS_{TARGET_NAMESPACE}/CI_{TARGET_CLASS}0/")
    }
    assert class_refs.isdisjoint(NEIGHBOUR_REFS)
