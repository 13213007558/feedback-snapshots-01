from __future__ import annotations

import hashlib
import struct
from pathlib import Path

import pytest

from dissect.cim.diagnostics import ROLE_INDEX, ROLE_OBJECT, diagnose

PAGE_SIZE = 0x2000
MAPPING_SIGNATURE = 0xABCD
MAPPING_FOOTER = 0xDCBA
INDEX_SIGNATURE = 0xACCC


def _build_index_page(logical_id: int, keys: list[str]) -> bytes:
    strings = bytearray()
    string_offsets: dict[bytes, int] = {}
    string_table: list[int] = []
    string_definition_table: list[int] = []
    key_indexes: list[int] = []

    def string_offset(value: bytes) -> int:
        if value not in string_offsets:
            string_offsets[value] = len(strings)
            strings.extend(value + b"\x00")
        return string_offsets[value]

    for key in keys:
        parts = [part.encode() for part in key.split("/")]
        key_indexes.append(len(string_definition_table))
        string_definition_table.append(len(parts))
        for part in parts:
            string_table.append(string_offset(part))
            string_definition_table.append(len(string_table) - 1)

    header = bytearray()
    header += struct.pack("<5I", INDEX_SIGNATURE, logical_id, 0, 0, len(keys))
    header += struct.pack(f"<{len(keys)}I", *([0] * len(keys)))
    header += struct.pack(f"<{len(keys) + 1}I", *([0xFFFFFFFF] * (len(keys) + 1)))
    header += struct.pack(f"<{len(keys)}H", *key_indexes)
    header += struct.pack("<H", len(string_definition_table))
    header += struct.pack(f"<{len(string_definition_table)}H", *string_definition_table)
    header += struct.pack("<H", len(string_table))
    header += struct.pack(f"<{len(string_table) + 1}H", *(string_table + [0]))
    page = bytes(header) + bytes(strings)
    if len(page) > PAGE_SIZE:
        raise ValueError("index page does not fit")
    return page + b"\x00" * (PAGE_SIZE - len(page))


def _object_page(record_id: int, payload: bytes) -> bytes:
    page = bytearray(PAGE_SIZE)
    struct.pack_into("<4I", page, 0, record_id, 32, len(payload), 0)
    page[32 : 32 + len(payload)] = payload
    return bytes(page)


def _mapping_section(
    role: str,
    version: int,
    first_id: int,
    targets: list[int],
    free_space: list[int],
) -> bytes:
    out = bytearray()
    out += struct.pack("<6I", MAPPING_SIGNATURE, version, first_id, first_id - 1, len(targets), len(targets))
    for logical, (target, free) in enumerate(zip(targets, free_space, strict=True)):
        out += struct.pack("<6I", target, 0x1000 + logical, free, 0, first_id, len(targets))
    out += struct.pack("<I", 0)  # free_dword_count
    out += struct.pack("<I", MAPPING_FOOTER)
    return bytes(out)


def _mapping_file(
    version: int,
    object_targets: list[int],
    object_free: list[int],
    index_targets: list[int],
    index_free: list[int],
    clean: int = 1,
    include_index: bool = True,
) -> bytes:
    data = _mapping_section(ROLE_OBJECT, version, 1, object_targets, object_free)
    if include_index:
        data += _mapping_section(ROLE_INDEX, version, 1, index_targets, index_free)
    data += struct.pack("<I", clean)
    return data


def _fixture_set(tmp_path: Path, name: str, version: int, object_base: int, index_base: int, pages: int) -> Path:
    """Build one generation inside a shared, two-generation repository.

    ``object_base`` and ``index_base`` are the first physical pages of this generation.  Both generations live in the
    same ``INDEX.BTR``/``OBJECTS.DATA`` pair, which is what makes cross-combination meaningful: every candidate is
    internally coherent, but only a matching pair resolves the index data references.
    """
    root = tmp_path / name
    root.mkdir()

    objects = bytearray()
    object_free = [0] * pages
    for logical in range(pages):
        payload = f"{name}:object:{logical}".encode()
        objects += _object_page(10 * version + logical, payload)
        object_free[logical] = PAGE_SIZE - (32 + len(payload))

    keys = [
        f"NS_X/CI_Y/IL_Z.{logical}.{10 * version + logical}.{len(f'{name}:object:{logical}')}"
        for logical in range(pages)
    ]
    index = bytearray()
    for logical in range(pages):
        index += _build_index_page(logical, keys if logical == 0 else [])

    (root / "OBJECTS.DATA").write_bytes(bytes(objects))
    (root / "INDEX.BTR").write_bytes(bytes(index))
    (root / f"{name}.MAP").write_bytes(
        _mapping_file(
            version,
            list(range(object_base, object_base + pages)),
            object_free,
            list(range(index_base, index_base + pages)),
            [0] * pages,
        )
    )
    return root


def _combined_repository(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    alpha = _fixture_set(tmp_path, "alpha", version=1, object_base=0, index_base=0, pages=4)
    beta = _fixture_set(tmp_path, "beta", version=2, object_base=4, index_base=4, pages=4)

    objects = alpha.joinpath("OBJECTS.DATA").read_bytes() + beta.joinpath("OBJECTS.DATA").read_bytes()
    index = alpha.joinpath("INDEX.BTR").read_bytes() + beta.joinpath("INDEX.BTR").read_bytes()
    combined = tmp_path / "combined"
    combined.mkdir()
    (combined / "OBJECTS.DATA").write_bytes(objects)
    (combined / "INDEX.BTR").write_bytes(index)
    (combined / "alpha.MAP").write_bytes(alpha.joinpath("alpha.MAP").read_bytes())
    (combined / "beta.MAP").write_bytes(beta.joinpath("beta.MAP").read_bytes())
    return combined / "INDEX.BTR", combined / "OBJECTS.DATA", combined / "alpha.MAP", combined / "beta.MAP"


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_individual_fixture_is_self_consistent(tmp_path: Path) -> None:
    index, objects, alpha, _ = _combined_repository(tmp_path)

    diagnosis = diagnose(index, objects, [alpha])

    assert diagnosis.verdict == "consistent"
    assert diagnosis.primary == "alpha.MAP"
    assert diagnosis.candidates[0].self_consistent is True
    assert diagnosis.candidates[0].object_check.free_space_matches == 4
    assert diagnosis.candidates[0].index_check.reachable_keys == 4
    assert diagnosis.cross[0].counts["ok"] == 4


def test_two_generations_cross_combination_is_never_mixed(tmp_path: Path) -> None:
    index, objects, alpha_map, beta_map = _combined_repository(tmp_path)

    diagnosis = diagnose(index, objects, [alpha_map, beta_map])

    assert diagnosis.verdict == "multiple_generations"
    assert diagnosis.primary == "beta.MAP"
    assert diagnosis.trusted == ["beta.MAP"]
    assert diagnosis.stale == ["alpha.MAP"]

    cross = {(item.index_candidate, item.object_candidate): item for item in diagnosis.cross}
    assert cross[("beta.MAP", "beta.MAP")].counts["ok"] == 4
    assert cross[("alpha.MAP", "alpha.MAP")].counts["ok"] == 4
    assert cross[("alpha.MAP", "beta.MAP")].counts["record_missing"] == 4
    assert cross[("beta.MAP", "alpha.MAP")].counts["record_missing"] == 4
    assert any("must not be mixed" in item for item in diagnosis.contradictions)


def test_missing_index_section_is_insufficient_not_absent(tmp_path: Path) -> None:
    root = tmp_path / "partial"
    root.mkdir()
    (root / "OBJECTS.DATA").write_bytes(_object_page(1, b"payload"))
    (root / "INDEX.BTR").write_bytes(_build_index_page(0, ["NS_X/CI_Y/IL_Z.0.1.7"]))
    (root / "partial.MAP").write_bytes(
        _mapping_file(
            version=1,
            object_targets=[0],
            object_free=[PAGE_SIZE - (32 + 7)],
            index_targets=[],
            index_free=[],
            include_index=False,
        )
    )

    diagnosis = diagnose(root / "INDEX.BTR", root / "OBJECTS.DATA", [root / "partial.MAP"])

    assert diagnosis.verdict == "contradiction"
    assert any("index mapping section is missing" in item for item in diagnosis.insufficiencies)
    assert any("object mapping section is missing" in item for item in diagnosis.insufficiencies) is False


def test_no_mapping_material_is_insufficient(tmp_path: Path) -> None:
    index, objects, _, _ = _combined_repository(tmp_path)

    diagnosis = diagnose(index, objects, [])

    assert diagnosis.verdict == "insufficient"
    assert diagnosis.primary is None
    assert any("no MAPPING material supplied" in item for item in diagnosis.insufficiencies)


def test_diagnosis_does_not_modify_inputs(tmp_path: Path) -> None:
    index, objects, alpha_map, beta_map = _combined_repository(tmp_path)
    paths = [index, objects, alpha_map, beta_map]
    before = [_digest(path) for path in paths]

    diagnose(index, objects, [alpha_map, beta_map])

    assert [_digest(path) for path in paths] == before


@pytest.fixture
def real_fixture_dir(tmp_path: Path) -> Path:
    import gzip

    root = tmp_path / "real"
    root.mkdir()
    data = Path(__file__).parent / "_data"
    for name in ("INDEX.BTR", "OBJECTS.DATA", "MAPPING1.MAP", "MAPPING2.MAP", "MAPPING3.MAP"):
        with gzip.open(data / f"{name}.gz", "rb") as source:
            (root / name).write_bytes(source.read())
    return root


def test_real_fixture_generations(real_fixture_dir: Path) -> None:
    root = real_fixture_dir
    diagnosis = diagnose(
        root / "INDEX.BTR",
        root / "OBJECTS.DATA",
        [root / "MAPPING1.MAP", root / "MAPPING2.MAP", root / "MAPPING3.MAP"],
    )

    assert [candidate.name for candidate in diagnosis.candidates] == [
        "MAPPING1.MAP",
        "MAPPING2.MAP",
        "MAPPING3.MAP",
    ]
    assert all(candidate.self_consistent for candidate in diagnosis.candidates)
    assert diagnosis.verdict == "multiple_generations"
    assert diagnosis.primary in {"MAPPING1.MAP", "MAPPING2.MAP"}
    assert diagnosis.stale == ["MAPPING3.MAP"]

    by_pair = {(item.index_candidate, item.object_candidate): item.counts for item in diagnosis.cross}
    assert by_pair[("MAPPING1.MAP", "MAPPING1.MAP")]["ok"] == 11949
    assert by_pair[("MAPPING2.MAP", "MAPPING2.MAP")]["ok"] == 11949
    assert by_pair[("MAPPING3.MAP", "MAPPING3.MAP")]["ok"] == 11951
    assert by_pair[("MAPPING1.MAP", "MAPPING3.MAP")]["record_missing"] == 22
    assert by_pair[("MAPPING3.MAP", "MAPPING1.MAP")]["record_missing"] == 24
    assert any("653 physical pages" in item for item in diagnosis.insufficiencies)
