import hashlib
import json

import scenario


def _hashes(directory):
    return {
        str(path.relative_to(directory)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


def test_fixture_bytes_are_stable_across_directories(tmp_path):
    one = scenario.build(tmp_path / "one")
    two = scenario.build(tmp_path / "two")
    assert _hashes(tmp_path / "one") == _hashes(tmp_path / "two")
    assert set(one) == set(two)


def test_fixture_manifest_matches_scenario(tmp_path):
    paths = scenario.build(tmp_path)
    manifest = {
        name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in paths.items()
    }
    assert set(manifest) == {"host", "candidate_v1", "candidate_v2"}
    assert len(set(manifest.values())) == 3


def test_reports_are_location_independent(tmp_path, monkeypatch):
    import run_demo

    out_a = tmp_path / "a"
    out_b = tmp_path / "b"
    monkeypatch.setattr(
        "sys.argv",
        ["run_demo.py", "--out", str(out_a), "--policies", "exact_identity"],
    )
    assert run_demo.main() == 0
    monkeypatch.setattr(
        "sys.argv",
        ["run_demo.py", "--out", str(out_b), "--policies", "exact_identity"],
    )
    assert run_demo.main() == 0

    def report_bytes(directory):
        return {
            name: hashlib.sha256(path.read_bytes()).hexdigest()
            for name, path in {
                "json": directory / "exact_identity" / "report.json",
                "text": directory / "exact_identity" / "report.txt",
                "comparison": directory / "comparison.json",
            }.items()
        }

    assert report_bytes(out_a) == report_bytes(out_b)
