#!/usr/bin/env python3
"""Reproducible investigation: why the same memory dump yields different WinAPI names.

Builds one synthetic 32-bit memory dump whose code calls three absolute addresses,
then disassembles the identical bytes under different API_COLLECTION_FILES setups:

  unconfigured   no API database at all
  target_matched the ApiScout DB of the (simulated) dump source: WinXP SP3
  near_version   a neighboring DB: Win7 SP1 (the "analysis machine" mistake)
  both_unpinned  both DBs, no os_name pinned, in two different config orders

For every call site it prints the raw target address, the config source, and the
resolved name, and writes last_run_report.json with the full candidate sets and
the minimal analysis context a server should persist. Exits 1 if expectations drift.

Run from the repo root:  python3 investigations/winapi-env-assumption/reproduce.py
"""

import hashlib
import json
import os
import struct
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

from smda.Disassembler import Disassembler  # noqa: E402
from smda.SmdaConfig import SmdaConfig  # noqa: E402

BASE_ADDR = 0x10000
OUT_PATH = os.path.join(os.path.dirname(__file__), "last_run_report.json")

DB_FILES = {
    "winxp_sp3": os.path.join(REPO_ROOT, "data", "apiscout_winxp_prof_sp3.json"),
    "win7_sp1": os.path.join(REPO_ROOT, "data", "apiscout_win7_prof-n_sp1.json"),
}

CALL_SITES = [
    ("conflict", 0x78180090),
    ("xp_only", 0x7C801A28),
    ("control", 0x78150000),
]

EXPECTED = {
    "unconfigured": {"conflict": None, "xp_only": None, "control": None},
    "target_matched_winxp_sp3": {
        "conflict": "msvcr80.dll_0x78130000!strncat",
        "xp_only": "kernel32.dll_0x7c800000!CreateFileA",
        "control": "msvcr80.dll_0x78130000!strrchr",
    },
    "near_version_win7_sp1": {
        "conflict": "msvcr80.dll_0x78130000!_execle",
        "xp_only": None,
        "control": "msvcr80.dll_0x78130000!strrchr",
    },
    "both_unpinned_win7_first": {"conflict": "msvcr80.dll_0x78130000!_execle"},
    "both_unpinned_winxp_first": {"conflict": "msvcr80.dll_0x78130000!strncat"},
}


def build_dump():
    code = bytearray(b"\x55\x8b\xec")
    site_offsets = {}
    for label, target in CALL_SITES:
        insn_addr = BASE_ADDR + len(code)
        code += b"\xe8" + struct.pack("<i", target - (insn_addr + 5))
        site_offsets[label] = insn_addr
    code += b"\x5d\xc3"
    return bytes(code).ljust(0x100, b"\xcc"), site_offsets


def load_candidate_map(db_path):
    with open(db_path, encoding="utf-8") as f_json:
        api_db = json.load(f_json)
    candidates = {}
    for dll_key, dll in api_db["dlls"].items():
        dll_name = "_".join(dll_key.split("_")[2:])
        for export in dll["exports"]:
            addr = dll["base_address"] + export["address"]
            candidates.setdefault(addr, []).append("{}!{}".format(dll_name, export["name"]))
    return {
        "os_name": api_db["os_name"],
        "os_version": api_db["os_version"],
        "sha256": hashlib.sha256(open(db_path, "rb").read()).hexdigest(),
        "candidates": candidates,
    }


def run_case(case_name, api_collection_files, dump):
    config = SmdaConfig()
    config.API_COLLECTION_FILES = api_collection_files
    report = Disassembler(config).disassembleBuffer(dump, BASE_ADDR, bitness=32, architecture="intel")
    function = report.getFunction(BASE_ADDR)
    call_instructions = {}
    for ins in function.getInstructions():
        if ins.mnemonic == "call" and ins.operands.startswith("0x"):
            call_instructions[ins.offset] = int(ins.operands, 16)
    return {
        "config_source": api_collection_files or None,
        "resolved": {off: function.apirefs.get(off) for off in call_instructions},
        "call_edges": call_instructions,
    }


def main():
    dump, site_offsets = build_dump()
    dump_sha256 = hashlib.sha256(dump).hexdigest()
    db_meta = {label: load_candidate_map(path) for label, path in DB_FILES.items()}

    cases = {
        "unconfigured": {},
        "target_matched_winxp_sp3": {"winxp": DB_FILES["winxp_sp3"]},
        "near_version_win7_sp1": {"win7": DB_FILES["win7_sp1"]},
        "both_unpinned_win7_first": {"win7": DB_FILES["win7_sp1"], "winxp": DB_FILES["winxp_sp3"]},
        "both_unpinned_winxp_first": {"winxp": DB_FILES["winxp_sp3"], "win7": DB_FILES["win7_sp1"]},
    }
    results = {name: run_case(name, files, dump) for name, files in cases.items()}

    print(f"dump sha256: {dump_sha256[:16]}  base: 0x{BASE_ADDR:x}  (identical bytes for every case)")
    header = "call site      insn@       raw target   " + "  ".join(f"{n:<28}" for n in cases)
    print("\n" + header)
    for label, target in CALL_SITES:
        off = site_offsets[label]
        row = f"{label:<14} 0x{off:08x}  0x{target:08x}   "
        for name in cases:
            resolved = results[name]["resolved"].get(off)
            row += "{:<28}  ".format(resolved if resolved else "(no name)")
        print(row)

    print("\ncall edges preserved without any DB (from unconfigured report):")
    for off, target in sorted(results["unconfigured"]["call_edges"].items()):
        print(f"  0x{off:08x} -> 0x{target:08x}")

    print("\nfull candidate sets per raw target (what a name-only report hides):")
    candidates_per_site = {}
    for label, target in CALL_SITES:
        candidates_per_site[label] = {
            db_label: db_meta[db_label]["candidates"].get(target, []) for db_label in DB_FILES
        }
        for db_label, names in candidates_per_site[label].items():
            print("  0x{:08x}  {:<10} {}".format(target, db_label, names or ["(absent)"]))

    minimal_context = {
        "sample": {"sha256": dump_sha256, "base_addr": BASE_ADDR, "bitness": 32, "architecture": "intel"},
        "smda_version": SmdaConfig.VERSION,
        "api_databases": {
            label: {
                "path": DB_FILES[label],
                "sha256": db_meta[label]["sha256"],
                "os_name": db_meta[label]["os_name"],
                "os_version": db_meta[label]["os_version"],
            }
            for label in DB_FILES
        },
        "call_sites": [
            {
                "instruction_offset": site_offsets[label],
                "raw_target": target,
                "candidates": candidates_per_site[label],
                "resolved_per_config": {case: results[case]["resolved"].get(site_offsets[label]) for case in cases},
            }
            for label, target in CALL_SITES
        ],
        "call_edges": {
            f"0x{off:08x}": f"0x{target:08x}" for off, target in sorted(results["unconfigured"]["call_edges"].items())
        },
    }
    with open(OUT_PATH, "w", encoding="utf-8") as f_out:
        json.dump(minimal_context, f_out, indent=2)
    print(f"\nwrote {os.path.relpath(OUT_PATH, REPO_ROOT)}")

    failures = []
    for case, sites in EXPECTED.items():
        for label, want in sites.items():
            got = results[case]["resolved"].get(site_offsets[label])
            if got != want:
                failures.append(f"{case}:{label} want {want!r} got {got!r}")
    if len(results["unconfigured"]["call_edges"]) != len(CALL_SITES):
        failures.append("unconfigured report lost call edges")
    if len(candidates_per_site["conflict"]["winxp_sp3"] + candidates_per_site["conflict"]["win7_sp1"]) < 2:
        failures.append("conflict site lost its ambiguity")
    if failures:
        print("\nFAIL:")
        for failure in failures:
            print("  " + failure)
        return 1
    print("\nOK: all expectations hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
