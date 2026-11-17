#!/usr/bin/env python3
"""Offline P/Invoke binding candidate analysis, based on dnfile metadata.

This tool correlates ImplMap rows with ModuleRef entries, MethodDef
identities, and the ExactSpelling / CharSet / CallingConvention mapping
flags, then matches the declared import names against a caller-supplied
export manifest for an explicitly named target platform.

It never loads the referenced DLLs and never consults the analysis
machine's DLL search path.  Every reported candidate is a static
hypothesis derived from metadata plus the given export list; it is NOT
proof of which symbol the runtime loader will finally bind.

Usage:
    pinvoke_candidates.py ASSEMBLY --exports MANIFEST.json
                          [--platform windows|unix|unknown]
                          [--format text|json]

Manifest format:
    {
      "platform": "windows",               # optional; CLI flag wins
      "modules": {
        "KERNEL32.dll": {
          "names": ["GetVersion", "GetVersionW"],
          "ordinals": {"123": "OrdinalOnlyFunc"}
        }
      }
    }
"""

import argparse
import json
import sys
from dataclasses import dataclass, field

import dnfile
from dnfile.enums import CorPinvokeCallConv, CorPinvokeMapCharSet

# MappingFlags bit fields (ECMA-335 II.10.1.7).
PM_NOMANGLE = 0x0001
PM_CHARSET_MASK = 0x0006
PM_CALLCONV_MASK = 0x0700

STATUS_MATCHED = "matched"
STATUS_AMBIGUOUS = "ambiguous"
STATUS_NO_MATCH = "no-match"
STATUS_MODULE_NOT_PROVIDED = "module-not-provided"
STATUS_UNKNOWN = "unknown"
STATUS_UNSUPPORTED_CONVENTION = "unsupported-convention"

DISCLAIMER = (
    "Static candidates only: derived from metadata and the supplied export "
    "manifest. The runtime loader's final binding (search order, API sets, "
    "redirection, forwarding) is NOT established by this analysis."
)


@dataclass
class ExportManifest:
    """Caller-supplied, deliberately finite view of a target's exports."""

    modules: dict  # declared module name -> {"names": set, "ordinals": {int: str}}
    platform: str = "unknown"

    @staticmethod
    def from_dict(data):
        modules = {}
        for name, entry in (data.get("modules") or {}).items():
            modules[name] = {
                "names": set(entry.get("names") or []),
                "ordinals": {int(k): v for k, v in (entry.get("ordinals") or {}).items()},
            }
        return ExportManifest(modules=modules, platform=data.get("platform", "unknown"))

    def lookup_module(self, declared_name):
        """Find a manifest module for the declared ModuleRef name.

        Comparison is case-insensitive (Windows loader semantics); the
        declared name itself is never rewritten.
        """
        for name, entry in self.modules.items():
            if name.lower() == declared_name.lower():
                return name, entry
        return None, None


@dataclass
class PInvokeImport:
    """Evidence extracted from one ImplMap row, with declared values kept."""

    implmap_rid: int
    mapping_flags_raw: int
    mapping_flags_decoded: list
    method_token: int
    method_name: str
    method_signature_hex: str
    declaring_type: str
    import_name: str          # declared value, preserved verbatim
    module_name: str          # declared ModuleRef name, preserved verbatim
    moduleref_rid: int


@dataclass
class Candidate:
    match_kind: str           # exact | suffix-a | suffix-w | ordinal
    export_name: str = None
    ordinal: int = None


@dataclass
class AnalysisResult:
    imported: PInvokeImport
    status: str
    candidates: list = field(default_factory=list)
    steps: list = field(default_factory=list)


def decode_mapping_flags(raw):
    names = []
    if raw & PM_NOMANGLE:
        names.append("pmNoMangle")
    charset = raw & PM_CHARSET_MASK
    names.append(CorPinvokeMapCharSet(charset).name)
    callconv = raw & PM_CALLCONV_MASK
    try:
        names.append(CorPinvokeCallConv(callconv).name)
    except ValueError:
        names.append("pmCallConvUnknown(0x%04x)" % callconv)
    if raw & 0x0040:
        names.append("pmSupportsLastError")
    return names


def find_declaring_type(pe, method_rid):
    typedefs = pe.net.mdtables.TypeDef
    if not typedefs or not typedefs.rows:
        return None
    for row in typedefs:
        for index in row.MethodList or []:
            if index.row_index == method_rid:
                namespace = str(row.TypeNamespace) if row.TypeNamespace else ""
                name = str(row.TypeName)
                return namespace + "." + name if namespace else name
    return None


def extract_imports(pe):
    implmap = pe.net.mdtables.ImplMap
    if not implmap or not implmap.rows:
        return []
    results = []
    for rid, row in enumerate(implmap, start=1):
        raw = row.struct.MappingFlags
        member = row.MemberForwarded
        method_rid = member.row_index if member and member.table and member.table.name == "MethodDef" else None
        method = member.row if method_rid else None
        signature = method.Signature.value if method is not None and method.Signature is not None else b""
        results.append(
            PInvokeImport(
                implmap_rid=rid,
                mapping_flags_raw=raw,
                mapping_flags_decoded=decode_mapping_flags(raw),
                method_token=(0x06000000 | method_rid) if method_rid else 0,
                method_name=str(method.Name) if method is not None else "<unresolved>",
                method_signature_hex=signature.hex(),
                declaring_type=find_declaring_type(pe, method_rid) if method_rid else None,
                import_name=str(row.ImportName),
                module_name=str(row.ImportScope.row.Name) if row.ImportScope and row.ImportScope.row else "<unresolved>",
                moduleref_rid=row.ImportScope.row_index if row.ImportScope else 0,
            )
        )
    return results


def assess_calling_convention(raw, platform, steps):
    callconv = raw & PM_CALLCONV_MASK
    if callconv == CorPinvokeCallConv.pmCallConvWinapi or callconv == 0:
        steps.append(
            "calling convention winapi (platform default); name lookup is "
            "unaffected on platform '%s'" % platform
        )
        return True
    if callconv in (CorPinvokeCallConv.pmCallConvCdecl, CorPinvokeCallConv.pmCallConvStdcall):
        steps.append(
            "calling convention %s: supported by runtime P/Invoke"
            % CorPinvokeCallConv(callconv).name
        )
        return True
    if callconv in (CorPinvokeCallConv.pmCallConvThiscall, CorPinvokeCallConv.pmCallConvFastcall):
        steps.append(
            "calling convention %s: not supported by runtime P/Invoke; "
            "no binding candidate can succeed" % CorPinvokeCallConv(callconv).name
        )
        return False
    steps.append(
        "calling convention bits 0x%04x are not a documented value; "
        "treatment is unknown" % callconv
    )
    return None


def name_probes(import_name, raw, platform, steps):
    """Compute the export names the loader is documented to try.

    Returns a list of (name, match_kind), the string "ordinal" for
    ordinal imports, or None when the transformation cannot be decided
    from the known conditions (no candidate is forced in that case).
    """
    if import_name.startswith("#") and import_name[1:].isdigit():
        steps.append(
            "declared import name '%s' is ordinal form; name "
            "transformations do not apply" % import_name
        )
        return "ordinal"

    if raw & PM_NOMANGLE:
        steps.append(
            "pmNoMangle (ExactSpelling) set: only the declared name "
            "'%s' is probed, no suffix variants" % import_name
        )
        return [(import_name, "exact")]

    charset = raw & PM_CHARSET_MASK
    if charset == CorPinvokeMapCharSet.pmCharSetAnsi:
        steps.append(
            "CharSet.Ansi without ExactSpelling: probe '%sA' first, "
            "then the declared name" % import_name
        )
        return [(import_name + "A", "suffix-a"), (import_name, "exact")]
    if charset == CorPinvokeMapCharSet.pmCharSetUnicode:
        steps.append(
            "CharSet.Unicode without ExactSpelling: probe '%sW' first, "
            "then the declared name" % import_name
        )
        return [(import_name + "W", "suffix-w"), (import_name, "exact")]
    if charset == CorPinvokeMapCharSet.pmCharSetAuto:
        if platform == "windows":
            steps.append(
                "CharSet.Auto on platform 'windows': behaves as Unicode; "
                "probe '%sW' first, then the declared name" % import_name
            )
            return [(import_name + "W", "suffix-w"), (import_name, "exact")]
        if platform in ("unix", "linux", "macos"):
            steps.append(
                "CharSet.Auto on platform '%s': behaves as Ansi; "
                "probe '%sA' first, then the declared name" % (platform, import_name)
            )
            return [(import_name + "A", "suffix-a"), (import_name, "exact")]
        steps.append(
            "CharSet.Auto is platform-dependent and no target platform "
            "was supplied; the name transformation is unknown"
        )
        return None
    # pmCharSetNotSpec
    steps.append(
        "CharSet not specified: the .NET default behaves as Ansi "
        "(documented assumption); probe '%sA' first, then the declared name"
        % import_name
    )
    return [(import_name + "A", "suffix-a"), (import_name, "exact")]


def analyze_import(imported, manifest, platform):
    steps = []
    result = AnalysisResult(imported=imported, status=STATUS_UNKNOWN, steps=steps)

    supported = assess_calling_convention(imported.mapping_flags_raw, platform, steps)
    if supported is False:
        result.status = STATUS_UNSUPPORTED_CONVENTION
        return result
    if supported is None:
        result.status = STATUS_UNKNOWN
        return result

    probes = name_probes(imported.import_name, imported.mapping_flags_raw, platform, steps)
    if probes is None:
        result.status = STATUS_UNKNOWN
        return result

    manifest_name, module = manifest.lookup_module(imported.module_name)
    if module is None:
        steps.append(
            "module '%s' (ModuleRef #%d) is not present in the supplied "
            "export manifest; no candidate can be formed"
            % (imported.module_name, imported.moduleref_rid)
        )
        result.status = STATUS_MODULE_NOT_PROVIDED
        return result
    steps.append(
        "module '%s' matched manifest entry '%s' (%d names, %d ordinals)"
        % (imported.module_name, manifest_name, len(module["names"]), len(module["ordinals"]))
    )

    if probes == "ordinal":
        ordinal = int(imported.import_name[1:])
        if ordinal in module["ordinals"]:
            steps.append(
                "ordinal %d resolves to export '%s' in the manifest"
                % (ordinal, module["ordinals"][ordinal])
            )
            result.candidates.append(
                Candidate(match_kind="ordinal", export_name=module["ordinals"][ordinal], ordinal=ordinal)
            )
            result.status = STATUS_MATCHED
        else:
            steps.append("ordinal %d is not listed in the manifest" % ordinal)
            result.status = STATUS_NO_MATCH
        return result

    for name, kind in probes:
        if name in module["names"]:
            steps.append("probe name '%s' is present in the export list (%s)" % (name, kind))
            result.candidates.append(Candidate(match_kind=kind, export_name=name))
        else:
            steps.append("probe name '%s' is absent from the export list" % name)

    if len(result.candidates) == 1:
        result.status = STATUS_MATCHED
    elif len(result.candidates) > 1:
        steps.append(
            "multiple probe names match; no candidate is selected because "
            "the manifest cannot order them"
        )
        result.status = STATUS_AMBIGUOUS
    else:
        result.status = STATUS_NO_MATCH
    return result


def analyze(assembly_path, manifest, platform):
    pe = dnfile.dnPE(str(assembly_path))
    imports = extract_imports(pe)
    return [analyze_import(item, manifest, platform) for item in imports]


def result_to_dict(result):
    item = result.imported
    return {
        "implmap_rid": item.implmap_rid,
        "method_token": "0x%08x" % item.method_token,
        "method_name": item.method_name,
        "method_signature_hex": item.method_signature_hex,
        "declaring_type": item.declaring_type,
        "declared_import_name": item.import_name,
        "declared_module": item.module_name,
        "moduleref_rid": item.moduleref_rid,
        "mapping_flags_raw": "0x%04x" % item.mapping_flags_raw,
        "mapping_flags_decoded": item.mapping_flags_decoded,
        "status": result.status,
        "candidates": [
            {k: v for k, v in {
                "match_kind": c.match_kind,
                "export_name": c.export_name,
                "ordinal": c.ordinal,
            }.items() if v is not None}
            for c in result.candidates
        ],
        "steps": result.steps,
        "disclaimer": DISCLAIMER,
    }


def print_text(results):
    for result in results:
        item = result.imported
        print("ImplMap row #%d -> MethodDef 0x%08x '%s' (%s)" % (
            item.implmap_rid, item.method_token, item.method_name,
            item.declaring_type or "<no declaring type>"))
        print("  declared: ImportName='%s' Module='%s' (ModuleRef #%d) "
              "MappingFlags=0x%04x [%s]" % (
                  item.import_name, item.module_name, item.moduleref_rid,
                  item.mapping_flags_raw, ", ".join(item.mapping_flags_decoded)))
        for i, step in enumerate(result.steps, start=1):
            print("  step %d: %s" % (i, step))
        if result.candidates:
            rendered = ", ".join(
                c.export_name if c.match_kind != "ordinal"
                else "#%d (%s)" % (c.ordinal, c.export_name)
                for c in result.candidates
            )
            print("  result: %s -> %s" % (result.status, rendered))
        else:
            print("  result: %s" % result.status)
        print()
    print("note: " + DISCLAIMER)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("assembly", help="path to the .NET assembly to analyze")
    parser.add_argument("--exports", required=True,
                        help="JSON export manifest for the target platform")
    parser.add_argument("--platform", default=None,
                        choices=["windows", "unix", "linux", "macos", "unknown"],
                        help="target platform; overrides the manifest value")
    parser.add_argument("--format", default="text", choices=["text", "json"])
    args = parser.parse_args(argv)

    with open(args.exports, "r", encoding="utf-8") as handle:
        manifest = ExportManifest.from_dict(json.load(handle))
    platform = args.platform or manifest.platform or "unknown"

    results = analyze(args.assembly, manifest, platform)
    if args.format == "json":
        json.dump(
            {"platform": platform, "results": [result_to_dict(r) for r in results]},
            sys.stdout, indent=2,
        )
        print()
    else:
        print("platform: %s" % platform)
        print()
        print_text(results)
    return 0


if __name__ == "__main__":
    sys.exit(main())
