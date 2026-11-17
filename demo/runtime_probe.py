"""Observe (never guess) the binding inputs a .NET host would use.

Two independent sources:

  1. The host's own metadata: assembly name, version, culture, public key
     token, and processor architecture.  This is what the binder *asks for*.
  2. Deployment configuration next to the host: deps.json, runtimeconfig.json,
     and a .NET Framework-style config with <assemblyBinding>.  This is what
     may *redirect* that request.

If neither file exists, the only honest statement is: the static policy's
choice is not a claim about runtime behaviour.  This module returns
`configured=False` in that case and never falls back to assumptions.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import identity as ident

def _host_base(path: Path) -> Path:
    name = path.name
    if name.lower().endswith((".exe", ".dll")):
        name = name[: -len(name.split(".")[-1]) - 1]
    return path.with_name(name)


def probe(host_path: str, display_host: str | None = None) -> dict[str, Any]:
    host = Path(host_path)
    base = _host_base(host)

    observations: list[dict[str, Any]] = []
    directives: list[dict[str, Any]] = []
    configured = False

    deps = base.with_name(base.name + ".deps.json")
    runtimeconfig = base.with_name(base.name + ".runtimeconfig.json")
    framework_config = base.with_name(base.name + ".config")

    if deps.is_file():
        configured = True
        data = json.loads(deps.read_text(encoding="utf-8"))
        targets = data.get("targets", {})
        libraries = data.get("libraries", {})
        observations.append(
            {
                "source": deps.name,
                "kind": "deps.json",
                "targets": sorted(targets.keys()),
                "libraries": {
                    name: {
                        "type": info.get("type"),
                        "serviceable": info.get("serviceable"),
                        "sha512": info.get("sha512"),
                    }
                    for name, info in libraries.items()
                },
                "runtime_asset_groups": _runtime_assets(targets),
            }
        )

    if runtimeconfig.is_file():
        configured = True
        data = json.loads(runtimeconfig.read_text(encoding="utf-8"))
        runtime_options = data.get("runtimeOptions", {})
        observations.append(
            {
                "source": runtimeconfig.name,
                "kind": "runtimeconfig.json",
                "tfm": runtime_options.get("tfm"),
                "framework": runtime_options.get("framework"),
                "frameworks": runtime_options.get("frameworks"),
                "roll_forward": runtime_options.get("rollForward"),
                "config_properties": runtime_options.get("configProperties"),
            }
        )
        if runtime_options.get("rollForward"):
            directives.append(
                {
                    "kind": "roll_forward",
                    "value": runtime_options["rollForward"],
                    "scope": "framework only; not a dependency binding rule",
                }
            )

    if framework_config.is_file():
        configured = True
        text = framework_config.read_text(encoding="utf-8", errors="replace")
        observations.append(
            {
                "source": framework_config.name,
                "kind": "app.config",
                "has_assembly_binding": "<assemblyBinding" in text,
                "has_code_base": "<codeBase" in text,
                "has_binding_redirect": "<bindingRedirect" in text,
            }
        )
        if "<bindingRedirect" in text:
            directives.append(
                {
                    "kind": "binding_redirect",
                    "scope": ".NET Framework only; ignored by .NET Core / .NET 5+",
                    "note": "redirect targets must be read from the file, not inferred",
                }
            )

    host_pe = _host_identity(host_path)

    return {
        "host": display_host or str(host),
        "configured": configured,
        "sources": observations,
        "directives": directives,
        "host_requested_identity": host_pe,
        "verdict": (
            "deployment configuration observed; binding may be redirected"
            if configured
            else "no deployment configuration observed; binding behaviour is unknown"
        ),
        "claim": (
            "none" if not configured else "observed-configuration-only"
        ),
    }


def _host_identity(host_path: str) -> dict[str, Any] | None:
    parsed = ident.parse_assembly(host_path)
    return parsed.identity.canonical() if parsed.identity else None


def _runtime_assets(targets: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for target, payload in targets.items():
        libraries = payload.get("", {}) if isinstance(payload, dict) else {}
        # deps.json nests libraries under an empty-string target key in some
        # writers, and directly in others; preserve whatever is present.
        groups = {}
        for name, info in (libraries or {}).items():
            runtime = info.get("runtime") if isinstance(info, dict) else None
            if runtime:
                groups[name] = sorted(runtime.keys())
        if not groups and isinstance(payload, dict):
            for name, info in payload.items():
                runtime = info.get("runtime") if isinstance(info, dict) else None
                if runtime:
                    groups[name] = sorted(runtime.keys())
        result[target] = groups
    return result
