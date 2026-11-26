"""Source-aware, shareable projections of ``tox config`` output.

The normal configuration view contains the exact values that tox passes to a
subprocess.  This module builds an additional read-only view which keeps the
decision trail (inheritance and replacements) while masking values derived
from non-public sources.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from tox.config.loader.ini import IniLoader
from tox.config.loader.native import to_native
from tox.config.loader.replacer import ConfigDefault, Replacer, ReplaceReference
from tox.util.redact import redact_value

from .common import format_config_error

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from tox.config.loader.api import Loader
    from tox.config.sets import ConfigSet
    from tox.session.state import State
    from tox.util.json_types import JsonValue

_BUILTIN_REFERENCES: Final[frozenset[str]] = frozenset({"", "/", "env", "tty", "posargs", "glob", "factor"})
_REFERENCE_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:\[(?P<section>[^\]]+)\])?(?P<key>[A-Za-z0-9_-]+)" r"(?::(?P<default>.*))?$",
    re.DOTALL,
)
_PRIVATE_NAME_RE: Final[re.Pattern[str]] = re.compile(
    r"PRIVATE|RESTRICTED|INTERNAL|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|API[_-]?KEY|AUTH",
    re.IGNORECASE,
)
REDACTION: Final[str] = "***"


@dataclass(slots=True)
class SourceTrace:
    """Collected provenance for one configuration set."""

    conf: ConfigSet
    sources: list[dict[str, JsonValue]] = field(default_factory=list)
    references: list[dict[str, JsonValue]] = field(default_factory=list)
    secrets: set[str] = field(default_factory=set)
    restricted: bool = False
    unresolved: list[str] = field(default_factory=list)
    has_error: bool = False

    def add_source(self, source: dict[str, JsonValue]) -> dict[str, JsonValue]:
        """Add a source once and return its JSON-safe descriptor."""
        source_id = str(source.get("id", ""))
        for existing in self.sources:
            if existing.get("id") == source_id:
                return existing
        self.sources.append(source)
        return source


def public_option_enabled(state: State) -> bool:
    """Return whether the caller asked for the shareable configuration view."""
    options = state.conf.options
    if bool(getattr(options, "public", False)):
        return True
    if getattr(options, "disclosure", None) == "public":
        return True
    if getattr(options, "config_view", None) == "public":
        return True
    return os.environ.get("TOX_SHOW_CONFIG_PUBLIC", "").lower() in {"1", "yes", "true", "on"}


def build_public_structured_result(
    state: State,
) -> tuple[dict[str, JsonValue], bool]:
    """Build the source-aware public result used by JSON and text formatters."""
    keys: list[str] = state.conf.options.list_keys_only
    show_everything = state.conf.options.env.is_all
    has_exception = False
    result: dict[str, JsonValue] = {
        "schema": "tox.show-config.public/v1",
        "public": True,
        "public_view": True,
        "disclosure": "public",
        "redaction": "provenance-bound",
    }

    envs: dict[str, JsonValue] = {}
    for name in state.envs.iter(package=True):
        tox_env = state.envs[name]
        env_data, exc = collect_public_conf(tox_env.conf, keys)
        has_exception = has_exception or exc
        envs[tox_env.conf.name] = env_data
    result["env"] = envs

    if show_everything or state.conf.options.show_core:
        tox_data, exc = collect_public_conf(state.conf.core, keys)
        has_exception = has_exception or exc
        result["tox"] = tox_data

    result["source_disclosure"] = _global_source_disclosure(result)
    return result, has_exception


def _global_source_disclosure(result: dict[str, JsonValue]) -> list[dict[str, JsonValue]]:
    """Merge per-section source groups to show disclosure by origin."""
    groups: dict[str, dict[str, JsonValue]] = {}
    for section_name in ("env", "tox"):
        section = result.get(section_name)
        sections = section.values() if section_name == "env" and isinstance(section, dict) else [section]
        for one_section in sections:
            if not isinstance(one_section, dict):
                continue
            for group in one_section.get("source_disclosure", []):
                if not isinstance(group, dict):
                    continue
                source_id = str(group.get("id", ""))
                merged = groups.setdefault(source_id, {**group, "sections": []})
                section_names = merged["sections"]
                if isinstance(section_names, list) and section_name not in section_names:
                    section_names.append(section_name)
    return list(groups.values())


def collect_public_conf(conf: ConfigSet, keys: Sequence[str]) -> tuple[dict[str, JsonValue], bool]:
    """Collect explained entries for one configuration section."""
    entries: dict[str, JsonValue] = {}
    values: dict[str, JsonValue] = {}
    provenance: dict[str, JsonValue] = {}
    has_exception = False

    selected_keys = list(keys) if keys else list(conf)
    for key in selected_keys:
        if key in conf:
            primary = conf.primary_key(key)
        elif keys:
            primary = key
        else:
            continue
        entry, failed = build_key_entry(conf, primary, allow_raw=bool(keys and key not in conf))
        has_exception = has_exception or failed
        entries[primary] = entry
        values[primary] = entry["value"]
        provenance[primary] = {
            name: value
            for name, value in entry.items()
            if name
            in {
                "status",
                "resolution",
                "visibility",
                "redacted",
                "sources",
                "origin",
                "inheritance",
                "references",
                "chain",
                "unresolved_references",
                "explanation",
            }
        }

    if (unused := conf.unused()) and not keys:
        entries["unused"] = sorted(unused)
        values["unused"] = sorted(unused)

    entries["source_disclosure"] = _source_disclosure(entries)
    entries["values"] = values
    entries["provenance"] = provenance
    return entries, has_exception


def _source_disclosure(entries: dict[str, JsonValue]) -> list[dict[str, JsonValue]]:
    """Group explained keys by each source that contributed to them."""
    groups: dict[str, dict[str, JsonValue]] = {}
    for key, entry in entries.items():
        if not isinstance(entry, dict) or not isinstance(entry.get("sources"), list):
            continue
        for source in entry["sources"]:
            if not isinstance(source, dict):
                continue
            source_id = str(source.get("id") or source.get("label") or "unknown")
            group = groups.setdefault(
                source_id,
                {
                    "id": source_id,
                    "source": source,
                    "visibility": source.get("visibility", "public"),
                    "private": bool(source.get("private", False)),
                    "keys": [],
                },
            )
            keys = group["keys"]
            if isinstance(keys, list) and key not in keys:
                keys.append(key)
    return list(groups.values())


def build_key_entry(conf: ConfigSet, key: str, *, allow_raw: bool = False) -> tuple[dict[str, JsonValue], bool]:
    """Build one JSON-safe explained configuration entry."""
    is_registered = key in conf
    aliases = _definition_keys(conf, key) if is_registered else (key,)
    inheritance, raw, raw_key, origin_loader = find_raw_origin(conf, aliases)
    trace = SourceTrace(conf=conf)
    origin: dict[str, JsonValue] | None = None
    if inheritance:
        origin = next((item for item in inheritance if item.get("selected") is True), inheritance[0])
        trace.add_source(origin)

    native: JsonValue = None
    load_error: str | None = None
    failed = False
    if is_registered:
        try:
            native = to_native(conf[key])
        except Exception as exception:  # mirror show-config's materialization boundary
            if os.environ.get("_TOX_SHOW_CONFIG_RAISE"):
                raise
            failed = True
            load_error = format_config_error(exception)

    expanded_raw: str | None = None
    if raw is not None and origin_loader is not None:
        expanded_raw = _trace_raw_value(conf, raw, origin_loader, trace)
    if not is_registered and allow_raw and load_error is None:
        native = (
            expanded_raw
            if expanded_raw is not None
            else (raw if isinstance(raw, (str, int, float, bool)) else str(raw))
        )

    for source in inheritance:
        if source.get("present", True) or source.get("kind") in {"default", "constant"}:
            trace.add_source(source)

    secret_values = {secret for secret in trace.secrets if secret}
    restricted = trace.restricted or bool(secret_values)
    safe_native = _redact_native(
        native if load_error is None else {"error": _redact_text(load_error, secret_values)},
        secret_values,
    )

    unresolved = list(dict.fromkeys(trace.unresolved))
    if load_error is not None:
        status = "error"
        resolution = "error"
    elif unresolved:
        status = "unresolved"
        resolution = "unresolved"
    elif restricted:
        status = "redacted"
        resolution = "resolved"
    else:
        status = "public"
        resolution = "resolved"

    chain = _build_chain(origin, trace.references)
    source_list = trace.sources
    display_value = _display_value(safe_native)
    if load_error is not None:
        error_text = safe_native.get("error", load_error) if isinstance(safe_native, dict) else safe_native
        display_value = f"[error] {error_text}"
    entry: dict[str, JsonValue] = {
        "key": key,
        "registered": is_registered,
        "value": safe_native,
        "safe_value": safe_native,
        "public_value": safe_native,
        "display_value": display_value,
        "raw": _redact_text(str(raw), secret_values) if raw is not None else None,
        "status": status,
        "resolution": resolution,
        "visibility": "restricted" if restricted else "public",
        "sensitivity": "private" if restricted else "public",
        "redacted": restricted,
        "contains_private_source": restricted,
        "sources": source_list,
        "origin": origin,
        "source": origin.get("label") if origin else ("default" if _has_default(conf, key) else "unknown"),
        "inheritance": inheritance,
        "references": trace.references,
        "chain": chain,
        "derived_from": [item.get("id") for item in trace.references],
        "unresolved_references": unresolved,
        "explanation": _explain(key, origin, inheritance, trace.references, unresolved, restricted),
    }
    inherited_from = [
        source.get("label") or source.get("id")
        for source in inheritance
        if source.get("present", True) and source.get("selected") is not True
    ]
    private_sources = [source for source in source_list if source.get("private") is True]
    entry.update(
        {
            "resolved": status not in {"unresolved", "error"},
            "is_redacted": restricted,
            "inherited_from": inherited_from,
            "replacement_chain": chain,
            "provenance_chain": chain,
            "private_sources": private_sources,
            "redacted_from": [source.get("id") for source in private_sources],
        }
    )
    if load_error is not None:
        entry["error"] = safe_native["error"] if isinstance(safe_native, dict) else safe_native
    return entry, failed


def _definition_keys(conf: ConfigSet, key: str) -> tuple[str, ...]:
    definition = conf._defined.get(key)  # noqa: SLF001 - tox's own config registry
    if definition is None:
        return (key,)
    return tuple(definition.keys)


def _has_default(conf: ConfigSet, key: str) -> bool:
    definition = conf._defined.get(key)  # noqa: SLF001
    return definition is not None and not isinstance(definition, type(None))


def find_raw_origin(
    conf: ConfigSet, aliases: Iterable[str]
) -> tuple[list[dict[str, JsonValue]], Any, str | None, Loader[Any] | None]:
    """Find raw loader values and the selected inheritance position."""
    alias_tuple = tuple(dict.fromkeys(aliases))
    inheritance: list[dict[str, JsonValue]] = []
    selected_raw: Any = None
    selected_key: str | None = None
    selected_loader: Loader[Any] | None = None

    for index, loader in enumerate(conf.loaders):
        descriptor = _loader_source(conf, loader, index)
        found_here = False
        for alias in alias_tuple:
            try:
                if alias not in loader.found_keys() and not _loader_has_override(loader, alias):
                    continue
            except Exception:  # pragma: no cover - defensive for third-party loaders
                pass
            try:
                raw = loader.load_raw(alias, conf._conf, conf.env_name)  # noqa: SLF001
            except KeyError:
                continue
            except Exception:
                # Factor filtering can reject a line; inheritance still has a candidate but no usable raw origin.
                raw = None
            found_here = True
            descriptor["present"] = True
            descriptor["key"] = alias
            descriptor["id"] = f"{descriptor['id']}#{alias}"
            descriptor["label"] = f"{descriptor['label']} {alias}"
            if selected_loader is None and raw is not None:
                descriptor["selected"] = True
                descriptor["role"] = "override" if _loader_has_override(loader, alias) else "value"
                selected_raw = raw
                selected_key = alias
                selected_loader = loader
            else:
                descriptor["selected"] = False
                descriptor["role"] = "shadowed"
            break
        descriptor.setdefault("present", found_here)
        if not found_here:
            descriptor["role"] = "section-without-key"
        inheritance.append(descriptor)

    if selected_loader is None:
        source = _default_source(conf)
        inheritance.append(source)
    return inheritance, selected_raw, selected_key, selected_loader


def _loader_has_override(loader: Loader[Any], key: str) -> bool:
    return key in loader.overrides or any(
        key in getattr(entry, "key", "") for entries in loader.overrides.values() for entry in entries
    )


def _loader_source(conf: ConfigSet, loader: Loader[Any], index: int) -> dict[str, JsonValue]:
    section = getattr(loader, "section", conf._section)  # noqa: SLF001
    section_key = getattr(section, "key", conf.name)
    actual_section = None
    proxy = getattr(loader, "_section_proxy", None)
    if proxy is not None:
        actual_section = getattr(proxy, "name", None)
    source_path = getattr(conf._conf, "src_path", None)  # noqa: SLF001
    path_label = _path_label(source_path)
    kind = _source_kind(loader)
    private = _loader_is_private(loader)
    source_id = f"{kind}:{path_label}#{section_key}"
    return {
        "kind": kind,
        "type": kind,
        "id": source_id,
        "label": f"{path_label} [{actual_section or section_key}]",
        "path": path_label,
        "section": actual_section or section_key,
        "requested_section": section_key,
        "loader": type(loader).__name__,
        "order": index,
        "inherited": index > 0,
        "visibility": "restricted" if private else "public",
        "private": private,
        "selected": False,
    }


def _source_kind(loader: Loader[Any]) -> str:
    class_name = type(loader).__name__.lower()
    if "memory" in class_name:
        return "memory"
    if "toml" in class_name:
        return "toml"
    if "ini" in class_name:
        return "ini"
    return class_name or "loader"


def _loader_is_private(loader: Loader[Any]) -> bool:
    for attr in ("visibility", "disclosure", "sensitivity", "public", "private", "sensitive"):
        if hasattr(loader, attr):
            value = getattr(loader, attr)
            if attr in {"public"}:
                return value is False
            if attr in {"private", "sensitive"}:
                return bool(value)
            if isinstance(value, str):
                return value.lower() in {"private", "restricted", "sensitive", "internal"}
    return False


def _default_source(conf: ConfigSet) -> dict[str, JsonValue]:
    constant = False
    primary = next(iter(conf), None)
    if primary is not None:
        constant = conf.is_constant(primary)
    kind = "constant" if constant else "default"
    return {
        "kind": kind,
        "type": kind,
        "id": f"{kind}:{conf.name}",
        "label": kind,
        "section": conf.name,
        "visibility": "public",
        "private": False,
        "selected": True,
        "inherited": False,
    }


def _path_label(path: object) -> str:
    if not isinstance(path, Path):
        return "config"
    try:
        return str(path.relative_to(Path.cwd()))
    except ValueError:
        return path.name


def _trace_raw_value(conf: ConfigSet, raw: Any, loader: Loader[Any], trace: SourceTrace) -> str | None:
    if not isinstance(raw, str):
        if isinstance(raw, (list, tuple)):
            for item in raw:
                _trace_raw_value(conf, item, loader, trace)
        elif isinstance(raw, dict):
            for item in raw.values():
                _trace_raw_value(conf, item, loader, trace)
        elif raw is not None:
            return _trace_text_references(conf, str(raw), loader, trace)
        return None
    return _trace_text_references(conf, raw, loader, trace)


class _NullReference(ReplaceReference):
    """Reference resolver used for loader types without INI section syntax."""

    def __call__(self, value: str, conf_args: Any) -> str | ConfigDefault | None:
        return None


def _trace_text_references(conf: ConfigSet, raw: str, loader: Loader[Any], trace: SourceTrace) -> str | None:
    # Imported here to keep module import cost close to the feature that uses it.
    from tox.config.loader.ini.replace import ReplaceReferenceIni

    class _ProvenanceReplacer(Replacer):
        provenance_trace: SourceTrace

        def _nested(self, conf_args: Any) -> _ProvenanceReplacer:
            nested = super()._nested(conf_args)
            nested.provenance_trace = self.provenance_trace
            return nested

        def _resolve_replace(self, of_type: str, args: list[str], flattened_args: list[str], conf_args: Any) -> Any:
            if of_type == "env":
                return self._resolve_env(of_type, args, super_result=super()._resolve_replace)
            if of_type in _BUILTIN_REFERENCES:
                return super()._resolve_replace(of_type, args, flattened_args, conf_args)

            reference = ":".join(flattened_args)
            before = len(self.provenance_trace.references)
            try:
                result = super()._resolve_replace(of_type, args, flattened_args, conf_args)
            except Exception as exception:
                self.provenance_trace.unresolved.append(reference)
                self.provenance_trace.references.append(
                    _reference_record(reference, "invalid", conf, loader, error=type(exception).__name__)
                )
                raise
            status = "resolved" if result is not None else "unresolved"
            if isinstance(result, ConfigDefault):
                status = "default"
            record = _reference_record(reference, status, conf, loader)
            if result is None:
                self.provenance_trace.unresolved.append(reference)
                record["visibility"] = "restricted" if record.get("visibility") == "restricted" else "public"
            self.provenance_trace.references.append(record)
            if len(self.provenance_trace.references) != before + 1:  # pragma: no cover - clarity guard
                pass
            return result

        def _resolve_env(self, of_type: str, args: list[str], super_result: Any) -> Any:
            name = args[0] if args else ""
            private = _environment_is_private(name)
            source: dict[str, JsonValue] = {
                "kind": "environment",
                "type": "environment",
                "id": f"env:{name}",
                "label": f"${{{name}}}",
                "name": name,
                "environment_variable": name,
                "visibility": "restricted" if private else "public",
                "private": private,
                "selected": True,
            }
            self.provenance_trace.add_source(source)
            if private:
                self.provenance_trace.restricted = True
                if name in os.environ:
                    self.provenance_trace.secrets.add(os.environ[name])
            in_host_environment = name in os.environ
            try:
                conf_args = self.conf_args.copy()
                result = super_result(of_type, args, [of_type, *args], conf_args)
            except Exception:
                self.provenance_trace.unresolved.append(f"env:{name}")
                self.provenance_trace.references.append(
                    {
                        "type": "environment",
                        "id": f"env:{name}",
                        "reference": f"{{env:{name}}}",
                        "target": f"env:{name}",
                        "status": "invalid",
                        "resolution": "invalid",
                        "visibility": "restricted" if private else "public",
                    }
                )
                raise
            result_text = result.text if isinstance(result, ConfigDefault) else result
            if in_host_environment or (isinstance(result_text, str) and not isinstance(result, ConfigDefault)):
                status = "resolved"
            elif isinstance(result, ConfigDefault):
                status = "default"
            else:
                status = "unresolved"
            if private and status == "resolved" and isinstance(result_text, str) and result_text:
                self.provenance_trace.secrets.add(result_text)
            if status == "unresolved":
                self.provenance_trace.unresolved.append(f"env:{name}")
            self.provenance_trace.references.append(
                {
                    "type": "environment",
                    "id": f"env:{name}",
                    "reference": f"{{env:{name}}}",
                    "target": f"env:{name}",
                    "name": name,
                    "status": status,
                    "resolution": status,
                    "visibility": "restricted" if private else "public",
                    "source": source,
                }
            )
            return result

    global_conf = conf._conf  # noqa: SLF001
    reference: ReplaceReference = (
        ReplaceReferenceIni(global_conf, loader) if isinstance(loader, IniLoader) else _NullReference()
    )
    args = _load_args(conf)
    replacer = _ProvenanceReplacer(global_conf, reference, args)
    replacer.provenance_trace = trace
    try:
        return replacer.expand(raw)
    except Exception as exception:
        trace.unresolved.append(raw)
        trace.references.append(
            {
                "type": "expression",
                "id": f"expression:{raw}",
                "reference": raw,
                "status": "invalid",
                "resolution": "invalid",
                "error": type(exception).__name__,
                "visibility": "public",
            }
        )
        return None


def _load_args(conf: ConfigSet) -> Any:
    from tox.config.loader.api import ConfigLoadArgs

    return ConfigLoadArgs([], conf.name, conf.env_name)


def _environment_is_private(name: str) -> bool:
    if not name:
        return True
    if redact_value(name, "x") == "*":
        return True
    return bool(_PRIVATE_NAME_RE.search(name))


def _reference_record(
    reference: str, status: str, conf: ConfigSet, loader: Loader[Any], *, error: str | None = None
) -> dict[str, JsonValue]:
    match = _REFERENCE_RE.match(reference.strip())
    section = match.group("section") if match else None
    key = match.group("key") if match else reference
    target_conf, descriptor = _reference_origin(conf, section, key, loader)
    restricted = bool(descriptor and descriptor.get("private"))
    record: dict[str, JsonValue] = {
        "type": "config",
        "id": f"config:{section or conf.name}:{key}",
        "reference": reference,
        "target": f"{section or conf.name}.{key}",
        "section": section,
        "key": key,
        "status": status,
        "resolution": status,
        "visibility": "restricted" if restricted else "public",
        "origin": descriptor,
        "source": descriptor.get("label") if descriptor else None,
    }
    if error:
        record["error"] = error
    if target_conf is not None:
        aliases = _definition_keys(target_conf, key) if key in target_conf else (key,)
        _, raw, _, origin_loader = find_raw_origin(target_conf, aliases)
        if raw is not None and origin_loader is not None:
            # The active replacer records nested edges itself; this only keeps source descriptors available.
            record["raw_origin"] = True
    return record


def _reference_origin(
    conf: ConfigSet, section: str | None, key: str, loader: Loader[Any]
) -> tuple[ConfigSet | None, dict[str, JsonValue] | None]:
    global_conf = conf._conf  # noqa: SLF001
    try:
        if section is None:
            if key in conf:
                return conf, find_raw_origin(conf, _definition_keys(conf, key))[0][
                    0
                ] if False else _selected_descriptor(conf, key)
            if key in global_conf.core:
                return global_conf.core, _selected_descriptor(global_conf.core, key)
            return conf, _selected_descriptor(conf, key)
        if section in {global_conf.core.name.key if hasattr(global_conf.core.name, "key") else "tox", "tox"}:
            return global_conf.core, _selected_descriptor(global_conf.core, key)
        if ":" in section:
            prefix, name = section.split(":", 1)
            if prefix in {"testenv", "pkg-env"} and name in global_conf:
                target = global_conf.get_env(name)
                return target, _selected_descriptor(target, key)
        if section == "testenv":
            for candidate in conf.loaders:
                candidate_section = getattr(candidate, "section", None)
                if getattr(candidate_section, "key", "") == "testenv":
                    descriptor = _loader_source(conf, candidate, conf.loaders.index(candidate))
                    descriptor["key"] = key
                    descriptor["selected"] = True
                    return conf, descriptor
        proxy = getattr(loader, "get_section", lambda _name: None)(section)
        if proxy is not None:
            return conf, {
                "kind": "ini",
                "type": "ini",
                "id": f"ini:{_path_label(global_conf.src_path)}#{section}#{key}",
                "label": f"{_path_label(global_conf.src_path)} [{section}] {key}",
                "path": _path_label(global_conf.src_path),
                "section": section,
                "key": key,
                "visibility": "public",
                "private": False,
                "selected": True,
            }
    except Exception:
        return None, None
    return None, None


def _selected_descriptor(conf: ConfigSet, key: str) -> dict[str, JsonValue] | None:
    aliases = (key,) if key not in conf else _definition_keys(conf, conf.primary_key(key))
    inheritance, _, _, _ = find_raw_origin(conf, aliases)
    return next((item for item in inheritance if item.get("selected") is True), inheritance[0] if inheritance else None)


def _build_chain(origin: dict[str, JsonValue] | None, references: Sequence[dict[str, JsonValue]]) -> list[str]:
    chain: list[str] = []
    if origin:
        chain.append(str(origin.get("label") or origin.get("id") or "origin"))
    for reference in references:
        target = reference.get("target") or reference.get("reference")
        status = reference.get("status")
        chain.append(f"{target} [{status}]")
    return chain


def _explain(
    key: str,
    origin: dict[str, JsonValue] | None,
    inheritance: Sequence[dict[str, JsonValue]],
    references: Sequence[dict[str, JsonValue]],
    unresolved: Sequence[str],
    restricted: bool,
) -> str:
    parts: list[str] = []
    if origin:
        action = (
            "overridden at"
            if origin.get("role") == "override" or origin.get("order") == 0 and len(inheritance) > 1
            else "loaded from"
        )
        parts.append(f"{key} {action} {origin.get('label')}")
        inherited = [
            item.get("label")
            for item in inheritance
            if not item.get("selected") and item.get("section") != origin.get("section")
        ]
        if inherited:
            parts.append("inherits " + ", ".join(str(item) for item in inherited))
    if references:
        parts.append(
            "references " + " -> ".join(str(item.get("target") or item.get("reference")) for item in references)
        )
    if unresolved:
        parts.append("unresolved: " + ", ".join(unresolved))
    parts.append(
        "value is masked because a referenced source is not public"
        if restricted
        else "all referenced sources are public"
    )
    return "; ".join(parts)


def _redact_native(value: JsonValue, secrets: set[str]) -> JsonValue:
    if isinstance(value, str):
        return _redact_text(value, secrets)
    if isinstance(value, list):
        return [_redact_native(item, secrets) for item in value]
    if isinstance(value, dict):
        return {str(key): _redact_native(item, secrets) for key, item in value.items()}
    return value


def _redact_text(text: str, secrets: Iterable[str]) -> str:
    result = text
    for secret in sorted((item for item in secrets if item), key=len, reverse=True):
        if secret in result:
            result = result.replace(secret, "*" * len(secret))
    return result


def _display_value(value: JsonValue) -> str:
    if isinstance(value, str):
        return value
    return _stringify_json_value(value)


def _stringify_json_value(value: JsonValue) -> str:
    if isinstance(value, list):
        return "\n".join(_stringify_json_value(item) for item in value)
    if isinstance(value, dict):
        return "\n".join(f"{key} = {_stringify_json_value(item)}" for key, item in value.items())
    if value is None:
        return ""
    return str(value)


build_public_view = build_public_structured_result
build_public_config = build_public_structured_result
public_config_view = build_public_structured_result


__all__ = [
    "build_public_config",
    "build_public_structured_result",
    "build_public_view",
    "collect_public_conf",
    "public_config_view",
    "public_option_enabled",
]
