"""Conflicting instrumentation manifests sharing one provider GUID.

Three collectors are simulated. Collectors A and B ship a different *version* of the manifest
for the same provider GUID, while collector C ships a manifest that has no event entry matching
the descriptor written into the ETL. Each manifest is a valid Windows instrumentation manifest
that :func:`dissect.etl.manifest.compile_xml` accepts without modification.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

NS = "http://schemas.microsoft.com/win/2004/08/events"

XML_TEMPLATE = """<instrumentationManifest xmlns="{ns}">
 <instrumentation><events>
  <provider name="{provider_name}" guid="{{{guid}}}" symbol="{symbol}">
   <keywords>
    <keyword name="Trace" message="$(string.Trace)" mask="0x1"/>
   </keywords>
   <events>
{events}
   </events>
   <templates>
{templates}
   </templates>
  </provider>
 </events></instrumentation>
 <localization><resources culture="en-US"><stringTable>
  <string id="Trace" value="Trace"/>
 </stringTable></resources></localization>
</instrumentationManifest>
"""

EVENT_LINE = (
    '    <event value="{value}" symbol="{symbol}" version="{version}" opcode="{opcode}" '
    'level="win:Informational" keywords="Trace" template="{template}"/>'
)


def _manifest(
    guid: UUID,
    provider_name: str,
    symbol: str,
    event_symbol: str,
    template_tid: str,
    template_fields: str,
    *,
    event_value: int = 11,
    opcode: int = 11,
    version: int = 0,
) -> str:
    events = EVENT_LINE.format(
        value=event_value,
        symbol=event_symbol,
        version=version,
        opcode=opcode,
        template=template_tid,
    )
    return XML_TEMPLATE.format(
        ns=NS,
        provider_name=provider_name,
        symbol=symbol,
        guid=guid,
        events=events,
        templates=f'    <template tid="{template_tid}">\n{template_fields}\n    </template>',
    )


def manifest_a(guid: UUID) -> str:
    """Version from collector A: a UInt32 counter followed by a Unicode string label."""
    return _manifest(
        guid,
        provider_name="ConflictProvider-CollectorA",
        symbol="ConflictProviderA",
        event_symbol="MeasurementA",
        template_tid="TmplA",
        template_fields=(
            '     <data name="Counter" inType="win:UInt32"/>\n'
            '     <data name="Label" inType="win:UnicodeString"/>'
        ),
    )


def manifest_b(guid: UUID) -> str:
    """Version from collector B: the same descriptor key, but a purely numeric layout."""
    return _manifest(
        guid,
        provider_name="ConflictProvider-CollectorB",
        symbol="ConflictProviderB",
        event_symbol="MeasurementB",
        template_tid="TmplB",
        template_fields=(
            '     <data name="Counter" inType="win:UInt32"/>\n'
            '     <data name="NextDword" inType="win:UInt32"/>\n'
            '     <data name="TrailingWord" inType="win:UInt16"/>'
        ),
    )


def manifest_c(guid: UUID) -> str:
    """Manifest whose event entry does not match the descriptor.

    The only event entry is keyed ``(99, 0)`` while the ETL descriptor is ``(11, 0)``. During
    :class:`dissect.etl.etl.Event` construction ``EVENTS[(opcode, version)]`` therefore raises
    ``KeyError``, which is swallowed into ``self._struct = None``: the provider is still resolved but
    no field is parsed and no exception is raised. The unused ``TmplC`` template is still emitted so
    the generated module remains valid.
    """
    return _manifest(
        guid,
        provider_name="ConflictProvider-CollectorC",
        symbol="ConflictProviderC",
        event_symbol="MeasurementC",
        template_tid="TmplC",
        template_fields='     <data name="Counter" inType="win:UInt32"/>',
        event_value=99,
        opcode=99,
    )


VARIANTS = {
    "collector-a": manifest_a,
    "collector-b": manifest_b,
    "collector-c": manifest_c,
}


def write_repos(base_dir: Path, guid: UUID) -> dict[str, Path]:
    """Write each manifest as ``{GUID}.xml`` into its own collector repository directory."""
    locations: dict[str, Path] = {}
    for collector, factory in VARIANTS.items():
        repo_dir = base_dir / collector
        repo_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = repo_dir / f"{{{guid}}}.xml"
        manifest_path.write_text(factory(guid))
        locations[collector] = manifest_path
    return locations
