from __future__ import annotations

import argparse
import logging
from pathlib import Path

from dissect.util import ts

from dissect.shellitem.lnk import Lnk
from dissect.shellitem.lnk.encoding import AnsiCodec, EncodedText

log = logging.getLogger(__name__)
logging.lastResort = None
logging.raiseExceptions = False


def _render(field: EncodedText | None) -> str | None:
    """Render a field without ever consulting the host locale.

    Pending ANSI fields are shown as an explicit undecoded marker plus their
    raw bytes, rather than being force-decoded through an assumed code page.
    """
    if field is None:
        return None
    if field.is_pending:
        return f"<undecoded ANSI, raw={field.raw.hex()}>"
    return field.text


def parse(path: Path, ansi_codec: AnsiCodec | None = None, explain: bool = False) -> None:
    lnk_file = Lnk(path.open("rb"), ansi_codec=ansi_codec)
    lnk_net_name = lnk_device_name = None

    if lnk_file.link_header:
        lnk_path = path
        lnk_name = _render(lnk_file.stringdata.name_string.string) if lnk_file.flag("has_name") else None

        lnk_mtime = ts.from_unix(path.stat().st_mtime)
        lnk_atime = ts.from_unix(path.stat().st_atime)
        lnk_ctime = ts.from_unix(path.stat().st_ctime)

        lnk_relativepath = (
            _render(lnk_file.stringdata.relative_path.string) if lnk_file.flag("has_relative_path") else None
        )
        lnk_workdir = _render(lnk_file.stringdata.working_dir.string) if lnk_file.flag("has_working_dir") else None
        lnk_iconlocation = (
            _render(lnk_file.stringdata.icon_location.string) if lnk_file.flag("has_icon_location") else None
        )
        lnk_arguments = (
            _render(lnk_file.stringdata.command_line_arguments.string) if lnk_file.flag("has_arguments") else None
        )

        local_base_path = (
            _render(lnk_file.text_fields.get("linkinfo.local_base_path"))
            if lnk_file.flag("has_link_info") and lnk_file.linkinfo.flag("volumeid_and_local_basepath")
            else None
        )
        common_path_suffix = (
            _render(lnk_file.text_fields.get("linkinfo.common_path_suffix")) if lnk_file.flag("has_link_info") else None
        )

        if local_base_path and common_path_suffix:
            lnk_full_path = local_base_path + common_path_suffix
        elif local_base_path and not common_path_suffix:
            lnk_full_path = local_base_path
        else:
            lnk_full_path = None

        if lnk_file.flag("has_link_info") and lnk_file.linkinfo.flag("common_network_relative_link_and_pathsuffix"):
            lnk_net_name = _render(lnk_file.text_fields.get("linkinfo.common_network_relative_link.net_name"))
            lnk_device_name = _render(lnk_file.text_fields.get("linkinfo.common_network_relative_link.device_name"))

        machine_field = lnk_file.extradata.text_fields.get("extradata.TRACKER_PROPS.machine_id")
        machine_id = _render(machine_field)

        target_mtime = ts.wintimestamp(lnk_file.link_header.write_time)
        target_atime = ts.wintimestamp(lnk_file.link_header.access_time)
        target_ctime = ts.wintimestamp(lnk_file.link_header.creation_time)

        print(
            f"Link Path\t\t\t: {lnk_path}\n"
            f"Link Name / description\t\t: {lnk_name}\n"
            f"Link modification time\t\t: {lnk_mtime}\n"
            f"Link access time\t\t: {lnk_atime}\n"
            f"Link changed time\t\t: {lnk_ctime}\n"
            f"Link relative path\t\t: {lnk_relativepath}\n"
            f"Link working directory\t\t: {lnk_workdir}\n"
            f"Link icon location\t\t: {lnk_iconlocation}\n"
            f"Link arguments\t\t\t: {lnk_arguments}\n"
            f"Link local base path\t\t: {local_base_path}\n"
            f"Link common path suffix\t\t: {common_path_suffix}\n"
            f"Link full path\t\t\t: {lnk_full_path}\n"
            f"Net name link\t\t\t: {lnk_net_name}\n"
            f"Device name link\t\t: {lnk_device_name}\n"
            f"Machine id link\t\t\t: {machine_id}\n"
            f"Target file modification time\t: {target_mtime}\n"
            f"Target file access time\t\t: {target_atime}\n"
            f"Target file changed time\t: {target_ctime}\n"
        )

        if lnk_file.console_fe_code_pages:
            print(f"ConsoleFE code pages (not auto-applied)\t: {lnk_file.console_fe_code_pages}")
            if lnk_file.console_fe_conflict:
                print("WARNING: conflicting ConsoleFE code page declarations were found.")
        if explain:
            print("Encoding decisions:")
            print(lnk_file.explain_text())


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse a .lnk file from your local disk.",
    )

    parser.add_argument("paths", metavar="paths", type=str, nargs="+", help="Path to .lnk file(s).")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity")
    parser.add_argument(
        "-a",
        "--ansi-codec",
        metavar="CODEC",
        type=str,
        default=None,
        help=(
            "Python codec (e.g. cp932, cp1252) for the file's ANSI fields, supplied out of band by the caller. "
            "Without it, ANSI fields stay undecoded and pending. A ConsoleFE code page is never assumed to apply."
        ),
    )
    parser.add_argument(
        "--ansi-provenance",
        metavar="SOURCE",
        type=str,
        default="cli",
        help="Free-form justification recorded with --ansi-codec as the decoding provenance.",
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        help="Print the per-field encoding basis alongside the parsed output.",
    )

    args = parser.parse_args()

    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    level = levels[min(len(levels) - 1, args.verbose)]
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(message)s")

    ansi_codec = AnsiCodec(codec=args.ansi_codec, provenance=f"cli:{args.ansi_provenance}") if args.ansi_codec else None

    for path in args.paths:
        path = Path(path)

        if path.is_dir():
            continue

        parse(Path(path), ansi_codec=ansi_codec, explain=args.explain)


if __name__ == "__main__":
    main()
