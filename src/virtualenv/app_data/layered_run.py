"""Drive a virtualenv creation with a read-only shared cache layered over a private staging folder.

This is a thin wrapper around the regular command line parsing. It only swaps the application data store
for a :class:`~virtualenv.app_data.layered.LayeredAppData` before any component is created, and routes the
seed image locks through the private layer, so every other option keeps its standard meaning and the shared
cache is never written to.
"""

from __future__ import annotations

__lazy_modules__ = [
    "virtualenv.report",
    "virtualenv.run",
    "virtualenv.seed.embed.via_app_data.via_app_data",
]

import os
import sys
from pathlib import Path
from threading import Thread
from typing import TYPE_CHECKING, Final

from virtualenv.app_data.layered import LayeredAppData
from virtualenv.run import build_parser
from virtualenv.run.session import Session
from virtualenv.seed.embed.via_app_data.via_app_data import FromAppData, _build_wheel_image

if TYPE_CHECKING:
    from collections.abc import MutableMapping

    from virtualenv.create.creator import Creator

#: Test/demo hook: when set, a missing seed image fails after its staging directory is created, so the recovery
#: path that reclaims the staging folder can be exercised without corrupting a real wheel.
FAIL_IMAGE_ENV: Final[str] = "VIRTUALENV_LAYERED_FAIL_IMAGE"


class LayeredFromAppData(FromAppData):
    """Seeder that reads shared images read-only and builds missing images in the private staging folder."""

    def run(self, creator: Creator) -> None:
        """Install the seed packages, keeping every lock and generated image inside the private layer.

        :param creator: the creator of the environment being seeded
        """
        if not self.enabled:
            return
        with self._get_seed_wheels(creator) as name_to_whl:
            installer_class = self.installer_class(
                name_to_whl["pip"].version_tuple if "pip" in name_to_whl else None
            )
            exceptions: dict = {}

            def _install(name: str, wheel) -> None:  # noqa: ANN001 - wheel type mirrors the base implementation
                try:
                    key = Path(installer_class.__name__) / wheel.path.stem
                    wheel_img = self.app_data.wheel_image(creator.interpreter.version_release_str, key)
                    installer = installer_class(wheel.path, creator, wheel_img)
                    # a shared read-only image is used as-is; only a miss takes a private lock and builds
                    if not installer.has_image():
                        private_img = self.app_data.lock_target(wheel_img)
                        installer = installer_class(wheel.path, creator, private_img)
                        parent = self.app_data.lock / private_img.parent
                        if os.environ.get(FAIL_IMAGE_ENV):
                            self._fail_after_staging(installer)
                        _build_wheel_image(parent, private_img.name, installer)
                    # version_info is a VersionInfo, which install types as a plain tuple
                    installer.install(creator.interpreter.version_info)  # ty: ignore[invalid-argument-type]
                except Exception:  # noqa: BLE001 - re-raised after every install finishes, as in the base seeder
                    exceptions[name] = sys.exc_info()

            threads = [Thread(target=_install, args=(n, w)) for n, w in name_to_whl.items()]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            if exceptions:
                import traceback

                messages = [f"layered seed failed for {', '.join(exceptions)} because:"]
                for exc_type, exc_value, exc_traceback in exceptions.values():
                    messages.append("".join(traceback.format_exception(exc_type, exc_value, exc_traceback)))
                raise RuntimeError("\n".join(messages))

    @staticmethod
    def _fail_after_staging(installer) -> None:  # noqa: ANN001 - installer is a PipInstall subclass
        """Make the next image build create its staging directory and then fail, exercising staging recovery.

        The replacement mirrors :meth:`PipInstall.build_image` failure semantics: the staging directory is
        removed before the exception propagates, so a caught failure never leaves temp files behind. A process
        killed before that cleanup runs is the separate orphan case audited after the fact.
        """
        from virtualenv.util.path import safe_delete

        def build_image_with_failure() -> None:
            staging = installer._image_dir.parent.with_name(  # noqa: SLF001 - mirrors PipInstall.build_image
                f"{installer._image_dir.parent.name}-{installer._image_dir.name}"
            )
            installer._image_dir.parent.mkdir(parents=True, exist_ok=True)  # noqa: SLF001
            staging.mkdir(exist_ok=True)
            (staging / "partial.txt").write_text("partial", encoding="utf-8")
            safe_delete(staging)
            raise RuntimeError(os.environ[FAIL_IMAGE_ENV])

        installer.build_image = build_image_with_failure  # type: ignore[method-assign]


def cli_run_layered(
    shared_folder: str,
    private_folder: str,
    args: list[str],
    env: MutableMapping[str, str] | None = None,
) -> tuple[Session, LayeredAppData]:
    """Create a virtual environment using the layered app data store.

    :param shared_folder: the pre-filled cache, mounted read-only and never written to
    :param private_folder: the project-owned writable staging folder for cache misses and locks
    :param args: the regular virtualenv command line arguments (without ``--app-data``)
    :param env: environment variables to use, defaults to the process environment
    :returns: the finished session and the layered store so callers can inspect both layers
    :raises RuntimeError: when the shared folder is missing or creation fails
    """
    env = os.environ if env is None else env
    parser, elements = build_parser(args, env=dict(env))
    options = parser.parse_args(args)
    # the parser carries the discovered interpreter, which ty cannot see
    options.py_version = parser._interpreter.version_info  # ruff:ignore[private-member-access]  # ty: ignore[union-attr, attr-defined]

    layered: Final[LayeredAppData] = LayeredAppData(shared_folder, private_folder)
    options.app_data = layered

    creator, seeder, activators = tuple(
        # parse_args returns a plain Namespace, not the typed VirtualEnvOptions ty expects
        element.create(options)  # ty: ignore[arg-type]
        for element in elements
    )
    # rebuild the seeder against the layered store when it is the standard app-data seeder
    if isinstance(seeder, FromAppData):
        seeder = LayeredFromAppData(options)  # ty: ignore[arg-type]
    session = Session(
        options.verbosity,  # ty: ignore[arg-type]
        layered,
        parser._interpreter,  # ruff:ignore[private-member-access]  # ty: ignore[arg-type]
        creator,  # ty: ignore[arg-type]
        seeder,  # ty: ignore[arg-type]
        activators,  # ty: ignore[arg-type]
    )
    with session:
        session.run()
    return session, layered


__all__ = ["LayeredFromAppData", "cli_run_layered"]
