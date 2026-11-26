from __future__ import annotations

__lazy_modules__ = [
    "pathlib",
    "virtualenv.info",
    "virtualenv.util.path",
    f"{__spec__.parent}.system_site_packages",  # ty: ignore[missing-union-attribute]  # imported modules have a spec
]

import logging
from abc import ABC
from pathlib import Path
from typing import TYPE_CHECKING, Final

from virtualenv.config.cli.parser import ExtendAction
from virtualenv.create.creator import Creator, CreatorMeta
from virtualenv.create.via_global_ref import system_site_packages
from virtualenv.info import fs_supports_symlink
from virtualenv.util.path import write_file

if TYPE_CHECKING:
    from argparse import ArgumentParser

    from python_discovery import PythonInfo

    from virtualenv.app_data.base import AppData
    from virtualenv.config.cli.parser import VirtualEnvOptions

LOGGER: Final[logging.Logger] = logging.getLogger(__name__)  # simplint: ignore[module-variable-prefix]  # existing name


class ViaGlobalRefMeta(CreatorMeta):
    """Capability metadata for creators that link to or copy a global interpreter.

    The errors of a failed symlink or copy check are kept in ``symlink_error`` and ``copy_error``.

    :var copy_error: the reason the files cannot be copied, ``None`` when they can
    :var symlink_error: the reason the files cannot be symlinked, ``None`` when they can

    """

    def __init__(self) -> None:
        super().__init__()
        self.copy_error = None
        self.symlink_error = None
        if not fs_supports_symlink():
            self.symlink_error = "the filesystem does not supports symlink"

    @property
    def can_copy(self) -> bool:
        """Whether the environment can be created by copying files."""
        return not self.copy_error

    @property
    def can_symlink(self) -> bool:
        """Whether the environment can be created by symlinking files."""
        return not self.symlink_error


class ViaGlobalRefApi(Creator, ABC):
    """Base for creators that build an environment from files of a global interpreter, linking or copying them.

    :param options: the parsed command line options
    :param interpreter: the interpreter the environment is created from

    :var symlinks: ``True`` to link files instead of copying them
    :var enable_system_site_package: ``True`` to give the environment access to the system site-packages
    :var system_site_allow: the approved top-level names of a scoped inheritance, empty when unscoped
    :var system_site_dirs: the parent site directories of a scoped inheritance, empty when unscoped

    """

    def __init__(self, options: VirtualEnvOptions, interpreter: PythonInfo) -> None:
        super().__init__(options, interpreter)
        self.symlinks = self._should_symlink(options)
        self.enable_system_site_package = options.system_site
        self.system_site_allow = system_site_packages.approve(getattr(options, "system_site_allow", None) or ())
        self.system_site_dirs = system_site_packages.check_directories(
            getattr(options, "system_site_dir", None) or (),
        )
        if self.system_site_allow and self.enable_system_site_package:
            msg = (
                "--system-site-packages and --system-site-packages-allow exclude each other: the first exposes every "
                "system package, the second only the approved names"
            )
            raise ValueError(msg)
        if self.system_site_dirs and not self.system_site_allow:
            msg = "--system-site-packages-dir needs --system-site-packages-allow to name the approved packages"
            raise ValueError(msg)

    @staticmethod
    def _should_symlink(options: VirtualEnvOptions) -> bool:
        # Priority of where the option is set to follow the order: CLI, env var, file, hardcoded.
        # If both set at same level prefers copy over symlink.
        copies, symlinks = getattr(options, "copies", False), getattr(options, "symlinks", False)
        copy_src, sym_src = options.get_source("copies"), options.get_source("symlinks")
        for level in ["cli", "env var", "file", "default"]:
            s_opt = symlinks if sym_src == level else None
            c_opt = copies if copy_src == level else None
            if s_opt is True and c_opt is True:
                return False
            if s_opt is True:
                return True
            if c_opt is True:
                return False
        return False  # fallback to copy

    if TYPE_CHECKING:

        @property
        def purelib(self) -> Path:
            """The pure Python library directory of the environment."""
            ...

        @property
        def script_dir(self) -> Path:
            """The directory holding the scripts the environment installs."""
            ...

    @classmethod
    def add_parser_arguments(
        cls,
        parser: ArgumentParser,
        interpreter: PythonInfo,
        meta: ViaGlobalRefMeta,
        app_data: AppData,
        # narrows meta to ViaGlobalRefMeta, which the base hook types as CreatorMeta
    ) -> None:  # ty: ignore[incompatible-method-override]
        """Add the system site-packages, ``--symlinks`` and ``--copies`` options.

        The copy and symlink options are only added when the matching method is supported.

        :param parser: the parser to add the options to
        :param interpreter: the interpreter the environment is created from
        :param meta: the capability metadata of the interpreter
        :param app_data: the application data folder

        :raises RuntimeError: when neither symlinks nor copies are supported

        """
        super().add_parser_arguments(parser, interpreter, meta, app_data)
        parser.add_argument(
            "--system-site-packages",
            default=False,
            action="store_true",
            dest="system_site",
            help="give the virtual environment access to all of the system site-packages dir",
        )
        parser.add_argument(
            "--system-site-packages-allow",
            dest="system_site_allow",
            metavar="name",
            type=str,
            nargs="+",
            action=ExtendAction,
            default=[],
            help="give the environment access to only these top-level packages of the system site-packages",
        )
        parser.add_argument(
            "--system-site-packages-dir",
            dest="system_site_dir",
            metavar="d",
            type=Path,
            nargs="+",
            action=ExtendAction,
            default=[],
            help="an additional parent site-packages dir the approved packages may come from (can be set 1+ times)",
        )
        if not meta.can_symlink and not meta.can_copy:
            errors = []
            if meta.symlink_error:
                errors.append(f"symlink: {meta.symlink_error}")
            if meta.copy_error:
                errors.append(f"copy: {meta.copy_error}")
            msg = f"neither symlink or copy method supported: {', '.join(errors)}"
            raise RuntimeError(msg)
        group = parser.add_mutually_exclusive_group()
        if meta.can_symlink:
            group.add_argument(
                "--symlinks",
                default=True,
                action="store_true",
                dest="symlinks",
                help="try to use symlinks rather than copies, when symlinks are not the default for the platform",
            )
        if meta.can_copy:
            group.add_argument(
                "--copies",
                "--always-copy",
                default=not meta.can_symlink,
                action="store_true",
                dest="copies",
                help="try to use copies rather than symlinks, even when symlinks are the default for the platform",
            )

    def create(self) -> None:
        """Create the environment, installing the import patch and the system site-packages scope."""
        self.install_patch()
        self.install_system_site_scope()

    def install_patch(self) -> None:
        """Write the distutils guard files into the purelib folder, only on interpreters older than Python 3.10."""
        # Python 3.10+ ignores the distutils install config keys this patch guards against (pip does so by default,
        # setuptools and CPython's vendored distutils drop them too), so the runtime import hook only earns its
        # startup cost on 3.9. See https://github.com/pypa/virtualenv/issues/3181.
        if self.interpreter.version_info >= (3, 10):
            return
        if text := self.env_patch_text():
            pth = self.purelib / "_virtualenv.pth"
            LOGGER.debug("create virtualenv import hook file %s", pth)
            write_file(pth, b"import _virtualenv")
            dest_path = self.purelib / "_virtualenv.py"
            LOGGER.debug("create %s", dest_path)
            write_file(dest_path, text.encode("utf-8"))

    def install_system_site_scope(self) -> None:
        """Replace the runtime scope artifacts of the purelib folder with those of the selected mode."""
        if not self.system_site_allow:
            system_site_packages.remove_scope(self.purelib)
            return
        roots = system_site_packages.parent_directories(self.interpreter, self.system_site_dirs)
        system_site_packages.write_scope(self.purelib, self.system_site_scope_text(), self.system_site_allow, roots)

    def system_site_scope_text(self) -> str:
        """Return the source text of the runtime gate module.

        :returns: the gate source text

        """
        with self.app_data.ensure_extracted(
            Path(__file__).parent / f"{system_site_packages.GATE_MODULE}.py",
        ) as resolved_path:
            return resolved_path.read_text(encoding="utf-8")

    def env_patch_text(self) -> str:
        """Patch the distutils package to not be derailed by its configuration files.

        :returns: the source text of the patch module

        """
        with self.app_data.ensure_extracted(Path(__file__).parent / "_virtualenv.py") as resolved_path:
            return resolved_path.read_text(encoding="utf-8")

    def _args(self) -> list[tuple[str, str | bool]]:
        result = [*super()._args(), ("global", self.enable_system_site_package)]
        if self.system_site_allow:
            result.append(("allow", ",".join(self.system_site_allow)))
        return result

    def set_pyenv_cfg(self) -> None:
        """Record whether the system site-packages are visible to the environment, and the approved subset."""
        super().set_pyenv_cfg()
        self.pyenv_cfg["include-system-site-packages"] = "true" if self.enable_system_site_package else "false"
        if self.system_site_allow:
            # the approved names resolve through the runtime gate, so the interpreter itself must not add the parent
            # site directories to sys.path
            self.pyenv_cfg[system_site_packages.CFG_SCOPE_KEY] = system_site_packages.SCOPE_MARKER
            self.pyenv_cfg[system_site_packages.CFG_ALLOW_KEY] = " ".join(self.system_site_allow)


__all__ = [
    "ViaGlobalRefApi",
    "ViaGlobalRefMeta",
]
