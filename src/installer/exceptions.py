"""Errors raised from this package."""


class InstallerError(Exception):
    """All exceptions raised from this package's code."""


class InvalidWheelSource(InstallerError):
    """When a wheel source violates a contract, or is not supported."""


class BytecodeCompilationError(InstallerError):
    """Raised when required bytecode could not be prepared during installation.

    The installation is aborted before it is admitted: the ``RECORD`` file is
    not written, files created by the current installation are removed and any
    pre-existing files that were overwritten are restored.
    """

    def __init__(self, failures: list[tuple[str, int, str]]) -> None:
        """Initialize the error.

        :param failures: ``(path, optimization_level, message)`` triples, describing
            every source file that could not be compiled.
        """
        super().__init__(
            "Failed to prepare required bytecode: "
            + "; ".join(
                f"{path!r} (optimization level {level}): {message}"
                for path, level, message in failures
            )
        )
        self.failures = failures
