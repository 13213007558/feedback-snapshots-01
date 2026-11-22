#
# This file is part of gunicorn released under the MIT license.
# See the NOTICE for more information.
"""Rules that decide which environment variables workers inherit.

The master process keeps every variable it was started with, including the
credentials it needs while initializing. Workers only need the configuration
of the application they serve, so the rules in this module are applied to
their environment before the application is loaded in each worker.
"""
import fnmatch
import os


def is_allowed(name, allowlist, denylist):
    """Return whether a variable may be passed to a worker.

    ``allowlist`` and ``denylist`` are lists of glob patterns matched against
    the variable name with :func:`fnmatch.fnmatchcase` (matching is case
    sensitive). An empty allowlist passes everything through; a non-empty
    allowlist keeps only variables matching one of its patterns. The
    denylist is evaluated second, so a match there always removes the
    variable, even when the allowlist matches it.
    """
    if allowlist and not any(
            fnmatch.fnmatchcase(name, pattern) for pattern in allowlist):
        return False
    return not any(
        fnmatch.fnmatchcase(name, pattern) for pattern in denylist)


def filtered_environ(allowlist, denylist, environ=None):
    """Return a copy of ``environ`` with worker-forbidden variables removed."""
    if environ is None:
        environ = os.environ
    return {
        name: value for name, value in environ.items()
        if is_allowed(name, allowlist, denylist)
    }


def strip_worker_environ(cfg, environ=None):
    """Remove variables the current configuration forbids in workers.

    Returns the sorted names that were removed so callers can log them.
    """
    if environ is None:
        environ = os.environ
    removed = sorted(
        name for name in list(environ)
        if not is_allowed(
            name, cfg.worker_env_allowlist, cfg.worker_env_denylist))
    for name in removed:
        del environ[name]
    return removed
