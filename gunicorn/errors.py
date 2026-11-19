#
# This file is part of gunicorn released under the MIT license.
# See the NOTICE for more information.

# We don't need to call super() in __init__ methods of our
# BaseException and Exception classes because we also define
# our own __str__ methods so there is no need to pass 'message'
# to the base class to get a meaningful output from 'str(exc)'.
# pylint: disable=super-init-not-called


# we inherit from BaseException here to make sure to not be caught
# at application level
class HaltServer(BaseException):
    def __init__(self, reason, exit_status=1):
        self.reason = reason
        self.exit_status = exit_status

    def __str__(self):
        return "<HaltServer %r %d>" % (self.reason, self.exit_status)


class ConfigError(Exception):
    """ Exception raised on config error """


class ConfigReloadError(ConfigError):
    """A reload could not read or validate the configuration.

    The running master keeps the previous settings. ``diagnostic`` holds the
    redacted configuration summary so the caller can report it without
    rebuilding it, and ``__str__`` returns the same text.
    """

    def __init__(self, message, diagnostic=None, summary=None):
        super().__init__(message)
        self.message = message
        self.diagnostic = diagnostic
        self.summary = summary or {}

    def __str__(self):
        if self.diagnostic:
            return self.diagnostic
        return self.message


class AppImportError(Exception):
    """ Exception raised when loading an application """
