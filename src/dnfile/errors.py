class dnFormatError(Exception):
    pass


class dnStreamTableError(dnFormatError):
    """A metadata stream table was rejected by the strict stream policy."""

    def __init__(self, message, report=None):
        super().__init__(message)
        self.report = report


class rsrcFormatError(dnFormatError):
    pass
